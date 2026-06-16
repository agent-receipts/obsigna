package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/agent-receipts/ar/sdk/go/emitter"
)

// claudeCodeFrame is the JSON envelope Claude Code sends on stdin for
// PostToolUse and PreToolUse hooks.
type claudeCodeFrame struct {
	HookEventName  string          `json:"hook_event_name"`
	SessionID      string          `json:"session_id"`
	ToolUseID      string          `json:"tool_use_id"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response"`
	AgentID        string          `json:"agent_id"`
	AgentType      string          `json:"agent_type"`
	TranscriptPath string          `json:"transcript_path"`
}

// readClaudeCode parses a Claude Code PostToolUse or PreToolUse stdin frame
// and maps it to an emitter.Event. The decision is derived from the
// hook_event_name field:
//   - "PostToolUse" → "allowed" (tool ran successfully)
//   - "PreToolUse"  → "pending" (tool is about to run; outcome not yet known)
//
// The returned sessionID is the host-supplied session identifier from the
// frame; it is the empty string when absent.
func readClaudeCode(stdin []byte, env func(string) string) (emitter.Event, string, error) {
	if len(stdin) == 0 {
		return emitter.Event{}, "", errors.New("empty stdin")
	}
	var f claudeCodeFrame
	if err := json.Unmarshal(stdin, &f); err != nil {
		return emitter.Event{}, "", err
	}
	if f.ToolName == "" {
		return emitter.Event{}, "", errors.New("missing tool_name")
	}

	var decision string
	switch f.HookEventName {
	case "PostToolUse":
		decision = "allowed"
	case "PreToolUse":
		decision = "pending"
	default:
		// hook_event_name absent or unrecognised — fall back to "allowed" for
		// backward compatibility with payloads that omit the field (e.g. runtimes
		// that set CLAUDE_SESSION_ID but do not include hook_event_name).
		decision = "allowed"
	}

	ev := emitter.Event{
		Channel:       "claude-code",
		Tool:          emitter.Tool{Name: f.ToolName},
		Decision:      decision,
		CorrelationID: f.ToolUseID,
		AgentID:       f.AgentID,
		AgentType:     f.AgentType,
	}
	// Only set Input/Output when non-empty; the emitter rejects non-nil empty
	// slices and the daemon expects nil to mean "no payload".
	if len(f.ToolInput) > 0 {
		ev.Input = f.ToolInput
		if sys, res, warn := extractFileTarget(f.ToolName, f.ToolInput); res != "" {
			ev.Target = emitter.Target{System: sys, Resource: res}
		} else if warn != "" {
			fmt.Fprintln(os.Stderr, warn)
		}
	}
	if len(f.ToolResponse) > 0 {
		ev.Output = f.ToolResponse
	}

	// Enrich with the model and token usage for this tool call, read from the
	// session transcript (works with OTEL disabled — no proxy involved). This is
	// strictly best-effort: a missing transcript, an unmatched id, or a turn with
	// no usage object simply leaves the fields unset. Enrichment never fails the
	// hook, so lookup errors are swallowed rather than surfaced.
	if f.ToolUseID != "" {
		path := resolveTranscriptPath(f.TranscriptPath, f.SessionID, env)
		model, usage, found, lookupErr := lookupTranscriptUsage(path, f.ToolUseID)
		switch {
		case lookupErr != nil:
			// Enrichment is best-effort and must never fail the hook, but a
			// genuine read error (unreadable or corrupt transcript) is worth a
			// non-fatal note so it is not silently indistinguishable from a
			// tool_use_id that is simply absent. We do not exit non-zero.
			fmt.Fprintf(os.Stderr, "agent-receipts-hook: transcript enrichment skipped: %v\n", lookupErr)
		case found:
			ev.Model = model
			ev.Usage = usage
			ev.CaptureMethod = "transcript"
		}
	}

	return ev, f.SessionID, nil
}

// fileTools is the set of tools known to always operate on a named file and
// expected to carry file_path in their input. An absent file_path for any tool
// in this set is returned as a warning string so the caller can surface the
// schema drift without failing the hook.
var fileTools = map[string]bool{
	"Read": true, "Write": true, "Edit": true, "MultiEdit": true,
}

// skipTools is the set of non-filesystem tools excluded from file_path
// extraction. Everything outside this set (and not MCP-namespaced) is
// attempted opportunistically, so new filesystem tools are auto-captured
// without requiring an explicit listing.
var skipTools = map[string]bool{
	"Bash": true, "Agent": true, "WebFetch": true, "WebSearch": true,
}

// extractFileTarget attempts to extract a file path from a tool's input JSON.
//
// Skip rules (in order):
//  1. MCP-namespaced tools (prefix "mcp__") — dynamic schema, not ours to predict.
//  2. Tools in skipTools — known non-filesystem tools.
//
// For all other tools, file_path is attempted. On success: returns
// ("filesystem", path, ""). When file_path is absent for a tool in fileTools
// (the known-important set), returns a non-empty warning so the caller can
// log the degradation — these tools should always have file_path, so absence
// means Claude Code's payload schema may have changed. For any other tool
// without file_path: returns ("", "", "") silently, since the tool may simply
// not touch files.
func extractFileTarget(toolName string, input json.RawMessage) (system, resource, warning string) {
	if strings.HasPrefix(toolName, "mcp__") {
		return "", "", ""
	}
	if skipTools[toolName] {
		return "", "", ""
	}
	if len(input) == 0 {
		return "", "", ""
	}
	var inp struct {
		FilePath string `json:"file_path"`
	}
	if err := json.Unmarshal(input, &inp); err != nil {
		// Malformed JSON is not a schema-drift signal — don't warn.
		return "", "", ""
	}
	filePath := strings.TrimSpace(inp.FilePath)
	if filePath == "" {
		if fileTools[toolName] {
			return "", "", fmt.Sprintf(
				"agent-receipts-hook: %s input has no file_path; action.target.resource will be empty",
				toolName,
			)
		}
		return "", "", ""
	}
	return "filesystem", filePath, ""
}
