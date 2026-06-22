package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"obsigna.dev/sdk/go/emitter"
)

// maxErrorTextLen bounds the failure message copied into the receipt. Claude
// Code error strings are short, but the field is host-supplied and otherwise
// uncapped before the emitter's whole-frame MaxFrameSize check. Truncating here
// degrades an oversized message to a truncated receipt rather than dropping the
// failure entirely (an oversized frame would fail Emit and exit the hook 1).
const maxErrorTextLen = 16 << 10

// failureErrorText extracts the human-readable failure message from a
// PostToolUseFailure frame's `error` field. Claude Code sends a JSON string
// today; the frame is treated as an external artifact, so a non-string value
// (object/array/number) is kept as its raw JSON text rather than aborting the
// whole-frame unmarshal — a schema variation degrades the message instead of
// dropping the failure receipt. The result is trimmed and length-capped.
func failureErrorText(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err != nil {
		// Not a JSON string — keep the raw JSON text as the message.
		s = string(trimmed)
	}
	s = strings.TrimSpace(s)
	if len(s) > maxErrorTextLen {
		// ToValidUTF8 drops a trailing partial rune left by the byte-slice cut.
		s = strings.ToValidUTF8(s[:maxErrorTextLen], "") + "…(truncated)"
	}
	return s
}

// claudeCodeFrame is the JSON envelope Claude Code sends on stdin for
// PostToolUse, PostToolUseFailure, and PreToolUse hooks.
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

	// Error and IsInterrupt are carried only on PostToolUseFailure frames.
	// Error is the human-readable failure message. Claude Code sends a JSON
	// string, but it is kept as RawMessage and decoded leniently (see
	// failureErrorText) so a non-string value cannot abort the whole-frame
	// unmarshal and drop the failure receipt. IsInterrupt distinguishes a
	// user/abort cancellation from a genuine execution error. A
	// PostToolUseFailure frame carries no tool_response.
	Error       json.RawMessage `json:"error"`
	IsInterrupt bool            `json:"is_interrupt"`
}

// readClaudeCode parses a Claude Code PostToolUse, PostToolUseFailure, or
// PreToolUse stdin frame and maps it to an emitter.Event. The decision is
// derived from the hook_event_name field:
//   - "PostToolUse"        → "allowed" (tool ran successfully)
//   - "PostToolUseFailure" → "allowed" + non-empty Error (tool ran but failed;
//     the daemon stamps outcome.status=failure from the error)
//   - "PreToolUse"         → "pending" (tool is about to run; outcome not yet known)
//
// PostToolUse fires only on success and PostToolUseFailure only on failure, so
// capturing both is what records a failed (or interrupted) tool call as a
// failure row in the chain rather than leaving no receipt at all.
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

	var decision, failureErr string
	switch f.HookEventName {
	case "PostToolUse":
		decision = "allowed"
	case "PostToolUseFailure":
		// The tool call was permitted and ran, but execution failed (or was
		// interrupted). Record it as "allowed" with a non-empty error: the
		// daemon maps decision="allowed" + a non-empty error to
		// outcome.status=failure. Guarantee non-empty text so a failure frame
		// is never silently downgraded to success by that rule, even on the
		// rare frame that carries no message.
		decision = "allowed"
		failureErr = failureErrorText(f.Error)
		if failureErr == "" {
			if f.IsInterrupt {
				failureErr = "tool call interrupted"
			} else {
				failureErr = "tool call failed"
			}
		}
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
		Error:         failureErr,
		CorrelationID: f.ToolUseID,
		AgentID:       f.AgentID,
		AgentType:     f.AgentType,
	}
	// Only set Input/Output when non-empty; the emitter rejects non-nil empty
	// slices and the daemon expects nil to mean "no payload".
	if len(f.ToolInput) > 0 {
		ev.Input = f.ToolInput
		switch {
		case f.ToolName == "Bash":
			// Best-effort: classify common filesystem-mutating shell commands
			// (rm/mv/cp and > redirects) so a destructive delete carries a
			// filesystem target and its real (high) risk instead of looking
			// like a harmless command. Unparseable commands fall through with
			// no target, preserving current behaviour.
			if sys, res, at := extractBashTarget(f.ToolInput); res != "" {
				ev.Target = emitter.Target{System: sys, Resource: res}
				ev.ActionType = at
			}
		default:
			if sys, res, warn := extractFileTarget(f.ToolName, f.ToolInput); res != "" {
				ev.Target = emitter.Target{System: sys, Resource: res}
				// Set the taxonomic action type only for native tools whose verb we
				// can name honestly (Read → read, Write/Edit/MultiEdit → modify).
				// Opportunistically-captured tools yield a path but no known verb, so
				// nativeToolActionType returns "" and ActionType stays empty.
				ev.ActionType = nativeToolActionType(f.ToolName)
			} else if warn != "" {
				fmt.Fprintln(os.Stderr, warn)
			}
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

// nativeActionTypes maps a native Claude Code tool name to its taxonomic
// filesystem action type. Only tools whose effect is unambiguous are listed:
// Read reads, while Write/Edit/MultiEdit all modify an existing path (Write
// clobbers it in place). Tools absent from the map have no honestly-derivable
// verb, so nativeToolActionType returns "" and the daemon falls back to its
// UnknownAction default. The action types are the shared consts from
// shell_target.go so there is one source of truth across both classifiers.
var nativeActionTypes = map[string]string{
	"Read":      actionFileRead,
	"Write":     actionFileModify,
	"Edit":      actionFileModify,
	"MultiEdit": actionFileModify,
}

// nativeToolActionType returns the taxonomic action type for a native Claude
// Code tool, or "" when the tool's verb is not known. Callers should only set
// ev.ActionType when a file target was resolved; an empty string leaves it
// unset so the daemon does not over-claim a verb we cannot derive.
func nativeToolActionType(toolName string) string {
	return nativeActionTypes[toolName]
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
