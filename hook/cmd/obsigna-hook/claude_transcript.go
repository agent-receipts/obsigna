package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// transcriptEntry is the minimal projection of one Claude Code transcript JSONL
// line we need to resolve a tool call's model and token usage. Only assistant
// message lines carry message.model and message.usage; user (tool_result),
// queue-operation, attachment, and similar lines leave them empty and are
// skipped. See the investigation notes in this package's tests for the full
// on-disk shape.
type transcriptEntry struct {
	Type    string `json:"type"`
	Message struct {
		Model string `json:"model"`
		// Usage is the runtime's token-usage object, kept as a raw message so it
		// is forwarded into the receipt verbatim — never recomputed.
		Usage json.RawMessage `json:"usage"`
		// Content is an array of blocks on assistant turns (and a plain string on
		// some user turns), so it is decoded lazily only when it looks like an
		// array.
		Content json.RawMessage `json:"content"`
	} `json:"message"`
}

// transcriptBlock is one entry of an assistant turn's message.content array.
// A tool_use block carries the id the PostToolUse hook later echoes back as
// tool_use_id, which is the join key into the turn's model + usage.
type transcriptBlock struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// lookupTranscriptUsage scans the transcript JSONL at path for the assistant
// turn that emitted toolUseID and returns that turn's model and token usage.
//
// The join is: PostToolUse tool_use_id == tool_use.id on an assistant turn,
// whose message.model and message.usage describe the model run that produced
// the call. Returns:
//
//   - found == false when no assistant turn emitted the id (id not in
//     transcript). err is nil in this case — a missing id is an expected,
//     non-fatal condition for a best-effort enrichment.
//   - found == true, usage == nil when the turn is located but has no usage
//     object (model is still returned).
//   - a non-nil err only for I/O failures opening or reading the file.
//
// The file may be large, so it is streamed line by line rather than read whole.
// Each line is cheaply pre-filtered with a substring check on toolUseID before
// the JSON decode, so only the handful of lines that mention the id (the
// assistant turn and its tool_result echo) are ever parsed.
func lookupTranscriptUsage(path, toolUseID string) (model string, usage json.RawMessage, found bool, err error) {
	if path == "" || toolUseID == "" {
		return "", nil, false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", nil, false, err
	}
	defer f.Close()

	needle := []byte(toolUseID)
	r := bufio.NewReader(f)
	for {
		line, readErr := r.ReadBytes('\n')
		if len(line) > 0 && bytes.Contains(line, needle) {
			m, u, ok := matchToolUse(line, toolUseID)
			if ok {
				return m, u, true, nil
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return "", nil, false, nil
			}
			return "", nil, false, readErr
		}
	}
}

// matchToolUse reports whether line is an assistant turn that emitted
// toolUseID, returning the turn's model and usage when it is. A malformed line
// is treated as a non-match rather than an error: the transcript is an external
// artifact and one bad line must not abort a best-effort lookup.
func matchToolUse(line []byte, toolUseID string) (model string, usage json.RawMessage, ok bool) {
	var entry transcriptEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		return "", nil, false
	}
	if entry.Type != "assistant" || !looksLikeJSONArray(entry.Message.Content) {
		return "", nil, false
	}
	var blocks []transcriptBlock
	if err := json.Unmarshal(entry.Message.Content, &blocks); err != nil {
		return "", nil, false
	}
	for _, b := range blocks {
		if b.Type == "tool_use" && b.ID == toolUseID {
			// usage is left nil when the turn carries no usage object, which the
			// caller surfaces as the "found but missing usage" case.
			return entry.Message.Model, entry.Message.Usage, true
		}
	}
	return "", nil, false
}

// looksLikeJSONArray reports whether raw's first non-whitespace byte is '[', so
// string-valued content (some user turns) is skipped without a failed decode.
func looksLikeJSONArray(raw json.RawMessage) bool {
	for _, c := range raw {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '[':
			return true
		default:
			return false
		}
	}
	return false
}

// resolveTranscriptPath returns the transcript JSONL path for a frame. The
// hook payload's transcript_path is authoritative; when absent it falls back to
// the conventional ~/.claude/projects/*/<session_id>.jsonl layout, returning
// "" when neither resolves (enrichment is then skipped). The glob is keyed on
// the globally-unique session id, so the project-directory mangling Claude Code
// applies to the cwd does not need to be reproduced.
func resolveTranscriptPath(transcriptPath, sessionID string, env func(string) string) string {
	if transcriptPath != "" {
		return transcriptPath
	}
	if sessionID == "" {
		return ""
	}
	home := env("HOME")
	if home == "" {
		return ""
	}
	matches, err := filepath.Glob(filepath.Join(home, ".claude", "projects", "*", sessionID+".jsonl"))
	if err != nil || len(matches) == 0 {
		return ""
	}
	return matches[0]
}
