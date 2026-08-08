package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"obsigna.dev/sdk/go/emitter"
)

// maxTranscriptLineLength caps a single transcript JSONL line, reusing the
// daemon's frame-size cap (via the already-imported emitter package):
// bufio.Reader.ReadBytes otherwise grows its returned slice without limit
// while it searches for a newline, so a line with no delimiter could exhaust
// the short-lived hook process's memory.
const maxTranscriptLineLength = emitter.MaxFrameSize

// errTranscriptLineTooLong is returned by readBoundedLine when a line
// exceeds maxTranscriptLineLength before a newline is found.
var errTranscriptLineTooLong = errors.New("transcript line too large")

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
//   - a non-nil err only for I/O failures opening or reading the file. A line
//     exceeding maxTranscriptLineLength is skipped like a malformed line
//     (readBoundedLine still bounds the memory used to read it) rather than
//     aborting the scan — real transcripts can legitimately contain large
//     tool_use inputs unrelated to the id being looked up, so one oversized
//     line must not cost every other tool call in the session its receipt
//     enrichment.
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
		line, readErr := readBoundedLine(r, maxTranscriptLineLength)
		if errors.Is(readErr, errTranscriptLineTooLong) {
			// Can't be the JSON we're matching against — it would already
			// have blown the daemon's own frame-size cap — so skip it like a
			// malformed line and keep scanning instead of aborting.
			continue
		}
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

// readBoundedLine reads one '\n'-delimited line from r, mirroring
// bufio.Reader.ReadBytes but capping the accumulated line at max bytes
// instead of growing the returned slice without bound while it searches for
// the delimiter. Once max is exceeded it discards the remainder of the line
// (still without accumulating it) so r is left positioned at the start of
// the next line, then returns errTranscriptLineTooLong — the caller can
// resume scanning from a subsequent readBoundedLine call.
func readBoundedLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > max {
			if err == bufio.ErrBufferFull {
				if discardErr := discardRestOfLine(r); discardErr != nil {
					return line, discardErr
				}
			}
			return line, errTranscriptLineTooLong
		}
		line = append(line, chunk...)
		if err == nil {
			return line, nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return line, err
	}
}

// discardRestOfLine reads and discards bytes from r up to and including the
// next '\n', without accumulating them, so readBoundedLine can resync to the
// next line after abandoning an oversized one. Returns nil once the
// delimiter is found, and also on io.EOF (the file's final line was itself
// the oversized one, with no trailing newline — there is simply nothing left
// to discard). A non-nil return is a genuine I/O error on the underlying
// reader, distinct from EOF.
func discardRestOfLine(r *bufio.Reader) error {
	for {
		_, err := r.ReadSlice('\n')
		if err == nil || errors.Is(err, io.EOF) {
			return nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return err
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
