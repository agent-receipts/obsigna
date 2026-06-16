package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// twoModelTranscript is a redacted, real-shaped Claude Code transcript fixture.
// It contains two assistant turns that used DIFFERENT models, each emitting one
// tool_use block, followed by their tool_result echoes. A third assistant turn
// emits a tool_use with NO usage object (the missing-usage case), and there are
// non-assistant lines (queue-operation, attachment, user text) interleaved to
// exercise the line filtering.
const twoModelTranscript = `{"type":"queue-operation","message":null}
{"type":"user","message":{"role":"user","content":"do the thing"}}
{"type":"assistant","message":{"model":"claude-opus-4-8","role":"assistant","content":[{"type":"thinking","thinking":"hmm"}],"usage":{"input_tokens":10,"output_tokens":2}}}
{"type":"assistant","message":{"model":"claude-opus-4-8","role":"assistant","content":[{"type":"tool_use","id":"toolu_AAA","name":"Bash","input":{"command":"ls"}}],"usage":{"input_tokens":1954,"output_tokens":392,"cache_read_input_tokens":0,"cache_creation_input_tokens":16762}}}
{"type":"user","message":{"role":"user","content":[{"tool_use_id":"toolu_AAA","type":"tool_result","content":"a\nb\n","is_error":false}]}}
{"type":"attachment","message":null}
{"type":"assistant","message":{"model":"claude-haiku-4-5-20251001","role":"assistant","content":[{"type":"tool_use","id":"toolu_BBB","name":"Read","input":{"file_path":"x"}}],"usage":{"input_tokens":77,"output_tokens":12,"cache_read_input_tokens":16762,"cache_creation_input_tokens":0}}}
{"type":"user","message":{"role":"user","content":[{"tool_use_id":"toolu_BBB","type":"tool_result","content":"contents","is_error":false}]}}
{"type":"assistant","message":{"model":"claude-sonnet-4-6","role":"assistant","content":[{"type":"tool_use","id":"toolu_CCC","name":"Grep","input":{"pattern":"x"}}]}}
`

func writeTranscript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "session.jsonl")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// usageField pulls one integer field out of a raw usage object so tests can
// assert the usage attached to a tool call without pinning the whole blob.
func usageField(t *testing.T, usage json.RawMessage, key string) (float64, bool) {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(usage, &m); err != nil {
		t.Fatalf("usage is not a JSON object: %v (%s)", err, usage)
	}
	raw, ok := m[key]
	if !ok {
		return 0, false
	}
	var v float64
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("usage[%q] is not a number: %v", key, err)
	}
	return v, true
}

// TestLookupTranscriptUsage_DifferentModelsPerToolCall is the core join test:
// two tool calls in the same transcript resolve to their own assistant turn's
// model and usage, even though those turns used different models.
func TestLookupTranscriptUsage_DifferentModelsPerToolCall(t *testing.T) {
	path := writeTranscript(t, twoModelTranscript)

	cases := []struct {
		toolUseID string
		wantModel string
		wantIn    float64
		wantOut   float64
		wantRead  float64
	}{
		{"toolu_AAA", "claude-opus-4-8", 1954, 392, 0},
		{"toolu_BBB", "claude-haiku-4-5-20251001", 77, 12, 16762},
	}
	for _, tc := range cases {
		t.Run(tc.toolUseID, func(t *testing.T) {
			model, usage, found, err := lookupTranscriptUsage(path, tc.toolUseID)
			if err != nil {
				t.Fatalf("lookupTranscriptUsage: %v", err)
			}
			if !found {
				t.Fatalf("id %q not found; want found", tc.toolUseID)
			}
			if model != tc.wantModel {
				t.Errorf("model = %q; want %q", model, tc.wantModel)
			}
			if got, ok := usageField(t, usage, "input_tokens"); !ok || got != tc.wantIn {
				t.Errorf("usage.input_tokens = %v (ok=%v); want %v", got, ok, tc.wantIn)
			}
			if got, ok := usageField(t, usage, "output_tokens"); !ok || got != tc.wantOut {
				t.Errorf("usage.output_tokens = %v (ok=%v); want %v", got, ok, tc.wantOut)
			}
			if got, ok := usageField(t, usage, "cache_read_input_tokens"); !ok || got != tc.wantRead {
				t.Errorf("usage.cache_read_input_tokens = %v (ok=%v); want %v", got, ok, tc.wantRead)
			}
		})
	}
}

// TestLookupTranscriptUsage_NotFound covers an id that no assistant turn
// emitted: found is false and err is nil (a missing id is non-fatal).
func TestLookupTranscriptUsage_NotFound(t *testing.T) {
	path := writeTranscript(t, twoModelTranscript)
	model, usage, found, err := lookupTranscriptUsage(path, "toolu_MISSING")
	if err != nil {
		t.Fatalf("lookupTranscriptUsage: %v", err)
	}
	if found {
		t.Errorf("found = true; want false for an absent id")
	}
	if model != "" || usage != nil {
		t.Errorf("model=%q usage=%s; want empty for an absent id", model, usage)
	}
}

// TestLookupTranscriptUsage_MissingUsage covers an assistant turn that emitted
// the id but carried no usage object: the model resolves, usage is nil, and
// found is true so the caller can still attach model + capture_method.
func TestLookupTranscriptUsage_MissingUsage(t *testing.T) {
	path := writeTranscript(t, twoModelTranscript)
	model, usage, found, err := lookupTranscriptUsage(path, "toolu_CCC")
	if err != nil {
		t.Fatalf("lookupTranscriptUsage: %v", err)
	}
	if !found {
		t.Fatalf("found = false; want true (turn exists, only usage is absent)")
	}
	if model != "claude-sonnet-4-6" {
		t.Errorf("model = %q; want claude-sonnet-4-6", model)
	}
	if usage != nil {
		t.Errorf("usage = %s; want nil when the turn has no usage object", usage)
	}
}

// TestLookupTranscriptUsage_MissingFile returns the I/O error so the caller can
// distinguish a read failure from an absent id.
func TestLookupTranscriptUsage_MissingFile(t *testing.T) {
	_, _, found, err := lookupTranscriptUsage(filepath.Join(t.TempDir(), "nope.jsonl"), "toolu_AAA")
	if err == nil {
		t.Fatal("expected an error opening a missing transcript")
	}
	if found {
		t.Error("found = true on a missing file; want false")
	}
}

// TestLookupTranscriptUsage_EmptyArgs short-circuits without touching the disk.
func TestLookupTranscriptUsage_EmptyArgs(t *testing.T) {
	if _, _, found, err := lookupTranscriptUsage("", "toolu_AAA"); err != nil || found {
		t.Errorf("empty path: found=%v err=%v; want false,nil", found, err)
	}
	path := writeTranscript(t, twoModelTranscript)
	if _, _, found, err := lookupTranscriptUsage(path, ""); err != nil || found {
		t.Errorf("empty id: found=%v err=%v; want false,nil", found, err)
	}
}

// TestReadClaudeCode_EnrichesFromTranscript verifies the wiring: a PostToolUse
// frame whose tool_use_id matches a transcript turn yields an emitter.Event
// carrying that turn's model, the verbatim usage object, and capture_method.
func TestReadClaudeCode_EnrichesFromTranscript(t *testing.T) {
	path := writeTranscript(t, twoModelTranscript)
	frame := map[string]any{
		"hook_event_name": "PostToolUse",
		"session_id":      "sess-xyz",
		"tool_use_id":     "toolu_BBB",
		"tool_name":       "Read",
		"tool_input":      map[string]string{"file_path": "x"},
		"tool_response":   map[string]string{"content": "contents"},
		"transcript_path": path,
	}
	stdin, _ := json.Marshal(frame)

	ev, _, err := readClaudeCode(stdin, func(string) string { return "" })
	if err != nil {
		t.Fatalf("readClaudeCode: %v", err)
	}
	if ev.Model != "claude-haiku-4-5-20251001" {
		t.Errorf("ev.Model = %q; want claude-haiku-4-5-20251001", ev.Model)
	}
	if ev.CaptureMethod != "transcript" {
		t.Errorf("ev.CaptureMethod = %q; want transcript", ev.CaptureMethod)
	}
	if got, ok := usageField(t, ev.Usage, "output_tokens"); !ok || got != 12 {
		t.Errorf("ev.Usage.output_tokens = %v (ok=%v); want 12", got, ok)
	}
}

// TestReadClaudeCode_NoTranscriptLeavesFieldsUnset confirms enrichment is
// best-effort: with no transcript_path and no resolvable fallback, the model,
// usage, and capture_method fields stay empty and no error is raised.
func TestReadClaudeCode_NoTranscriptLeavesFieldsUnset(t *testing.T) {
	stdin := []byte(`{
		"hook_event_name": "PostToolUse",
		"session_id": "sess-none",
		"tool_use_id": "toolu_AAA",
		"tool_name": "Bash",
		"tool_input": {"command":"ls"}
	}`)
	// HOME points at an empty dir so the glob fallback resolves nothing.
	env := func(k string) string {
		if k == "HOME" {
			return t.TempDir()
		}
		return ""
	}
	ev, _, err := readClaudeCode(stdin, env)
	if err != nil {
		t.Fatalf("readClaudeCode: %v", err)
	}
	if ev.Model != "" || ev.Usage != nil || ev.CaptureMethod != "" {
		t.Errorf("enrichment fields set without a transcript: model=%q usage=%s capture=%q",
			ev.Model, ev.Usage, ev.CaptureMethod)
	}
}
