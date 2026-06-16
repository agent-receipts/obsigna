package receipt

import (
	"encoding/json"
	"testing"
)

// TestRuntimeRoundTrip_ModelUsageCaptureMethod locks the JSON shape of the
// observability members added to the open issuer.runtime container: model,
// usage (verbatim), and capture_method survive a marshal → unmarshal round-trip
// alongside agent_id/agent_type and any unknown keys preserved via Extra.
func TestRuntimeRoundTrip_ModelUsageCaptureMethod(t *testing.T) {
	usage := json.RawMessage(`{"input_tokens":1954,"output_tokens":392,"cache_read_input_tokens":0}`)
	in := Runtime{
		AgentID:       "agent-abc",
		AgentType:     "general-purpose",
		Model:         "claude-opus-4-8",
		Usage:         usage,
		CaptureMethod: "transcript",
		Extra:         map[string]json.RawMessage{"trace_id": json.RawMessage(`"abc123"`)},
	}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Confirm the wire keys are the snake_case names the schema documents.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	for _, k := range []string{"agent_id", "agent_type", "model", "usage", "capture_method", "trace_id"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("marshalled runtime missing key %q (got %s)", k, b)
		}
	}

	var out Runtime
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Model != in.Model {
		t.Errorf("model = %q; want %q", out.Model, in.Model)
	}
	if out.CaptureMethod != in.CaptureMethod {
		t.Errorf("capture_method = %q; want %q", out.CaptureMethod, in.CaptureMethod)
	}
	if string(out.Usage) == "" {
		t.Fatal("usage was dropped on round-trip")
	}
	var um map[string]int
	if err := json.Unmarshal(out.Usage, &um); err != nil {
		t.Fatalf("round-tripped usage not an object: %v", err)
	}
	if um["input_tokens"] != 1954 || um["output_tokens"] != 392 {
		t.Errorf("usage = %v; want the verbatim token counts", um)
	}
	if got, ok := out.Extra["trace_id"]; !ok || string(got) != `"abc123"` {
		t.Errorf("unknown runtime key trace_id not preserved: %q (ok=%v)", got, ok)
	}
}

// TestRuntimeMarshal_OmitsEmptyObservabilityFields confirms a runtime carrying
// only agent identity emits no model/usage/capture_method keys, so existing
// sub-agent receipts are byte-for-byte unchanged by this addition.
func TestRuntimeMarshal_OmitsEmptyObservabilityFields(t *testing.T) {
	b, err := json.Marshal(Runtime{AgentID: "agent-x", AgentType: "explorer"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"model", "usage", "capture_method"} {
		if _, ok := raw[k]; ok {
			t.Errorf("empty %q should be omitted; got %s", k, b)
		}
	}
}
