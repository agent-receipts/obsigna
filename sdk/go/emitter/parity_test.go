package emitter

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestFrameParityKnownFields asserts that the frame struct's JSON tags
// exactly match the expected list. The expected list is the contract:
// updating it forces a deliberate review of the wire format change.
//
// frame mirrors daemon/internal/pipeline.EmitterFrame field-for-field
// (minus EmitterFrame's extra "action_type" field). A divergence here
// means a daemon that reads fields the emitter never writes, or vice versa.
func TestFrameParityKnownFields(t *testing.T) {
	expected := []string{
		"agent_id",
		"agent_type",
		"capture_method",
		"channel",
		"correlation_id",
		"decision",
		"drop_count",
		"error",
		"idempotency_key",
		"input",
		"issuer_model",
		"issuer_name",
		"model",
		"operator_id",
		"operator_name",
		"output",
		"session_id",
		"target_resource",
		"target_system",
		"tool",
		"ts_emit",
		"usage",
		"v",
	}

	got := jsonTagsOf(frame{})
	sort.Strings(got)
	sort.Strings(expected)

	if !reflect.DeepEqual(got, expected) {
		t.Errorf("frame JSON tags do not match expected set\n  got:  %v\n  want: %v", got, expected)
	}
}

// jsonTagsOf extracts all non-empty JSON tag names from the exported and
// unexported fields of a struct (one level deep, no embedding).
func jsonTagsOf(v any) []string {
	t := reflect.TypeOf(v)
	if t.Kind() != reflect.Struct {
		return nil
	}
	var tags []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name != "" {
			tags = append(tags, name)
		}
	}
	return tags
}
