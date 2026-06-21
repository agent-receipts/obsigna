package daemon

import (
	"encoding/json"
	"strconv"
	"testing"

	"obsigna.dev/daemon/internal/pipeline"
)

// TestSpokenProtocolVersionMirrorsPipeline asserts the exported spoken range
// reflects the pipeline constants — the single source of truth for which frame
// versions the daemon accepts.
func TestSpokenProtocolVersionMirrorsPipeline(t *testing.T) {
	pv := SpokenProtocolVersion()
	if pv.FrameVersion.Min != pipeline.SpokenFrameVersionMin {
		t.Errorf("Min = %d, want %d", pv.FrameVersion.Min, pipeline.SpokenFrameVersionMin)
	}
	if pv.FrameVersion.Max != pipeline.SpokenFrameVersionMax {
		t.Errorf("Max = %d, want %d", pv.FrameVersion.Max, pipeline.SpokenFrameVersionMax)
	}
}

// TestSpokenRangeWellFormed guards the range invariant: min <= max.
func TestSpokenRangeWellFormed(t *testing.T) {
	if pipeline.SpokenFrameVersionMin > pipeline.SpokenFrameVersionMax {
		t.Fatalf("spoken range is inverted: min %d > max %d",
			pipeline.SpokenFrameVersionMin, pipeline.SpokenFrameVersionMax)
	}
}

// TestSpokenRangeCoversAcceptedVersion ties the declared range to the version
// the daemon actually accepts. SupportedFrameVersion must parse to an integer
// inside [min, max]; otherwise the daemon would advertise a range that does not
// match the bytes it honours, defeating the point of Gate #8. While the daemon
// speaks a single version, min == max == that version.
func TestSpokenRangeCoversAcceptedVersion(t *testing.T) {
	v, err := strconv.Atoi(pipeline.SupportedFrameVersion)
	if err != nil {
		t.Fatalf("SupportedFrameVersion %q is not an integer: %v", pipeline.SupportedFrameVersion, err)
	}
	if v < pipeline.SpokenFrameVersionMin || v > pipeline.SpokenFrameVersionMax {
		t.Fatalf("SupportedFrameVersion %d is outside spoken range [%d, %d]",
			v, pipeline.SpokenFrameVersionMin, pipeline.SpokenFrameVersionMax)
	}
	if pipeline.SpokenFrameVersionMin != v {
		t.Fatalf("daemon accepts only %q but advertises min %d; widen the accept check and the range together",
			pipeline.SupportedFrameVersion, pipeline.SpokenFrameVersionMin)
	}
	if pipeline.SpokenFrameVersionMax != v {
		t.Fatalf("daemon accepts only %q but advertises max %d; widen the accept check and the range together",
			pipeline.SupportedFrameVersion, pipeline.SpokenFrameVersionMax)
	}
}

// TestSpokenProtocolVersionJSON pins the wire shape the gate parses.
func TestSpokenProtocolVersionJSON(t *testing.T) {
	got, err := json.Marshal(SpokenProtocolVersion())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"frame_version":{"min":1,"max":1}}`
	if string(got) != want {
		t.Errorf("JSON = %s, want %s", got, want)
	}
}
