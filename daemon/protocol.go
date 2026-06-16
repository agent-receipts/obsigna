package daemon

import "github.com/agent-receipts/ar/daemon/internal/pipeline"

// VersionRange is an inclusive range of integer protocol versions. An empty
// intersection between two ranges means the two peers cannot talk.
type VersionRange struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// ProtocolVersion describes the wire protocol this daemon speaks. It is the
// machine-readable surface ADR-0024 Gate #8 reads (via the
// `obsigna-daemon --protocol-version` flag) to assert the released
// daemon's spoken range intersects the range each released SDK declares it can
// emit.
type ProtocolVersion struct {
	// FrameVersion is the range of emitter-frame schema versions (the `v`
	// field on the wire) the daemon can interpret.
	FrameVersion VersionRange `json:"frame_version"`
}

// SpokenProtocolVersion returns the daemon's spoken protocol range, sourced
// from the pipeline that actually accepts frames so the declaration cannot
// drift from the bytes the daemon honours.
func SpokenProtocolVersion() ProtocolVersion {
	return ProtocolVersion{
		FrameVersion: VersionRange{
			Min: pipeline.SpokenFrameVersionMin,
			Max: pipeline.SpokenFrameVersionMax,
		},
	}
}
