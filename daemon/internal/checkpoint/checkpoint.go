// Package checkpoint is the daemon's checkpoint anchor: it emits signed
// checkpoints to append-only sinks (emitter.go) and reads them back from an
// anchor log for `verify --against-anchor` (reader.go).
//
// The portable wire types and the sign/verify crypto live in the SDK
// (obsigna.dev/sdk/go/checkpoint) so the daemon, the verify CLI, and the
// browser verifier all share one implementation. This package re-exports them
// under their original names so the daemon's emitter, reader, and callers use a
// single `checkpoint.*` surface for both the portable crypto and the
// daemon-local sink/log machinery.
package checkpoint

import sdk "obsigna.dev/sdk/go/checkpoint"

// Portable checkpoint types and crypto, re-exported from the SDK. See
// obsigna.dev/sdk/go/checkpoint for the design constraints (ADR-0008).
type (
	Checkpoint = sdk.Checkpoint
	Signed     = sdk.Signed
	Signer     = sdk.Signer
)

var (
	Sign             = sdk.Sign
	Verify           = sdk.Verify
	PublicKeyFromPEM = sdk.PublicKeyFromPEM
)
