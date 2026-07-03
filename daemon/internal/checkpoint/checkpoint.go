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

import (
	"crypto/ed25519"

	sdk "obsigna.dev/sdk/go/checkpoint"
)

// Portable checkpoint types, re-exported from the SDK so the daemon's emitter,
// reader, and callers keep one `checkpoint.*` surface. See
// obsigna.dev/sdk/go/checkpoint for the design constraints (ADR-0015 External
// anchor write contract; ADR-0008 anchoring freeze).
type (
	Checkpoint = sdk.Checkpoint
	Signed     = sdk.Signed
	Signer     = sdk.Signer
)

// Sign, Verify, and PublicKeyFromPEM delegate to the SDK. They are thin wrapper
// functions rather than var aliases so the crypto entrypoints stay immutable
// (a var would let any importer reassign them) and function-shaped for docs and
// grep.
func Sign(cp Checkpoint, signer Signer) (Signed, error) { return sdk.Sign(cp, signer) }

func Verify(s Signed, publicKeyPEM string) (bool, error) { return sdk.Verify(s, publicKeyPEM) }

func PublicKeyFromPEM(publicKeyPEM []byte) (ed25519.PublicKey, error) {
	return sdk.PublicKeyFromPEM(publicKeyPEM)
}
