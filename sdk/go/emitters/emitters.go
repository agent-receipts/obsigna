// Package emitters defines the signed-receipt delivery abstraction
// introduced in ADR-0020.
//
// An [Emitter] is responsible only for delivering a fully-signed,
// already-chained [receipt.AgentReceipt]. Construction, signing, and
// chaining stay client-side and upstream of this layer.
//
// The legacy [emitter.DaemonEmitter] in sdk/go/emitter is a separate
// adapter that forwards UNSIGNED tool-call frames to the agent-receipts
// daemon for daemon-side signing. It does NOT implement the [Emitter]
// interface defined here — see ADR-0020 §"Migration from the current
// daemon architecture" (step 2 is tracked separately).
//
// Built-in implementations:
//
//   - [HttpEmitter] — POSTs receipts as application/ld+json to a remote
//     collector. Status mapping per ADR-0020: 201/409 -> success,
//     400 -> immediate EmitError, 5xx/network -> exponential backoff
//     with jitter up to MaxAttempts.
//   - [CompositeEmitter] — fans out sequentially to a slice of children;
//     every child is attempted, errors are aggregated via errors.Join.
//   - [BufferingEmitter] — in-memory batch buffer with timer flush.
//     Documents the crash-loss risk; not for audit-critical paths.
//   - [InMemoryEmitter] — test double exposing the received receipts.
package emitters

import (
	"context"

	"obsigna.dev/sdk/go/receipt"
)

// Emitter delivers a signed [receipt.AgentReceipt]. Implementations handle
// transport (HTTPS, in-memory, composite, buffered) but never construction,
// signing, or chaining.
//
// Implementations SHOULD honour ctx for cancellation/deadlines.
type Emitter interface {
	Emit(ctx context.Context, r receipt.AgentReceipt) error
}
