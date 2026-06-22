package emitters

import (
	"context"
	"sync"

	"obsigna.dev/sdk/go/receipt"
)

// InMemoryEmitter captures emitted receipts in an exposed slice. Performs
// no I/O and provides no delivery guarantee. Use as a test double in unit
// and integration tests where the assertion is against the receipts that
// passed through the emitter.
//
// NOT for production use.
type InMemoryEmitter struct {
	mu       sync.Mutex
	received []receipt.AgentReceipt
}

// NewInMemory returns an empty InMemoryEmitter ready to record receipts.
func NewInMemory() *InMemoryEmitter {
	return &InMemoryEmitter{}
}

// Emit records r in the internal slice and returns nil. The ctx argument
// is accepted to satisfy the [Emitter] interface but is otherwise ignored —
// the operation never blocks.
func (e *InMemoryEmitter) Emit(_ context.Context, r receipt.AgentReceipt) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.received = append(e.received, r)
	return nil
}

// Received returns a copy of every receipt passed to Emit, in arrival
// order. Safe to call concurrently with Emit.
func (e *InMemoryEmitter) Received() []receipt.AgentReceipt {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]receipt.AgentReceipt, len(e.received))
	copy(out, e.received)
	return out
}

// Clear drops all recorded receipts. Useful between test cases.
func (e *InMemoryEmitter) Clear() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.received = nil
}
