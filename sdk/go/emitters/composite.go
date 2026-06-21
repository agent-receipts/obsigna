package emitters

import (
	"context"
	"errors"
	"fmt"

	"obsigna.dev/sdk/go/receipt"
)

// CompositeEmitter forwards each receipt to a list of child emitters
// sequentially. Every child is attempted, in order. If a child returns an
// error, that error is captured and the remaining children are still
// attempted. When at least one child returned an error, Emit returns a
// wrapped error built with [errors.Join] holding the underlying errors in
// the order they were observed.
//
// Use cases: writing to a primary collector plus an offsite archive, or
// dual-writing during an endpoint migration.
//
// Per ADR-0020 every child must implement the [Emitter] interface;
// [emitter.DaemonEmitter] does not (yet) — it takes the unsigned event
// frame, not a signed receipt.
type CompositeEmitter struct {
	children []Emitter
}

// NewComposite returns a CompositeEmitter that forwards to every child in
// the given order. The caller's slice is defensively copied so subsequent
// mutations to it do not affect the composite's child list.
func NewComposite(children []Emitter) *CompositeEmitter {
	cp := make([]Emitter, len(children))
	copy(cp, children)
	return &CompositeEmitter{children: cp}
}

// Emit fans r out to every child sequentially. Errors from individual
// children are aggregated and returned as one joined error so callers can
// see every failure without losing the partial-success information.
func (c *CompositeEmitter) Emit(ctx context.Context, r receipt.AgentReceipt) error {
	var errs []error
	for _, child := range c.children {
		if err := child.Emit(ctx, r); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("CompositeEmitter: %d of %d child emitters failed: %w",
		len(errs), len(c.children), errors.Join(errs...))
}
