package checkpoint

import (
	"errors"
	"sync"
	"testing"

	"github.com/agent-receipts/ar/daemon/internal/anchor"
)

// recordingSink captures every payload it is asked to write. okWrite toggles
// whether Write succeeds, so a single type covers both the happy and the
// fail-visible paths.
type recordingSink struct {
	mu      sync.Mutex
	writes  [][]byte
	events  []string
	okWrite bool
	closed  bool
}

func (s *recordingSink) Write(eventType string, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.okWrite {
		return errors.New("sink down")
	}
	s.events = append(s.events, eventType)
	cp := append([]byte(nil), payload...)
	s.writes = append(s.writes, cp)
	return nil
}

func (s *recordingSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *recordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.writes)
}

func TestEmitterFanOut(t *testing.T) {
	signer, _ := newTestSigner(t)
	a := &recordingSink{okWrite: true}
	b := &recordingSink{okWrite: true}
	e := NewEmitter([]anchor.Sink{a, b}, signer, 1, nil)
	defer func() { _ = e.Close() }()

	e.Observe("chain-1", 1, "sha256:aa")
	_ = e.FlushAll() // drain the async worker before asserting

	if a.count() != 1 || b.count() != 1 {
		t.Fatalf("fan-out incomplete: a=%d b=%d, want 1 each", a.count(), b.count())
	}
	if got := e.Emitted(); got != 1 {
		t.Errorf("Emitted = %d, want 1", got)
	}
	if got := e.Failures(); got != 0 {
		t.Errorf("Failures = %d, want 0", got)
	}
}

func TestEmitterCadence(t *testing.T) {
	signer, _ := newTestSigner(t)
	sink := &recordingSink{okWrite: true}
	e := NewEmitter([]anchor.Sink{sink}, signer, 3, nil)
	defer func() { _ = e.Close() }()

	// Cadence 3 over 5 receipts: only the 3rd observation emits (seqs 4,5 leave
	// the counter at 2, below the cadence).
	for seq := int64(1); seq <= 5; seq++ {
		e.Observe("chain-1", seq, "sha256:h")
	}
	_ = e.FlushAll() // drain before checking
	if got := sink.count(); got != 1 {
		t.Fatalf("with cadence 3 over 5 receipts, got %d checkpoints, want 1", got)
	}

	// Flush forces a final emission of the current head (seq 5) even though it
	// fell off a cadence boundary and was not yet anchored (the graceful-shutdown
	// path). seq 5 > the last-anchored seq 3, so it emits.
	e.Flush("chain-1", 5, "sha256:head")
	if got := sink.count(); got != 2 {
		t.Fatalf("after Flush of an unanchored head, got %d checkpoints, want 2", got)
	}
}

func TestEmitterFailVisibleNotSilent(t *testing.T) {
	signer, _ := newTestSigner(t)
	down := &recordingSink{okWrite: false}
	up := &recordingSink{okWrite: true}

	var logged int
	logf := func(string, ...any) { logged++ }
	e := NewEmitter([]anchor.Sink{down, up}, signer, 1, logf)
	defer func() { _ = e.Close() }()

	// One sink fails; the other still receives the checkpoint. The failure is
	// counted and logged (visible), and Observe never panics or blocks — it runs
	// after the receipt is already committed and must not undo it.
	e.Observe("chain-1", 1, "sha256:aa")
	_ = e.FlushAll() // drain the async worker before asserting

	if up.count() != 1 {
		t.Errorf("healthy sink got %d writes, want 1 (a failing sibling must not block it)", up.count())
	}
	if got := e.Failures(); got != 1 {
		t.Errorf("Failures = %d, want 1 (the down sink)", got)
	}
	if logged == 0 {
		t.Error("a sink failure was not logged — failures must be visible, not silent")
	}
	// At least one sink accepted it, so it counts as emitted.
	if got := e.Emitted(); got != 1 {
		t.Errorf("Emitted = %d, want 1", got)
	}
}

func TestEmitterFlushDoesNotReEmitAlreadyAnchoredHead(t *testing.T) {
	signer, _ := newTestSigner(t)
	sink := &recordingSink{okWrite: true}
	e := NewEmitter([]anchor.Sink{sink}, signer, 1, nil)
	defer func() { _ = e.Close() }()

	// Per-receipt Observe anchors head seq 3 (cadence 1).
	e.Observe("c", 3, "sha256:h3")
	_ = e.FlushAll() // drain before asserting
	if sink.count() != 1 {
		t.Fatalf("after Observe(3): got %d checkpoints, want 1", sink.count())
	}

	// Graceful shutdown re-flushes the SAME head (e.g. the terminator was skipped
	// on a tight deadline, so the tail is still seq 3). This must NOT write a
	// second checkpoint at seq 3 — a duplicate makes verify read the anchor log
	// as non-strictly-increasing and fail a healthy chain (the bug this guards).
	e.Flush("c", 3, "sha256:h3")
	if sink.count() != 1 {
		t.Fatalf("Flush re-anchored an already-anchored head: got %d checkpoints, want 1", sink.count())
	}

	// A flush at a genuinely new head (the terminator advanced the chain to 4)
	// still anchors.
	e.Flush("c", 4, "sha256:h4")
	if sink.count() != 2 {
		t.Fatalf("Flush at a new head did not anchor: got %d checkpoints, want 2", sink.count())
	}
}

func TestEmitterClosesAllSinks(t *testing.T) {
	signer, _ := newTestSigner(t)
	a := &recordingSink{okWrite: true}
	b := &recordingSink{okWrite: true}
	e := NewEmitter([]anchor.Sink{a, b}, signer, 1, nil)
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !a.closed || !b.closed {
		t.Errorf("Close did not close all sinks: a=%v b=%v", a.closed, b.closed)
	}
}
