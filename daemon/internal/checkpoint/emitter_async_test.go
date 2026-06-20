package checkpoint

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/anchor"
)

// slowSink simulates a sink whose Write blocks for a configurable duration,
// so tests can confirm that Observe returns before the sink finishes.
type slowSink struct {
	mu     sync.Mutex
	delay  time.Duration
	writes atomic.Int64
	closed bool
}

func (s *slowSink) Write(_ string, _ []byte) error {
	time.Sleep(s.delay)
	s.writes.Add(1)
	return nil
}

func (s *slowSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// TestObserveDoesNotBlockOnSlowSink verifies the core liveness requirement:
// Observe must return quickly even when the underlying sink is slow. A 50 ms
// Observe wall-time budget is used; the sink itself blocks for 200 ms.
func TestObserveDoesNotBlockOnSlowSink(t *testing.T) {
	signer, _ := newTestSigner(t)
	slow := &slowSink{delay: 200 * time.Millisecond}
	e := NewEmitter([]anchor.Sink{slow}, signer, 1, nil)
	defer func() { _ = e.Close() }()

	start := time.Now()
	e.Observe("chain-1", 1, "sha256:aa")
	elapsed := time.Since(start)

	// Observe must return before the sink delay expires.
	if elapsed > 50*time.Millisecond {
		t.Errorf("Observe blocked for %v; want < 50ms (sink delay is 200ms)", elapsed)
	}

	// Flush drains the queue: the slow write must have completed by the time
	// Flush returns so the shutdown path is guaranteed.
	if err := e.FlushAll(); err != nil {
		t.Fatalf("FlushAll: %v", err)
	}
	if got := slow.writes.Load(); got != 1 {
		t.Errorf("after FlushAll, sink received %d writes, want 1", got)
	}
}

// TestQueueDropsWhenFull verifies the bounded-queue backpressure path: when
// the worker queue is full and Observe is called many times concurrently,
// Observe never blocks (returns immediately) and the drop counter increments.
func TestQueueDropsWhenFull(t *testing.T) {
	signer, _ := newTestSigner(t)
	// Sink blocks for a long time so the worker stalls and the queue fills up.
	slow := &slowSink{delay: 2 * time.Second}
	var logged int
	logf := func(string, ...any) { logged++ }

	// Queue depth 1 so overflow happens quickly without relying on many goroutines.
	e := newEmitterWithQueueDepth([]anchor.Sink{slow}, signer, 1, logf, 1)
	defer func() { _ = e.Close() }()

	// Saturate the queue: send enough Observes to guarantee at least one drop.
	// We send cadence=1, so every Observe would emit. Queue depth is 1, plus
	// the worker is blocked, so anything beyond the first item overflows.
	const sends = 10
	start := time.Now()
	for i := int64(1); i <= sends; i++ {
		e.Observe("chain-1", i, "sha256:x")
	}
	elapsed := time.Since(start)

	// All Observe calls must have returned without blocking.
	if elapsed > 500*time.Millisecond {
		t.Errorf("Observe loop blocked for %v across %d calls; want fast (non-blocking)", elapsed, sends)
	}
	if got := e.Dropped(); got == 0 {
		t.Error("expected at least one drop when queue is saturated; Dropped() == 0")
	}
	if logged == 0 {
		t.Error("expected at least one log line for queue drop; none seen")
	}
}

// TestFlushAllDrains verifies that FlushAll waits until all enqueued emissions
// have been sent to the sink before returning.
func TestFlushAllDrains(t *testing.T) {
	signer, _ := newTestSigner(t)
	var mu sync.Mutex
	var received []int64
	sink := &recordingSink{okWrite: true}

	// Wrap the recording sink to capture seq order independently.
	_ = sink
	counter := &countSink{}
	e := NewEmitter([]anchor.Sink{counter}, signer, 1, nil)
	defer func() { _ = e.Close() }()

	const n = 5
	for i := int64(1); i <= n; i++ {
		e.Observe("c", i, "sha256:h")
	}

	if err := e.FlushAll(); err != nil {
		t.Fatalf("FlushAll: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	_ = received // keep linter happy
	if got := counter.count(); int(got) != n {
		t.Errorf("after FlushAll, sink received %d writes, want %d", got, n)
	}
}

// TestFlushAllAfterCloseIsNoop verifies that calling FlushAll on a closed
// emitter does not panic or deadlock.
func TestFlushAllAfterCloseIsNoop(t *testing.T) {
	signer, _ := newTestSigner(t)
	sink := &recordingSink{okWrite: true}
	e := NewEmitter([]anchor.Sink{sink}, signer, 1, nil)
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Should not block or panic.
	done := make(chan struct{})
	go func() {
		_ = e.FlushAll()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("FlushAll after Close blocked for 2s; likely deadlock")
	}
}

// TestConcurrentObserveNoPanic stress-tests concurrent Observe calls across
// multiple goroutines to catch data races (run with -race).
func TestConcurrentObserveNoPanic(t *testing.T) {
	signer, _ := newTestSigner(t)
	sink := &recordingSink{okWrite: true}
	e := NewEmitter([]anchor.Sink{sink}, signer, 1, nil)
	defer func() { _ = e.Close() }()

	var wg sync.WaitGroup
	const goroutines = 10
	const perGoroutine = 20
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				e.Observe("chain", int64(base*perGoroutine+i+1), "sha256:h")
			}
		}(g)
	}
	wg.Wait()
	if err := e.FlushAll(); err != nil {
		t.Fatalf("FlushAll: %v", err)
	}
}

// countSink counts writes without storing payloads. Lighter than recordingSink
// when payload content is not needed.
type countSink struct {
	n atomic.Int64
}

func (c *countSink) Write(_ string, _ []byte) error { c.n.Add(1); return nil }
func (c *countSink) Close() error                   { return nil }
func (c *countSink) count() int64                   { return c.n.Load() }
