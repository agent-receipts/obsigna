package emitters_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"obsigna.dev/sdk/go/emitters"
	"obsigna.dev/sdk/go/receipt"
)

// signalingEmitter notifies on every Emit so timer-driven tests don't have
// to poll.
type signalingEmitter struct {
	mu       sync.Mutex
	received []receipt.AgentReceipt
	ch       chan struct{}
}

func newSignalingEmitter(buf int) *signalingEmitter {
	return &signalingEmitter{ch: make(chan struct{}, buf)}
}

func (s *signalingEmitter) Emit(_ context.Context, r receipt.AgentReceipt) error {
	s.mu.Lock()
	s.received = append(s.received, r)
	s.mu.Unlock()
	select {
	case s.ch <- struct{}{}:
	default:
	}
	return nil
}

func (s *signalingEmitter) Received() []receipt.AgentReceipt {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]receipt.AgentReceipt, len(s.received))
	copy(out, s.received)
	return out
}

func TestBufferingEmitter_RejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  emitters.BufferingEmitterConfig
	}{
		{
			"missing inner",
			emitters.BufferingEmitterConfig{MaxBatchSize: 1, FlushInterval: time.Second},
		},
		{
			"zero batch size",
			emitters.BufferingEmitterConfig{
				Inner: emitters.NewInMemory(), MaxBatchSize: 0, FlushInterval: time.Second,
			},
		},
		{
			"zero interval",
			emitters.BufferingEmitterConfig{
				Inner: emitters.NewInMemory(), MaxBatchSize: 1, FlushInterval: 0,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := emitters.NewBuffering(tc.cfg); err == nil {
				t.Fatalf("NewBuffering(%s) = nil err; want validation error", tc.name)
			}
		})
	}
}

func TestBufferingEmitter_FlushesOnBatchSize(t *testing.T) {
	inner := emitters.NewInMemory()
	buf, err := emitters.NewBuffering(emitters.BufferingEmitterConfig{
		Inner: inner, MaxBatchSize: 3, FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewBuffering: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close(context.Background()) })

	ctx := context.Background()
	for _, id := range []string{"r1", "r2"} {
		if err := buf.Emit(ctx, fakeReceipt(id)); err != nil {
			t.Fatalf("Emit(%s): %v", id, err)
		}
	}
	if got := inner.Received(); len(got) != 0 {
		t.Fatalf("flushed early: %v", got)
	}
	if err := buf.Emit(ctx, fakeReceipt("r3")); err != nil {
		t.Fatalf("Emit(r3): %v", err)
	}
	got := inner.Received()
	if len(got) != 3 {
		t.Fatalf("inner.Received() = %v; want 3 entries", got)
	}
}

func TestBufferingEmitter_FlushesOnInterval(t *testing.T) {
	sig := newSignalingEmitter(4)
	buf, err := emitters.NewBuffering(emitters.BufferingEmitterConfig{
		Inner: sig, MaxBatchSize: 100, FlushInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewBuffering: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close(context.Background()) })

	if err := buf.Emit(context.Background(), fakeReceipt("r1")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	select {
	case <-sig.ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("interval flush did not fire within 2s")
	}
	if got := sig.Received(); len(got) != 1 || got[0].ID != "r1" {
		t.Errorf("received = %v; want [r1]", got)
	}
}

func TestBufferingEmitter_ExplicitFlushDrainsBuffer(t *testing.T) {
	inner := emitters.NewInMemory()
	buf, err := emitters.NewBuffering(emitters.BufferingEmitterConfig{
		Inner: inner, MaxBatchSize: 100, FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewBuffering: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close(context.Background()) })

	ctx := context.Background()
	_ = buf.Emit(ctx, fakeReceipt("r1"))
	_ = buf.Emit(ctx, fakeReceipt("r2"))
	if err := buf.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	got := inner.Received()
	if len(got) != 2 {
		t.Fatalf("inner.Received() = %v; want 2 entries", got)
	}
}

func TestBufferingEmitter_PerReceiptContract(t *testing.T) {
	inner := emitters.NewInMemory()
	buf, err := emitters.NewBuffering(emitters.BufferingEmitterConfig{
		Inner: inner, MaxBatchSize: 4, FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewBuffering: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close(context.Background()) })

	ctx := context.Background()
	for _, id := range []string{"r1", "r2", "r3", "r4"} {
		_ = buf.Emit(ctx, fakeReceipt(id))
	}
	// Each receipt arrives individually at the downstream — not batched.
	if got := inner.Received(); len(got) != 4 {
		t.Fatalf("inner.Received() = %v; want 4 separate entries", got)
	}
}

func TestBufferingEmitter_FlushSurfacesDownstreamError(t *testing.T) {
	boom := errors.New("downstream failed")
	buf, err := emitters.NewBuffering(emitters.BufferingEmitterConfig{
		Inner:         &failingEmitter{err: boom},
		MaxBatchSize:  100,
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewBuffering: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close(context.Background()) })

	ctx := context.Background()
	_ = buf.Emit(ctx, fakeReceipt("r1"))
	if err := buf.Flush(ctx); !errors.Is(err, boom) {
		t.Fatalf("Flush err = %v; want %v", err, boom)
	}
}

// flakyEmitter alternates failures and successes so a single batch can
// observe both outcomes — exercises the per-receipt aggregation path.
type flakyEmitter struct {
	mu        sync.Mutex
	attempted []string
	fail      error
}

func (f *flakyEmitter) Emit(_ context.Context, r receipt.AgentReceipt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempted = append(f.attempted, r.ID)
	if len(f.attempted)%2 == 1 {
		return fmt.Errorf("%w: %s", f.fail, r.ID)
	}
	return nil
}

func TestBufferingEmitter_FlushAttemptsEveryReceiptAggregatingFailures(t *testing.T) {
	// B4: a downstream error on receipt N must not drop receipts N+1..M
	// from the current batch.
	boom := errors.New("downstream boom")
	flaky := &flakyEmitter{fail: boom}
	buf, err := emitters.NewBuffering(emitters.BufferingEmitterConfig{
		Inner:         flaky,
		MaxBatchSize:  100,
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewBuffering: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close(context.Background()) })

	ctx := context.Background()
	ids := []string{"r1", "r2", "r3", "r4"}
	for _, id := range ids {
		if err := buf.Emit(ctx, fakeReceipt(id)); err != nil {
			t.Fatalf("Emit(%s): %v", id, err)
		}
	}
	err = buf.Flush(ctx)
	if err == nil {
		t.Fatalf("Flush err = nil; want aggregated error")
	}
	// All four were attempted, in submission order.
	flaky.mu.Lock()
	got := append([]string(nil), flaky.attempted...)
	flaky.mu.Unlock()
	if len(got) != 4 {
		t.Errorf("attempted = %v; want all 4 attempted", got)
	}
	for i, want := range ids {
		if i >= len(got) || got[i] != want {
			t.Errorf("attempted[%d] = %q; want %q (full=%v)", i, got[i], want, got)
		}
	}
	// The aggregated error wraps the original boom.
	if !errors.Is(err, boom) {
		t.Errorf("errors.Is(err, boom) = false; err = %v", err)
	}
}

func TestBufferingEmitter_ConcurrentEmitsAndFlushAreSerialised(t *testing.T) {
	// B3: concurrent Emit + Flush must never observe interleaved
	// inner.Emit() calls. The inner emitter records its observed order
	// guarded by a private lock; we then assert that no batch's receipts
	// were interleaved with another batch's by counting overlapping
	// in-flight calls.
	var (
		mu        sync.Mutex
		inFlight  atomic.Int32
		maxInF    atomic.Int32
		delivered []string
	)
	slow := emitterFunc(func(_ context.Context, r receipt.AgentReceipt) error {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			cur := maxInF.Load()
			if n <= cur || maxInF.CompareAndSwap(cur, n) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		mu.Lock()
		delivered = append(delivered, r.ID)
		mu.Unlock()
		return nil
	})
	buf, err := emitters.NewBuffering(emitters.BufferingEmitterConfig{
		Inner:         slow,
		MaxBatchSize:  2,
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewBuffering: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close(context.Background()) })

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("r%02d", idx)
			_ = buf.Emit(context.Background(), fakeReceipt(id))
		}(i)
	}
	wg.Wait()
	if err := buf.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := maxInF.Load(); got > 1 {
		t.Errorf("delivery lock failed: max concurrent inner.Emit = %d; want <=1", got)
	}
	if len(delivered) != 20 {
		t.Errorf("delivered %d; want 20", len(delivered))
	}
}

func TestBufferingEmitter_CloseDrainsAndBlocksEmit(t *testing.T) {
	inner := emitters.NewInMemory()
	buf, err := emitters.NewBuffering(emitters.BufferingEmitterConfig{
		Inner: inner, MaxBatchSize: 100, FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewBuffering: %v", err)
	}

	ctx := context.Background()
	_ = buf.Emit(ctx, fakeReceipt("r1"))
	if err := buf.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := inner.Received(); len(got) != 1 || got[0].ID != "r1" {
		t.Errorf("inner.Received() = %v; want [r1]", got)
	}
	if err := buf.Emit(ctx, fakeReceipt("r2")); err == nil {
		t.Errorf("Emit after Close: nil err; want closed error")
	}
}
