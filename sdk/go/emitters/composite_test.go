package emitters_test

import (
	"context"
	"errors"
	"testing"

	"obsigna.dev/sdk/go/emitters"
	"obsigna.dev/sdk/go/receipt"
)

// failingEmitter always returns the configured error.
type failingEmitter struct {
	err   error
	calls []receipt.AgentReceipt
}

func (f *failingEmitter) Emit(_ context.Context, r receipt.AgentReceipt) error {
	f.calls = append(f.calls, r)
	return f.err
}

func TestCompositeEmitter_ForwardsToAllChildren(t *testing.T) {
	a, b, c := emitters.NewInMemory(), emitters.NewInMemory(), emitters.NewInMemory()
	comp := emitters.NewComposite([]emitters.Emitter{a, b, c})

	if err := comp.Emit(context.Background(), fakeReceipt("r1")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := comp.Emit(context.Background(), fakeReceipt("r2")); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	for i, child := range []*emitters.InMemoryEmitter{a, b, c} {
		got := child.Received()
		if len(got) != 2 || got[0].ID != "r1" || got[1].ID != "r2" {
			t.Errorf("child %d received %v; want [r1 r2]", i, got)
		}
	}
}

func TestCompositeEmitter_ContinuesPastFailingChild(t *testing.T) {
	before := emitters.NewInMemory()
	boom := errors.New("kaboom")
	fail := &failingEmitter{err: boom}
	after := emitters.NewInMemory()

	comp := emitters.NewComposite([]emitters.Emitter{before, fail, after})
	err := comp.Emit(context.Background(), fakeReceipt("r1"))
	if err == nil {
		t.Fatalf("Emit returned nil error; want aggregated failure")
	}
	if !errors.Is(err, boom) {
		t.Errorf("errors.Is(err, boom) = false; want true")
	}
	if len(before.Received()) != 1 {
		t.Errorf("before.Received() = %v; want 1 entry", before.Received())
	}
	if len(fail.calls) != 1 {
		t.Errorf("fail.calls = %v; want 1 entry", fail.calls)
	}
	if len(after.Received()) != 1 {
		t.Errorf("after.Received() = %v; want 1 entry", after.Received())
	}
}

func TestCompositeEmitter_AggregatesMultipleErrors(t *testing.T) {
	err1 := errors.New("first")
	err2 := errors.New("second")
	comp := emitters.NewComposite([]emitters.Emitter{
		&failingEmitter{err: err1},
		emitters.NewInMemory(),
		&failingEmitter{err: err2},
	})

	err := comp.Emit(context.Background(), fakeReceipt("r1"))
	if err == nil {
		t.Fatalf("Emit returned nil error")
	}
	if !errors.Is(err, err1) || !errors.Is(err, err2) {
		t.Errorf("errors.Is missed one of the wrapped errors: %v", err)
	}
}

func TestCompositeEmitter_AllSucceed(t *testing.T) {
	comp := emitters.NewComposite([]emitters.Emitter{
		emitters.NewInMemory(),
		emitters.NewInMemory(),
	})
	if err := comp.Emit(context.Background(), fakeReceipt("r1")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
}

func TestCompositeEmitter_NoChildrenIsNoop(t *testing.T) {
	comp := emitters.NewComposite(nil)
	if err := comp.Emit(context.Background(), fakeReceipt("r1")); err != nil {
		t.Fatalf("Emit on empty composite: %v", err)
	}
}
