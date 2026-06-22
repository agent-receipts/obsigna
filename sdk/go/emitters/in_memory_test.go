package emitters_test

import (
	"context"
	"testing"

	"obsigna.dev/sdk/go/emitters"
	"obsigna.dev/sdk/go/receipt"
)

func fakeReceipt(id string) receipt.AgentReceipt {
	return receipt.AgentReceipt{ID: id}
}

func TestInMemoryEmitter_StartsEmpty(t *testing.T) {
	e := emitters.NewInMemory()
	if got := e.Received(); len(got) != 0 {
		t.Fatalf("Received() = %v; want empty", got)
	}
}

func TestInMemoryEmitter_AppendsInOrder(t *testing.T) {
	e := emitters.NewInMemory()
	for _, id := range []string{"r1", "r2", "r3"} {
		if err := e.Emit(context.Background(), fakeReceipt(id)); err != nil {
			t.Fatalf("Emit(%s): %v", id, err)
		}
	}
	got := e.Received()
	if len(got) != 3 {
		t.Fatalf("len(Received()) = %d; want 3", len(got))
	}
	for i, want := range []string{"r1", "r2", "r3"} {
		if got[i].ID != want {
			t.Errorf("Received[%d].ID = %q; want %q", i, got[i].ID, want)
		}
	}
}

func TestInMemoryEmitter_Clear(t *testing.T) {
	e := emitters.NewInMemory()
	_ = e.Emit(context.Background(), fakeReceipt("r1"))
	e.Clear()
	if got := e.Received(); len(got) != 0 {
		t.Fatalf("Received() after Clear() = %v; want empty", got)
	}
}

func TestInMemoryEmitter_ImplementsEmitter(t *testing.T) {
	// Compile-time check: NewInMemory must satisfy emitters.Emitter.
	var _ emitters.Emitter = emitters.NewInMemory()
}

func TestInMemoryEmitter_ReceivedReturnsCopy(t *testing.T) {
	// Mutating the returned slice MUST NOT affect the emitter's internal
	// state. Otherwise tests could accidentally clobber recorded receipts.
	e := emitters.NewInMemory()
	_ = e.Emit(context.Background(), fakeReceipt("r1"))
	got := e.Received()
	got[0].ID = "mutated"
	if e.Received()[0].ID != "r1" {
		t.Fatalf("internal slice was mutated through Received()")
	}
}
