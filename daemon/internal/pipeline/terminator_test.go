package pipeline

import (
	"context"
	"testing"
	"time"

	"obsigna.dev/daemon/internal/chain"
	"obsigna.dev/sdk/go/receipt"
)

// TestEmitTerminator_EmitsOnOpenChain verifies that EmitTerminator writes a
// terminal receipt with chain.status="interrupted" when the chain has at least
// one non-terminal receipt.
func TestEmitTerminator_EmitsOnOpenChain(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:test")

	// Emit a normal receipt to open the chain.
	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatalf("Process: %v", err)
	}

	if err := p.EmitTerminator(context.Background()); err != nil {
		t.Fatalf("EmitTerminator: %v", err)
	}

	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(receipts) != 2 {
		t.Fatalf("got %d receipts, want 2", len(receipts))
	}

	term := receipts[1]
	c := term.CredentialSubject.Chain
	if c.Terminal == nil || !*c.Terminal {
		t.Error("terminator: chain.terminal is not true")
	}
	if c.Status != receipt.ChainStatusInterrupted {
		t.Errorf("terminator: chain.status = %q, want %q", c.Status, receipt.ChainStatusInterrupted)
	}
	if c.Sequence != 2 {
		t.Errorf("terminator: sequence = %d, want 2", c.Sequence)
	}
	if c.PreviousReceiptHash == nil {
		t.Error("terminator: previous_receipt_hash is nil")
	}
	wantHash, hashErr := receipt.HashReceipt(receipts[0])
	if hashErr != nil {
		t.Fatalf("hash receipt[0]: %v", hashErr)
	}
	if *c.PreviousReceiptHash != wantHash {
		t.Errorf("terminator: previous_receipt_hash = %q, want %q", *c.PreviousReceiptHash, wantHash)
	}
}

// TestEmitTerminator_SkipsEmptyChain verifies that EmitTerminator is a no-op
// when no receipts have been written.
func TestEmitTerminator_SkipsEmptyChain(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("empty-chain")
	p := New(state, ks, st, "did:test")

	if err := p.EmitTerminator(context.Background()); err != nil {
		t.Fatalf("EmitTerminator on empty chain: %v", err)
	}

	receipts, err := st.GetChain("empty-chain")
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(receipts) != 0 {
		t.Errorf("got %d receipts, want 0 (empty chain — no terminator)", len(receipts))
	}
}

// TestEmitTerminator_SkipsAlreadyTerminated verifies that calling EmitTerminator
// twice does not produce a second terminator.
func TestEmitTerminator_SkipsAlreadyTerminated(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("term-chain")
	p := New(state, ks, st, "did:test")

	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := p.EmitTerminator(context.Background()); err != nil {
		t.Fatalf("first EmitTerminator: %v", err)
	}

	// Second call: chain is already terminated — must be a no-op.
	if err := p.EmitTerminator(context.Background()); err != nil {
		t.Fatalf("second EmitTerminator: %v", err)
	}

	receipts, err := st.GetChain("term-chain")
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(receipts) != 2 {
		t.Errorf("got %d receipts after two EmitTerminator calls, want 2", len(receipts))
	}
}

// TestEmitTerminator_ExpiredContext verifies that an already-expired context
// causes EmitTerminator to return a non-nil error without inserting a receipt.
func TestEmitTerminator_ExpiredContext(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("ctx-chain")
	p := New(state, ks, st, "did:test")

	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatalf("Process: %v", err)
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	err := p.EmitTerminator(ctx)
	if err == nil {
		t.Error("EmitTerminator with expired context: want error, got nil")
	}

	// The chain must still have exactly 1 receipt — no partial insert.
	receipts, err2 := st.GetChain("ctx-chain")
	if err2 != nil {
		t.Fatalf("GetChain: %v", err2)
	}
	if len(receipts) != 1 {
		t.Errorf("got %d receipts after expired-ctx call, want 1 (no terminator)", len(receipts))
	}
}

// TestEmitTerminator_ActionType verifies the action type on the emitted receipt.
func TestEmitTerminator_ActionType(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("type-chain")
	p := New(state, ks, st, "did:test")

	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := p.EmitTerminator(context.Background()); err != nil {
		t.Fatalf("EmitTerminator: %v", err)
	}

	receipts, err := st.GetChain("type-chain")
	if err != nil || len(receipts) < 2 {
		t.Fatalf("GetChain: %v / %d receipts", err, len(receipts))
	}

	got := receipts[1].CredentialSubject.Action.Type
	if got != actionTypeChainInterrupted {
		t.Errorf("action.type = %q, want %q", got, actionTypeChainInterrupted)
	}
}
