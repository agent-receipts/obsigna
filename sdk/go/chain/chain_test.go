package chain_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"obsigna.dev/sdk/go/chain"
	"obsigna.dev/sdk/go/emitters"
	"obsigna.dev/sdk/go/receipt"
)

const verificationMethod = "did:agent:test#key-1"

func testKeys(t *testing.T) receipt.KeyPair {
	t.Helper()
	keys, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return keys
}

func emitInput() chain.EmitInput {
	return chain.EmitInput{
		Issuer:    receipt.Issuer{ID: "did:agent:test"},
		Principal: receipt.Principal{ID: "did:user:alice"},
		Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
		Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
	}
}

// recordingHandler captures log messages and signals on the first Warn.
type recordingHandler struct {
	mu     sync.Mutex
	msgs   []string
	warned chan struct{}
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.msgs = append(h.msgs, r.Message)
	h.mu.Unlock()
	if r.Level == slog.LevelWarn && h.warned != nil {
		select {
		case h.warned <- struct{}{}:
		default:
		}
	}
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) warnCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, m := range h.msgs {
		if strings.Contains(m, "concurrent Emit()") {
			n++
		}
	}
	return n
}

// gateEmitter blocks every delivery until release is closed, then records.
type gateEmitter struct {
	inner   *emitters.InMemoryEmitter
	release chan struct{}
}

func (g *gateEmitter) Emit(ctx context.Context, r receipt.AgentReceipt) error {
	<-g.release
	return g.inner.Emit(ctx, r)
}

func TestNewRequiresCoreOptions(t *testing.T) {
	keys := testKeys(t)
	base := chain.Options{
		ChainID:            "c",
		PrivateKeyPEM:      keys.PrivateKey,
		VerificationMethod: verificationMethod,
		Emitter:            emitters.NewInMemory(),
	}
	cases := map[string]func(o *chain.Options){
		"ChainID":            func(o *chain.Options) { o.ChainID = "" },
		"PrivateKeyPEM":      func(o *chain.Options) { o.PrivateKeyPEM = "" },
		"VerificationMethod": func(o *chain.Options) { o.VerificationMethod = "" },
		"Emitter":            func(o *chain.Options) { o.Emitter = nil },
		"negative StartSeq":  func(o *chain.Options) { o.StartSequence = -1 },
	}
	for name, mutate := range cases {
		opts := base
		mutate(&opts)
		if _, err := chain.New(opts); err == nil {
			t.Errorf("New with empty %s: want error, got nil", name)
		}
	}
}

func TestEmitBuildsSignsLinksAndDelivers(t *testing.T) {
	keys := testKeys(t)
	inmem := emitters.NewInMemory()
	rc, err := chain.New(chain.Options{
		ChainID:            "chain_test",
		PrivateKeyPEM:      keys.PrivateKey,
		VerificationMethod: verificationMethod,
		Emitter:            inmem,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := rc.NextSequence(); got != 1 {
		t.Errorf("NextSequence before emit = %d, want 1", got)
	}
	if rc.PreviousReceiptHash() != nil {
		t.Error("PreviousReceiptHash before emit = non-nil, want nil")
	}

	ctx := context.Background()
	r1, err := rc.Emit(ctx, emitInput())
	if err != nil {
		t.Fatalf("Emit r1: %v", err)
	}
	r2, err := rc.Emit(ctx, emitInput())
	if err != nil {
		t.Fatalf("Emit r2: %v", err)
	}

	if r1.CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("r1 sequence = %d, want 1", r1.CredentialSubject.Chain.Sequence)
	}
	if r1.CredentialSubject.Chain.PreviousReceiptHash != nil {
		t.Error("r1 previous_receipt_hash = non-nil, want nil")
	}
	if r2.CredentialSubject.Chain.Sequence != 2 {
		t.Errorf("r2 sequence = %d, want 2", r2.CredentialSubject.Chain.Sequence)
	}
	h1, err := receipt.HashReceipt(r1)
	if err != nil {
		t.Fatalf("HashReceipt r1: %v", err)
	}
	if got := r2.CredentialSubject.Chain.PreviousReceiptHash; got == nil || *got != h1 {
		t.Errorf("r2 previous_receipt_hash = %v, want %q", got, h1)
	}

	if got := rc.NextSequence(); got != 3 {
		t.Errorf("NextSequence after two emits = %d, want 3", got)
	}

	result := receipt.VerifyChain(inmem.Received(), keys.PublicKey)
	if !result.Valid {
		t.Errorf("VerifyChain: not valid: %+v", result)
	}
}

func TestNoWarnWhenSequential(t *testing.T) {
	keys := testKeys(t)
	rec := &recordingHandler{}
	rc, err := chain.New(chain.Options{
		ChainID:            "chain_test",
		PrivateKeyPEM:      keys.PrivateKey,
		VerificationMethod: verificationMethod,
		Emitter:            emitters.NewInMemory(),
		Logger:             slog.New(rec),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	for range 3 {
		if _, err := rc.Emit(ctx, emitInput()); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	if n := rec.warnCount(); n != 0 {
		t.Errorf("sequential emits warned %d times, want 0", n)
	}
}

func TestConcurrentEmitsSerialisedAndWarn(t *testing.T) {
	keys := testKeys(t)
	rec := &recordingHandler{warned: make(chan struct{}, 1)}
	gate := &gateEmitter{inner: emitters.NewInMemory(), release: make(chan struct{})}
	rc, err := chain.New(chain.Options{
		ChainID:            "chain_test",
		PrivateKeyPEM:      keys.PrivateKey,
		VerificationMethod: verificationMethod,
		Emitter:            gate,
		Logger:             slog.New(rec),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const n = 5
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = rc.Emit(context.Background(), emitInput())
		}()
	}

	// Wait for the warning (proof that ≥2 emits overlapped) before releasing
	// the gate; bounded so a regression fails instead of hanging.
	select {
	case <-rec.warned:
	case <-time.After(5 * time.Second):
		t.Fatal("expected a concurrency warning")
	}
	close(gate.release)
	wg.Wait()

	received := gate.inner.Received()
	if len(received) != n {
		t.Fatalf("received %d receipts, want %d", len(received), n)
	}
	for i, r := range received {
		if got := r.CredentialSubject.Chain.Sequence; got != i+1 {
			t.Errorf("received[%d] sequence = %d, want %d", i, got, i+1)
		}
	}
	if result := receipt.VerifyChain(received, keys.PublicKey); !result.Valid {
		t.Errorf("VerifyChain: not valid: %+v", result)
	}
	if got := rec.warnCount(); got != 1 {
		t.Errorf("warned %d times, want exactly 1", got)
	}
}

func TestRejectsEmitAfterTerminal(t *testing.T) {
	keys := testKeys(t)
	rc, err := chain.New(chain.Options{
		ChainID:            "chain_test",
		PrivateKeyPEM:      keys.PrivateKey,
		VerificationMethod: verificationMethod,
		Emitter:            emitters.NewInMemory(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	terminal := emitInput()
	terminal.Terminal = true
	if _, err := rc.Emit(ctx, terminal); err != nil {
		t.Fatalf("Emit terminal: %v", err)
	}
	if _, err := rc.Emit(ctx, emitInput()); err == nil {
		t.Fatal("Emit after terminal: want closed-chain error, got nil")
	}
}

func TestHeadAdvancesBeforeDelivery(t *testing.T) {
	keys := testKeys(t)
	fe := &failingEmitter{inner: emitters.NewInMemory(), failNext: true}
	rc, err := chain.New(chain.Options{
		ChainID:            "chain_test",
		PrivateKeyPEM:      keys.PrivateKey,
		VerificationMethod: verificationMethod,
		Emitter:            fe,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	if _, err := rc.Emit(ctx, emitInput()); err == nil {
		t.Fatal("Emit: want delivery error, got nil")
	}
	// Head advanced even though delivery failed.
	if got := rc.NextSequence(); got != 2 {
		t.Errorf("NextSequence after failed delivery = %d, want 2", got)
	}

	r2, err := rc.Emit(ctx, emitInput())
	if err != nil {
		t.Fatalf("Emit r2: %v", err)
	}
	if r2.CredentialSubject.Chain.Sequence != 2 {
		t.Errorf("r2 sequence = %d, want 2", r2.CredentialSubject.Chain.Sequence)
	}
	// r2 links to the signed-but-undelivered r1, not back to nil.
	if r2.CredentialSubject.Chain.PreviousReceiptHash == nil {
		t.Error("r2 previous_receipt_hash = nil, want the failed receipt's hash")
	}
}

func TestResumeExistingChain(t *testing.T) {
	keys := testKeys(t)
	prev := "sha256:deadbeef"
	rc, err := chain.New(chain.Options{
		ChainID:             "chain_test",
		PrivateKeyPEM:       keys.PrivateKey,
		VerificationMethod:  verificationMethod,
		Emitter:             emitters.NewInMemory(),
		StartSequence:       7,
		PreviousReceiptHash: &prev,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r, err := rc.Emit(context.Background(), emitInput())
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if r.CredentialSubject.Chain.Sequence != 7 {
		t.Errorf("sequence = %d, want 7", r.CredentialSubject.Chain.Sequence)
	}
	if got := r.CredentialSubject.Chain.PreviousReceiptHash; got == nil || *got != prev {
		t.Errorf("previous_receipt_hash = %v, want %q", got, prev)
	}
}

func TestEmitPreservesCorrelationID(t *testing.T) {
	keys := testKeys(t)
	inmem := emitters.NewInMemory()
	rc, err := chain.New(chain.Options{
		ChainID:            "chain_test",
		PrivateKeyPEM:      keys.PrivateKey,
		VerificationMethod: verificationMethod,
		Emitter:            inmem,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const want = "toolu_01AAAAAAAAAAAAAAAAAAAAAA"
	input := emitInput()
	input.CorrelationID = want

	ctx := context.Background()
	r, err := rc.Emit(ctx, input)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := r.CredentialSubject.CorrelationID; got != want {
		t.Errorf("CorrelationID = %q, want %q", got, want)
	}
}

type failingEmitter struct {
	inner    *emitters.InMemoryEmitter
	failNext bool
}

func (f *failingEmitter) Emit(ctx context.Context, r receipt.AgentReceipt) error {
	if f.failNext {
		f.failNext = false
		return errors.New("collector unreachable")
	}
	return f.inner.Emit(ctx, r)
}
