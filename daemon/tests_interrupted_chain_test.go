//go:build integration && (linux || darwin)

// Integration tests for interrupted-chain terminator emission (issue #500).
// The daemon emits a terminal receipt with chain.status="interrupted" on
// SIGTERM/SIGINT for every chain that has at least one receipt and no terminal
// receipt yet. In-process tests simulate the signal by cancelling the context
// — signal.NotifyContext in main.go converts SIGTERM/SIGINT to the same
// cancellation, so the behaviour under real signals is identical.
package daemon_test

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/daemon/internal/pipeline"
	"github.com/agent-receipts/ar/daemon/internal/sockettest"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// interruptDaemonCfg builds a Config for interrupted-chain tests.
func interruptDaemonCfg(t *testing.T, chainID string) (daemon.Config, string) {
	t.Helper()
	sockDir := sockettest.ShortSocketDir(t)
	dataDir := t.TempDir()
	cfg := daemon.Config{
		SocketPath:           filepath.Join(sockDir, "events.sock"),
		UnsafeSocketPath:     true,
		DBPath:               filepath.Join(dataDir, "receipts.db"),
		KeyPath:              filepath.Join(dataDir, "signing.key"),
		PublicKeyPath:        filepath.Join(dataDir, "signing.key.pub"),
		ChainID:              chainID,
		IssuerID:             "did:agent-receipts-daemon:integration",
		VerificationMethodID: "did:agent-receipts-daemon:integration#k1",
		Logger:               log.New(io.Discard, "", 0),
	}
	pubPEM := writeTestKey(t, cfg.KeyPath)
	return cfg, pubPEM
}

// runInterruptDaemon starts the daemon and waits for its socket to be ready.
// Returns a cancel func and a done channel that receives Run's return value.
func runInterruptDaemon(t *testing.T, cfg daemon.Config) (cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() { ch <- daemon.Run(ctx, cfg) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("unix", cfg.SocketPath, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return cancel, ch
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("daemon socket %s did not become ready within 2s", cfg.SocketPath)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// shutdownAndWait cancels the context and waits for Run to return.
func shutdownAndWait(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("daemon Run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not shut down within 3s")
	}
}

// assertInterruptedTerminator verifies that the last receipt in receipts is a
// properly formed interrupted terminal receipt with correct chain linkage.
func assertInterruptedTerminator(t *testing.T, receipts []receipt.AgentReceipt, pubPEM, chainID string) {
	t.Helper()
	if len(receipts) == 0 {
		t.Fatal("assertInterruptedTerminator: no receipts")
	}

	last := receipts[len(receipts)-1]
	c := last.CredentialSubject.Chain

	if c.ChainID != chainID {
		t.Errorf("terminator chain_id = %q, want %q", c.ChainID, chainID)
	}
	if c.Terminal == nil || !*c.Terminal {
		t.Error("terminator: chain.terminal is not true")
	}
	if c.Status != receipt.ChainStatusInterrupted {
		t.Errorf("terminator: chain.status = %q, want %q", c.Status, receipt.ChainStatusInterrupted)
	}

	// Must link back to the preceding receipt.
	if len(receipts) > 1 {
		prev := receipts[len(receipts)-2]
		wantHash, err := receipt.HashReceipt(prev)
		if err != nil {
			t.Fatalf("hash previous receipt: %v", err)
		}
		if c.PreviousReceiptHash == nil {
			t.Error("terminator: previous_receipt_hash is nil")
		} else if *c.PreviousReceiptHash != wantHash {
			t.Errorf("terminator: previous_receipt_hash = %q, want %q", *c.PreviousReceiptHash, wantHash)
		}
	}

	ok, err := receipt.Verify(last, pubPEM)
	if err != nil || !ok {
		t.Errorf("terminator signature verify: ok=%v err=%v", ok, err)
	}
}

// assertChainVerifiesInterrupted opens the store's VerifyStoredChain and
// checks that the chain verification status is ChainStatusInterrupted.
func assertChainVerifiesInterrupted(t *testing.T, st *store.Store, chainID, pubPEM string) {
	t.Helper()
	cv, err := st.VerifyStoredChain(chainID, pubPEM)
	if err != nil {
		t.Fatalf("VerifyStoredChain: %v", err)
	}
	if cv.Status != receipt.ChainStatusInterrupted {
		t.Errorf("chain verification status = %q, want %q", cv.Status, receipt.ChainStatusInterrupted)
	}
}

// TestInterruptedChainOnSIGTERM verifies that cancelling the daemon context
// (in-process equivalent of SIGTERM) causes the daemon to emit a terminal
// receipt with chain.status="interrupted" and that the stored chain verifies
// cleanly end-to-end.
func TestInterruptedChainOnSIGTERM(t *testing.T) {
	cfg, pubPEM := interruptDaemonCfg(t, "sigterm-chain")
	cancel, done := runInterruptDaemon(t, cfg)

	// Emit one receipt to open the chain.
	emitFrame(t, cfg.SocketPath, pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: "sigterm-sess",
		Channel:   "sdk",
		Tool:      pipeline.EmitterTool{Name: "noop"},
		Decision:  "allowed",
	})
	_ = waitForReceiptCount(t, cfg.DBPath, cfg.ChainID, 1, 5*time.Second)

	// Simulate SIGTERM.
	shutdownAndWait(t, cancel, done)

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	receipts, err := st.GetChain(cfg.ChainID)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(receipts) != 2 {
		t.Fatalf("got %d receipts, want 2 (original + interrupted terminator)", len(receipts))
	}

	assertInterruptedTerminator(t, receipts, pubPEM, cfg.ChainID)
	assertChainVerifiesInterrupted(t, st, cfg.ChainID, pubPEM)
}

// TestInterruptedChainOnSIGINT confirms the SIGINT path is identical to SIGTERM.
// Both signals cancel the same context via signal.NotifyContext; the terminator
// emission path is the same for both.
func TestInterruptedChainOnSIGINT(t *testing.T) {
	cfg, pubPEM := interruptDaemonCfg(t, "sigint-chain")
	cancel, done := runInterruptDaemon(t, cfg)

	emitFrame(t, cfg.SocketPath, pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: "sigint-sess",
		Channel:   "sdk",
		Tool:      pipeline.EmitterTool{Name: "noop"},
		Decision:  "allowed",
	})
	_ = waitForReceiptCount(t, cfg.DBPath, cfg.ChainID, 1, 5*time.Second)

	// Simulate SIGINT (identical mechanism to SIGTERM in the daemon).
	shutdownAndWait(t, cancel, done)

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	receipts, err := st.GetChain(cfg.ChainID)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(receipts) != 2 {
		t.Fatalf("got %d receipts, want 2 (original + interrupted terminator)", len(receipts))
	}

	assertInterruptedTerminator(t, receipts, pubPEM, cfg.ChainID)
	assertChainVerifiesInterrupted(t, st, cfg.ChainID, pubPEM)
}

// TestEmptyChainShutdownClean verifies that a daemon with no open chains
// (no receipts written) shuts down cleanly without emitting a terminator.
func TestEmptyChainShutdownClean(t *testing.T) {
	cfg, _ := interruptDaemonCfg(t, "empty-chain")
	cancel, done := runInterruptDaemon(t, cfg)

	// No receipts — shut down immediately.
	shutdownAndWait(t, cancel, done)

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	receipts, err := st.GetChain(cfg.ChainID)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(receipts) != 0 {
		t.Fatalf("got %d receipts for empty chain, want 0", len(receipts))
	}
}

// TestTerminatorTimeoutSilent verifies that when the shutdown deadline expires
// before the terminator is emitted, Run returns nil (no error), the chain has
// no terminal receipt, and the verifier classifies it as "unknown".
func TestTerminatorTimeoutSilent(t *testing.T) {
	cfg, _ := interruptDaemonCfg(t, "timeout-chain")
	// 1ns deadline expires before the terminator is built.
	cfg.ShutdownDeadline = time.Nanosecond

	cancel, done := runInterruptDaemon(t, cfg)

	emitFrame(t, cfg.SocketPath, pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: "timeout-sess",
		Channel:   "sdk",
		Tool:      pipeline.EmitterTool{Name: "noop"},
		Decision:  "allowed",
	})
	_ = waitForReceiptCount(t, cfg.DBPath, cfg.ChainID, 1, 5*time.Second)

	cancel()
	select {
	case err := <-done:
		// Per spec: timeout failures are silent — Run must return nil.
		if err != nil {
			t.Fatalf("daemon Run returned error on timeout: %v (want nil)", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not shut down within 3s")
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	receipts, err := st.GetChain(cfg.ChainID)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1 (no terminator due to timeout)", len(receipts))
	}
	if receipts[0].CredentialSubject.Chain.Terminal != nil {
		t.Error("receipt is marked terminal; expected no terminator due to timeout")
	}

	// Verifier must classify the chain as "unknown" since there is no terminal receipt.
	pubPEMBytes, err := os.ReadFile(cfg.PublicKeyPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	cv, err := st.VerifyStoredChain(cfg.ChainID, string(pubPEMBytes))
	if err != nil {
		t.Fatalf("VerifyStoredChain: %v", err)
	}
	if cv.Status != receipt.ChainStatusUnknown {
		t.Errorf("chain status = %q, want %q (no terminal receipt)", cv.Status, receipt.ChainStatusUnknown)
	}
}

// TestNoTerminatorOnAlreadyTerminatedChain verifies that when a daemon restarts
// on a chain whose tail is already terminal, it advances to a new chain ID
// rather than refusing to start, and no duplicate terminator is written to the
// original chain.
func TestNoTerminatorOnAlreadyTerminatedChain(t *testing.T) {
	sockDir := sockettest.ShortSocketDir(t)
	dataDir := t.TempDir()
	keyPath := filepath.Join(dataDir, "signing.key")
	pubPEM := writeTestKey(t, keyPath)

	const chainID = "already-term-chain"
	mkCfg := func() daemon.Config {
		return daemon.Config{
			SocketPath:           filepath.Join(sockDir, "events.sock"),
			UnsafeSocketPath:     true,
			DBPath:               filepath.Join(dataDir, "receipts.db"),
			KeyPath:              keyPath,
			PublicKeyPath:        keyPath + ".pub",
			ChainID:              chainID,
			IssuerID:             "did:agent-receipts-daemon:integration",
			VerificationMethodID: "did:agent-receipts-daemon:integration#k1",
			Logger:               log.New(io.Discard, "", 0),
		}
	}

	// First run: emit one receipt, then shut down to trigger interrupted terminator.
	cancel1, done1 := runInterruptDaemon(t, mkCfg())
	emitFrame(t, mkCfg().SocketPath, pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: "already-term-sess",
		Channel:   "sdk",
		Tool:      pipeline.EmitterTool{Name: "noop"},
		Decision:  "allowed",
	})
	_ = waitForReceiptCount(t, mkCfg().DBPath, chainID, 1, 5*time.Second)
	shutdownAndWait(t, cancel1, done1)

	// Verify the interrupted terminator was written (seq=2).
	st, err := store.Open(mkCfg().DBPath)
	if err != nil {
		t.Fatalf("open store after first run: %v", err)
	}
	receiptsAfterFirst, err := st.GetChain(chainID)
	st.Close()
	if err != nil {
		t.Fatalf("GetChain after first run: %v", err)
	}
	if len(receiptsAfterFirst) != 2 {
		t.Fatalf("after first run: got %d receipts, want 2", len(receiptsAfterFirst))
	}

	// Wait for socket to become unconnectable before second run.
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("unix", mkCfg().SocketPath, 100*time.Millisecond)
		if errors.Is(dialErr, syscall.ENOENT) || errors.Is(dialErr, syscall.ECONNREFUSED) {
			break
		}
		if dialErr == nil {
			conn.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("first daemon socket still listening — cannot start second run")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Second run with the same config: daemon auto-advances to "already-term-chain-2"
	// and starts successfully. No duplicate terminator may be written to the
	// original chain.
	advancedID := chainID + "-2"
	cancel2, done2 := runInterruptDaemon(t, mkCfg())

	emitFrame(t, mkCfg().SocketPath, pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: "already-term-sess-2",
		Channel:   "sdk",
		Tool:      pipeline.EmitterTool{Name: "noop"},
		Decision:  "allowed",
	})
	_ = waitForReceiptCount(t, mkCfg().DBPath, advancedID, 1, 5*time.Second)
	shutdownAndWait(t, cancel2, done2)

	// Original chain must still have exactly 2 receipts — no duplicate terminator.
	st, err = store.Open(mkCfg().DBPath)
	if err != nil {
		t.Fatalf("open store after second run: %v", err)
	}
	defer st.Close()

	receiptsAfterSecond, err := st.GetChain(chainID)
	if err != nil {
		t.Fatalf("GetChain after second run: %v", err)
	}
	if len(receiptsAfterSecond) != 2 {
		t.Fatalf("after second run: got %d receipts on original chain, want 2 (no duplicate terminator)", len(receiptsAfterSecond))
	}
	assertInterruptedTerminator(t, receiptsAfterSecond, pubPEM, chainID)
}

// TestDaemonAutoAdvancesTerminatedChain verifies that a daemon restarts cleanly
// after an interrupted shutdown by advancing to the next chain ID. The new chain
// is independent: receipts on it are valid and no receipt is appended to the
// terminated chain, preserving spec §7.3.2 (no receipt may follow a terminal).
func TestDaemonAutoAdvancesTerminatedChain(t *testing.T) {
	cfg, pubPEM := interruptDaemonCfg(t, "advance-chain")
	cancel1, done1 := runInterruptDaemon(t, cfg)

	emitFrame(t, cfg.SocketPath, pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: "advance-sess",
		Channel:   "sdk",
		Tool:      pipeline.EmitterTool{Name: "advance-tool"},
		Decision:  "allowed",
	})
	_ = waitForReceiptCount(t, cfg.DBPath, cfg.ChainID, 1, 5*time.Second)

	// Stop first daemon (writes interrupted terminator on "advance-chain").
	shutdownAndWait(t, cancel1, done1)

	// Wait for socket to become unconnectable before the second start.
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("unix", cfg.SocketPath, 100*time.Millisecond)
		if errors.Is(dialErr, syscall.ENOENT) || errors.Is(dialErr, syscall.ECONNREFUSED) {
			break
		}
		if dialErr == nil {
			conn.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("first daemon socket still listening — cannot start second daemon")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Second start with the same config: daemon advances to "advance-chain-2".
	cancel2, done2 := runInterruptDaemon(t, cfg)

	advancedID := cfg.ChainID + "-2"
	emitFrame(t, cfg.SocketPath, pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: "advance-sess-2",
		Channel:   "sdk",
		Tool:      pipeline.EmitterTool{Name: "advance-tool-2"},
		Decision:  "allowed",
	})
	_ = waitForReceiptCount(t, cfg.DBPath, advancedID, 1, 5*time.Second)
	shutdownAndWait(t, cancel2, done2)

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	// Original chain: exactly 2 receipts (1 receipt + interrupted terminator).
	origReceipts, err := st.GetChain(cfg.ChainID)
	if err != nil {
		t.Fatalf("GetChain original: %v", err)
	}
	if len(origReceipts) != 2 {
		t.Fatalf("original chain: got %d receipts, want 2", len(origReceipts))
	}
	assertInterruptedTerminator(t, origReceipts, pubPEM, cfg.ChainID)

	// Advanced chain: at least 1 receipt + its own interrupted terminator.
	advReceipts, err := st.GetChain(advancedID)
	if err != nil {
		t.Fatalf("GetChain advanced: %v", err)
	}
	if len(advReceipts) < 2 {
		t.Fatalf("advanced chain: got %d receipts, want at least 2", len(advReceipts))
	}
	assertInterruptedTerminator(t, advReceipts, pubPEM, advancedID)
}

// TestQuiescePropertyNoReceiptAfterTerminator confirms that the interrupted
// terminator is always the final receipt in the chain: no in-flight handler
// can append after it because the listener closes (and drains) before
// terminator emission.
func TestQuiescePropertyNoReceiptAfterTerminator(t *testing.T) {
	cfg, pubPEM := interruptDaemonCfg(t, "quiesce-chain")
	cancel, done := runInterruptDaemon(t, cfg)

	// Emit several receipts, then shut down.
	for i := 0; i < 3; i++ {
		emitFrame(t, cfg.SocketPath, pipeline.EmitterFrame{
			Version:   "1",
			TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
			SessionID: "quiesce-sess",
			Channel:   "sdk",
			Tool:      pipeline.EmitterTool{Name: "noop"},
			Decision:  "allowed",
		})
	}
	_ = waitForReceiptCount(t, cfg.DBPath, cfg.ChainID, 3, 5*time.Second)

	shutdownAndWait(t, cancel, done)

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	receipts, err := st.GetChain(cfg.ChainID)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}

	if len(receipts) < 4 {
		t.Fatalf("got %d receipts, want at least 4 (3 + terminator)", len(receipts))
	}

	// Terminator must be the very last receipt.
	last := receipts[len(receipts)-1]
	if last.CredentialSubject.Chain.Terminal == nil || !*last.CredentialSubject.Chain.Terminal {
		t.Error("last receipt is not terminal; interrupted terminator must be the final receipt")
	}
	if last.CredentialSubject.Chain.Status != receipt.ChainStatusInterrupted {
		t.Errorf("last receipt chain.status = %q, want %q", last.CredentialSubject.Chain.Status, receipt.ChainStatusInterrupted)
	}

	// No receipt may appear after the terminator in the chain.
	terminatorSeq := last.CredentialSubject.Chain.Sequence
	for _, r := range receipts {
		if r.CredentialSubject.Chain.Sequence > terminatorSeq {
			t.Errorf("found receipt at seq %d after terminator at seq %d — quiesce property violated",
				r.CredentialSubject.Chain.Sequence, terminatorSeq)
		}
	}

	assertInterruptedTerminator(t, receipts, pubPEM, cfg.ChainID)
	assertChainVerifiesInterrupted(t, st, cfg.ChainID, pubPEM)
}
