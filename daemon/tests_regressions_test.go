//go:build integration && (linux || darwin)

package daemon

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"obsigna.dev/sdk/go/emitter"
	"obsigna.dev/sdk/go/receipt"
)

// TestConcurrentDaemonStartSameSocket verifies that when two daemon instances
// race to bind the same socket path, exactly one wins and the other returns a
// clear error containing "another daemon is already listening". This is the
// regression test for the "bind: address already in use" bug documented in
// issue #236 comment 1, where the second instance would crash or leave the
// socket in an inconsistent state.
func TestConcurrentDaemonStartSameSocket(t *testing.T) {
	fix := StartDaemon(t)

	// Attempt to start a second daemon at the SAME socket path. Give it the
	// same key (read-only reuse is fine — the second daemon will fail before
	// it needs to sign anything) and a separate writable DB so the only point
	// of contention is the socket.
	//
	// The second daemon MUST return a graceful error (not hang, not panic, not
	// remove the first daemon's socket). The exact error message is a contract
	// the socket package promises: "another daemon is already listening on …".
	dataDir2 := t.TempDir()
	cfg2 := fix.Config
	cfg2.DBPath = dataDir2 + "/receipts2.db"
	cfg2.PublicKeyPath = dataDir2 + "/signing.key.pub"

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := make(chan error, 1)
	go func() { done2 <- Run(ctx2, cfg2) }()

	select {
	case err := <-done2:
		if err == nil {
			t.Fatal("second daemon started on an already-bound socket: expected error, got nil")
		}
		if !strings.Contains(err.Error(), "another daemon is already listening") {
			t.Errorf("unexpected error from second daemon: %v\n(want message containing 'another daemon is already listening')", err)
		}
	case <-time.After(5 * time.Second):
		cancel2()
		t.Fatal("second daemon did not exit within 5s; expected immediate error on duplicate socket bind")
	}

	// The first daemon must still be alive and serving.
	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(fix.Config.SocketPath),
		emitter.WithLogger(slog.Default()),
	)
	if err != nil {
		t.Fatalf("create emitter: %v", err)
	}
	defer em.Close()
	if err := em.Emit(context.Background(), emitter.Event{
		Channel:  "regression",
		Tool:     emitter.Tool{Name: "port-collision-test"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("first daemon no longer accepting after second daemon exit: %v", err)
	}
	fix.WaitForReceiptCount(t, 1, 5*time.Second)
}

// TestDropCounterEndToEnd verifies the full drop-counter pipeline: emitter
// drops accumulate while the daemon is down, the count is flushed on the first
// successful send after restart, and the daemon inserts a synthetic
// events_dropped receipt in the chain before the live receipt.
func TestDropCounterEndToEnd(t *testing.T) {
	fix1 := StartDaemon(t)
	pubPEM := fix1.PublicKey
	cfg := fix1.Config

	// Stop the first daemon without emitting anything. The emitter will be
	// created after stop so all initial sends hit a dead socket.
	fix1.cancel()
	select {
	case <-fix1.done:
		if fix1.daemonErr != nil {
			t.Logf("first daemon: %v", fix1.daemonErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first daemon did not stop within 3s")
	}

	// WithBestEffort so the dead-socket sends return nil and accumulate in the
	// drop counter rather than surfacing as errors (ADR-0025). The drop-counter
	// pipeline is exactly the loss-tolerant path this option selects.
	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(cfg.SocketPath),
		emitter.WithSessionID("drop-e2e-session"),
		emitter.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		emitter.WithBestEffort(),
	)
	if err != nil {
		t.Fatalf("emitter.NewDaemon: %v", err)
	}
	defer em.Close()

	ctx := context.Background()
	// Three emits to the dead socket → three dial failures → drop_count = 3.
	for i := 0; i < 3; i++ {
		if err := em.Emit(ctx, emitter.Event{Channel: "test", Tool: emitter.Tool{Name: "dropped"}, Decision: "allowed"}); err != nil {
			t.Fatalf("Emit %d: expected nil (WithBestEffort), got %v", i, err)
		}
	}

	// Restart the daemon at the same socket/DB/key.
	fix2 := StartDaemonFromConfig(t, cfg, pubPEM)

	// First successful send to fix2 flushes drop_count = 3.
	if err := em.Emit(ctx, emitter.Event{Channel: "test", Tool: emitter.Tool{Name: "live"}, Decision: "allowed"}); err != nil {
		t.Fatalf("live Emit: %v", err)
	}

	// Expect two receipts: synthetic events_dropped (seq 1) + live (seq 2).
	receipts := fix2.WaitForReceiptCount(t, 2, 10*time.Second)
	if len(receipts) != 2 {
		t.Fatalf("got %d receipts, want 2 (events_dropped + live)\ntrace:\n%s", len(receipts), fix2.Trace())
	}

	synthetic := receipts[0]
	live := receipts[1]

	if synthetic.CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("synthetic seq = %d, want 1", synthetic.CredentialSubject.Chain.Sequence)
	}
	if got := synthetic.CredentialSubject.Action.Type; got != "agent_receipts.events_dropped" {
		t.Errorf("synthetic action.type = %q, want agent_receipts.events_dropped", got)
	}
	meta := synthetic.CredentialSubject.Action.EmitterMetadata
	if meta == nil {
		t.Fatal("synthetic events_dropped receipt missing emitter_metadata")
	}
	if meta.DropCount != 3 {
		t.Errorf("synthetic emitter_metadata.drop_count = %d, want 3", meta.DropCount)
	}
	if got := synthetic.Issuer.SessionID; got != "drop-e2e-session" {
		t.Errorf("synthetic session_id = %q, want drop-e2e-session", got)
	}

	if live.CredentialSubject.Chain.Sequence != 2 {
		t.Errorf("live seq = %d, want 2", live.CredentialSubject.Chain.Sequence)
	}
	if got := live.CredentialSubject.Action.Type; got != "test.live" {
		t.Errorf("live action.type = %q, want test.live", got)
	}

	// Verify prev_hash link: live must point to synthetic.
	wantPrev, err := receipt.HashReceipt(synthetic)
	if err != nil {
		t.Fatalf("hash synthetic: %v", err)
	}
	if live.CredentialSubject.Chain.PreviousReceiptHash == nil || *live.CredentialSubject.Chain.PreviousReceiptHash != wantPrev {
		t.Errorf("live prev_hash = %v, want %s", live.CredentialSubject.Chain.PreviousReceiptHash, wantPrev)
	}

	// Both receipts must verify under the daemon's public key.
	for i, r := range receipts {
		ok, err := receipt.Verify(r, pubPEM)
		if err != nil || !ok {
			t.Errorf("receipt[%d]: verify ok=%v err=%v", i, ok, err)
		}
	}
}

// TestEmitterRequiresOnlySocketPath verifies that the emitter succeeds even
// when every default filesystem path the old in-process emitter would have
// used (HOME, XDG_DATA_HOME, XDG_RUNTIME_DIR, TMPDIR) is read-only. This is
// the ADR-0010 regression guard: if someone accidentally re-introduces DB or
// key access into the emitter, those opens would return EACCES and surface as
// an Emit error here.
func TestEmitterRequiresOnlySocketPath(t *testing.T) {
	fix := StartDaemon(t)

	// Create a read-only sandbox directory and redirect all default path
	// env vars into it. Any emitter code that tries os.Create/os.OpenFile
	// under HOME, XDG_DATA_HOME, XDG_RUNTIME_DIR, or TMPDIR will get EACCES.
	sandboxHome := t.TempDir()
	if err := os.Chmod(sandboxHome, 0o555); err != nil {
		t.Fatalf("chmod sandboxHome: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(sandboxHome, 0o755) })
	t.Setenv("HOME", sandboxHome)
	t.Setenv("XDG_DATA_HOME", filepath.Join(sandboxHome, ".local", "share"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(sandboxHome, "run"))
	t.Setenv("TMPDIR", filepath.Join(sandboxHome, "tmp")) // pre-#545 macOS socket base; still covered here in case anything else reads TMPDIR

	// The daemon was started before the env vars were redirected and uses
	// paths from its Config struct, so it is unaffected.

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(fix.Config.SocketPath),
		emitter.WithSessionID("socket-only-session"),
		emitter.WithLogger(slog.Default()),
	)
	if err != nil {
		t.Fatalf("emitter.NewDaemon: %v", err)
	}
	defer em.Close()

	if err := em.Emit(context.Background(), emitter.Event{
		Channel:  "test",
		Tool:     emitter.Tool{Name: "socket-only-tool"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("Emit in read-only-HOME sandbox: %v", err)
	}

	receipts := fix.WaitForReceiptCount(t, 1, 5*time.Second)
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1", len(receipts))
	}
	r := receipts[0]
	if r.CredentialSubject.Action.Type != "test.socket-only-tool" {
		t.Errorf("action.type = %q, want test.socket-only-tool", r.CredentialSubject.Action.Type)
	}
	if r.Issuer.SessionID != "socket-only-session" {
		t.Errorf("issuer.session_id = %q, want socket-only-session", r.Issuer.SessionID)
	}
}
