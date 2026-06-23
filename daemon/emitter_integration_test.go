//go:build integration && (linux || darwin)

// End-to-end tests of the Go SDK emitter against an in-process daemon.
//
// These live in the daemon module — not in sdk/go — because the SDK is the
// lower layer: the daemon requires sdk/go, so an emitter↔daemon test belongs
// on the daemon side where importing both is the natural dependency direction.
// Keeping it here means sdk/go's published module graph never references
// obsigna.dev/daemon, so `go mod tidy` against the published SDK stays clean
// (ADR-0037). The daemon module already hosts the other emitter integration
// tests and shares their helpers (startEmitterDaemon, writeTestKey,
// waitForReceiptCount, sockettest.ShortSocketDir).
//
// Build-tag-gated to:
//   - integration: boots a real daemon; daemon CI runs `go test -tags=integration`.
//   - linux/darwin: the emitter speaks AF_UNIX and the daemon refuses to start
//     on other platforms — running these on a Windows builder would fail at
//     daemon.Run, not at the emitter we want to exercise.
package daemon_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"obsigna.dev/daemon"
	"obsigna.dev/daemon/internal/sockettest"
	"obsigna.dev/sdk/go/emitter"
	"obsigna.dev/sdk/go/receipt"
	"obsigna.dev/sdk/go/store"
)

type emitterDaemonHandle struct {
	cfg      daemon.Config
	cancel   context.CancelFunc
	done     <-chan error
	stopOnce sync.Once
	stopErr  error
}

func startEmitterDaemon(t *testing.T, dir string) *emitterDaemonHandle {
	t.Helper()
	cfg := daemon.Config{
		SocketPath: filepath.Join(dir, "events.sock"),
		// The temp dir lives under /tmp to stay within the 104-byte AF_UNIX
		// sun_path limit on macOS — outside the daemon's per-platform safe
		// set, so opt into the documented escape hatch (issue #538).
		UnsafeSocketPath:     true,
		DBPath:               filepath.Join(dir, "receipts.db"),
		KeyPath:              filepath.Join(dir, "signing.key"),
		PublicKeyPath:        filepath.Join(dir, "signing.key.pub"),
		ChainID:              "emitter-test-chain",
		IssuerID:             "did:agent-receipts-daemon:emitter-test",
		VerificationMethodID: "did:agent-receipts-daemon:emitter-test#k1",
		Logger:               log.New(io.Discard, "", 0),
		ShutdownDeadline:     time.Nanosecond, // crash mode: no terminator on shutdown, so d2 can resume the same chain
	}
	if _, err := os.Stat(cfg.KeyPath); os.IsNotExist(err) {
		writeTestKey(t, cfg.KeyPath)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx, cfg) }()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("daemon exited before socket appeared: %v", err)
		case <-timeout.C:
			cancel()
			t.Fatalf("socket %s did not appear within 2s", cfg.SocketPath)
		case <-ticker.C:
			// poll again
		}
	}

	d := &emitterDaemonHandle{cfg: cfg, cancel: cancel, done: done}
	t.Cleanup(func() { d.stop(t) })
	return d
}

// stop shuts the daemon down deterministically and waits for Run to return.
// Idempotent via sync.Once so tests that explicitly stop a daemon mid-test
// (TestEmit_ReconnectAfterDaemonRestart) do not race the t.Cleanup
// registered by startEmitterDaemon — both paths converge on a single shutdown.
func (d *emitterDaemonHandle) stop(t *testing.T) {
	t.Helper()
	d.stopOnce.Do(func() {
		d.cancel()
		select {
		case err := <-d.done:
			if err != nil {
				t.Logf("daemon Run returned: %v", err)
			}
		case <-time.After(3 * time.Second):
			d.stopErr = errors.New("daemon did not shut down within 3s")
		}
		// Confirm the socket is no longer accepting connections; a
		// "reconnect" test that ran against a still-listening socket
		// would silently pass without exercising the reconnect path.
		if conn, err := net.Dial("unix", d.cfg.SocketPath); err == nil {
			conn.Close()
			d.stopErr = errors.New("socket still accepting connections after stop")
		}
	})
	if d.stopErr != nil {
		t.Fatal(d.stopErr)
	}
}

// silentLogger discards every log line so the fire-and-forget drop logs
// do not pollute test output. Shared across tests rather than reallocated
// per-call — the handler has no per-test state.
var silentLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// TestEmit_FrameRoundTrip is the basic acceptance test: three events fired
// through the emitter materialise as three signed receipts in the daemon's
// chain, with monotonic sequence and the channel/tool/decision values the
// emitter sent.
func TestEmit_FrameRoundTrip(t *testing.T) {
	d := startEmitterDaemon(t, sockettest.ShortSocketDir(t))

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(d.cfg.SocketPath),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = em.Close() })

	events := []emitter.Event{
		{Channel: "sdk", Tool: emitter.Tool{Server: "fixture", Name: "alpha"}, Decision: "allowed"},
		{Channel: "sdk", Tool: emitter.Tool{Server: "fixture", Name: "beta"}, Decision: "denied"},
		{Channel: "sdk", Tool: emitter.Tool{Name: "gamma"}, Decision: "pending"},
	}
	ctx := context.Background()
	for i, ev := range events {
		if err := em.Emit(ctx, ev); err != nil {
			t.Fatalf("Emit[%d]: %v", i, err)
		}
	}

	receipts := waitForReceiptCount(t, d.cfg.DBPath, d.cfg.ChainID, len(events), 5*time.Second)
	if len(receipts) != len(events) {
		t.Fatalf("got %d receipts, want %d", len(receipts), len(events))
	}

	wantTypes := []string{"sdk.fixture.alpha", "sdk.fixture.beta", "sdk.gamma"}
	wantStatus := []receipt.OutcomeStatus{receipt.StatusSuccess, receipt.StatusFailure, receipt.StatusPending}
	for i, r := range receipts {
		if r.CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("receipt %d: seq = %d, want %d", i, r.CredentialSubject.Chain.Sequence, i+1)
		}
		if r.CredentialSubject.Action.Type != wantTypes[i] {
			t.Errorf("receipt %d: action.type = %q, want %q", i, r.CredentialSubject.Action.Type, wantTypes[i])
		}
		if r.CredentialSubject.Action.ToolName != events[i].Tool.Name {
			t.Errorf("receipt %d: action.tool_name = %q, want %q", i, r.CredentialSubject.Action.ToolName, events[i].Tool.Name)
		}
		if r.CredentialSubject.Outcome.Status != wantStatus[i] {
			t.Errorf("receipt %d: outcome.status = %q, want %q", i, r.CredentialSubject.Outcome.Status, wantStatus[i])
		}
	}
}

// TestEmit_SessionIDStableAcrossEmits pins the OQ4 (ADR-0010, 2026-05-06)
// rule: session_id is allocated once at New() and reused across every Emit
// from the same emitter instance, never per-call. A regression that
// generated a fresh UUID per emit would fragment a logical agent session
// into N receipts with N session_ids.
func TestEmit_SessionIDStableAcrossEmits(t *testing.T) {
	d := startEmitterDaemon(t, sockettest.ShortSocketDir(t))

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(d.cfg.SocketPath),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = em.Close() })

	wantSession := em.SessionID()
	if wantSession == "" {
		t.Fatal("emitter SessionID is empty; New() should generate a UUID v4")
	}

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := em.Emit(ctx, emitter.Event{
			Channel:  "sdk",
			Tool:     emitter.Tool{Name: "noop"},
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("Emit[%d]: %v", i, err)
		}
	}

	receipts := waitForReceiptCount(t, d.cfg.DBPath, d.cfg.ChainID, 3, 5*time.Second)
	for i, r := range receipts {
		if r.Issuer.SessionID != wantSession {
			t.Errorf("receipt %d: Issuer.SessionID = %q, want %q", i, r.Issuer.SessionID, wantSession)
		}
	}
}

// TestEmit_HashDeterminism guards that the emitter forwards Input bytes
// faithfully — without re-encoding — so that the daemon's RFC 8785
// canonicalisation is what actually determines parameters_hash. Two events
// whose Input is logically identical but differs in whitespace and key
// order MUST produce identical Action.ParametersHash. If the emitter ever
// starts re-marshalling Input, one of the two payloads would canonicalise
// to a different byte stream than the other, breaking this property.
func TestEmit_HashDeterminism(t *testing.T) {
	d := startEmitterDaemon(t, sockettest.ShortSocketDir(t))

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(d.cfg.SocketPath),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = em.Close() })

	// Same logical {a:1, b:2} payload, different key order, different
	// whitespace. RFC 8785 ignores both, so parameters_hash MUST match.
	inputs := []json.RawMessage{
		json.RawMessage(`{"a":1,"b":2}`),
		json.RawMessage(`{ "b":  2 , "a" : 1 }`),
	}
	ctx := context.Background()
	for i, in := range inputs {
		if err := em.Emit(ctx, emitter.Event{
			Channel:  "sdk",
			Tool:     emitter.Tool{Name: "hash-fixture"},
			Input:    in,
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("Emit[%d]: %v", i, err)
		}
	}

	receipts := waitForReceiptCount(t, d.cfg.DBPath, d.cfg.ChainID, len(inputs), 5*time.Second)
	if h0, h1 := receipts[0].CredentialSubject.Action.ParametersHash, receipts[1].CredentialSubject.Action.ParametersHash; h0 == "" || h1 == "" || h0 != h1 {
		t.Errorf("parameters_hash mismatch: receipt[0]=%q receipt[1]=%q (both must be non-empty and equal)", h0, h1)
	}
}

// TestEmit_BestEffortWhenDaemonDown enforces the non-blocking property under
// the WithBestEffort opt-out (ADR-0025): an unreachable daemon MUST NOT block
// the agent, and Emit returns nil within milliseconds when the configured
// socket path does not exist on disk. (The default surface-error behaviour is
// covered by the unit tests in emitter_unix_test.go.)
func TestEmit_BestEffortWhenDaemonDown(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	socketPath := filepath.Join(dir, "no-such-daemon.sock")

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(socketPath),
		emitter.WithLogger(silentLogger),
		emitter.WithBestEffort(),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = em.Close() })

	ctx := context.Background()
	start := time.Now()
	err = em.Emit(ctx, emitter.Event{
		Channel:  "sdk",
		Tool:     emitter.Tool{Name: "noop"},
		Decision: "allowed",
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Emit returned err = %v, want nil (WithBestEffort)", err)
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("Emit blocked for %v, want <50ms (non-blocking contract)", elapsed)
	}
}

// TestEmit_ReconnectAfterDaemonRestart proves the emitter survives a daemon
// outage: connection drops, daemon comes back, the next Emit (or one of
// the next few — ADR-0010 lets the emitter discover the broken conn at
// write time and re-dial on the following Emit) succeeds with the same
// session_id the emitter started with. Without lazy re-dial after a write
// failure, every post-restart Emit would silently drop forever.
func TestEmit_ReconnectAfterDaemonRestart(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	d1 := startEmitterDaemon(t, dir)

	// WithBestEffort so the stale-connection write failure on the first
	// post-restart Emit returns nil and the reconnect loop keeps going
	// (ADR-0025); success is detected via the receipt store, not the return
	// value.
	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(d1.cfg.SocketPath),
		emitter.WithLogger(silentLogger),
		emitter.WithBestEffort(),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = em.Close() })

	wantSession := em.SessionID()
	ctx := context.Background()

	// Round 1: two events while the first daemon is up.
	for i := 0; i < 2; i++ {
		if err := em.Emit(ctx, emitter.Event{
			Channel:  "sdk",
			Tool:     emitter.Tool{Name: "before-restart"},
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("pre-restart Emit[%d]: %v", i, err)
		}
	}
	_ = waitForReceiptCount(t, d1.cfg.DBPath, d1.cfg.ChainID, 2, 5*time.Second)

	// Stop daemon 1, then start daemon 2 against the same DB / socket
	// path. The second daemon resumes the existing chain (ADR-0010 OQ2:
	// the daemon resumes from GetChainTail).
	d1.stop(t)
	d2 := startEmitterDaemon(t, dir)

	// Loop until reconnect lands a receipt. The emitter holds a stale
	// connection from daemon 1; the first Emit may fail at write time,
	// after which the conn is closed and the next Emit redials. Tolerating
	// a few attempts covers both orderings (immediate write failure
	// vs. delayed broken-pipe detection) without a hard-coded retry count.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := em.Emit(ctx, emitter.Event{
			Channel:  "sdk",
			Tool:     emitter.Tool{Name: "after-restart"},
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("post-restart Emit: %v", err)
		}
		s, openErr := store.OpenReadOnly(d2.cfg.DBPath)
		if openErr != nil {
			t.Fatalf("open store: %v", openErr)
		}
		receipts, getErr := s.GetChain(d2.cfg.ChainID)
		s.Close()
		if getErr == nil && len(receipts) >= 3 {
			// Filter out daemon-synthesised receipts. d1 uses crash mode
			// (ShutdownDeadline=1ns) so chain_interrupted never actually
			// appears here; the filter is defensive for events_dropped.
			var live []receipt.AgentReceipt
			for _, r := range receipts[2:] {
				if r.CredentialSubject.Action.Type != "agent_receipts.events_dropped" &&
					r.CredentialSubject.Action.Type != "agent_receipts.chain_interrupted" {
					live = append(live, r)
				}
			}
			if len(live) == 0 {
				// Only the synthetic receipt has arrived yet; wait for the live one.
				time.Sleep(50 * time.Millisecond)
				continue
			}
			// Verify post-restart receipts carry the emitter's stable
			// session_id (OQ4 property: persists across daemon reconnects).
			for _, r := range live {
				if r.Issuer.SessionID != wantSession {
					t.Errorf("post-restart receipt session_id = %q, want %q", r.Issuer.SessionID, wantSession)
				}
				if r.CredentialSubject.Action.ToolName != "after-restart" {
					t.Errorf("post-restart receipt tool_name = %q, want %q", r.CredentialSubject.Action.ToolName, "after-restart")
				}
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("emitter did not reconnect to the restarted daemon within 5s")
}

// TestEmit_ReturnsErrorAfterClose pins the contract that Close finalises
// the emitter: subsequent Emit calls return a clear error rather than
// silently dropping. A silent post-Close drop would mask use-after-close
// bugs in the caller (e.g. a deferred Emit firing after Close).
func TestEmit_ReturnsErrorAfterClose(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	d := startEmitterDaemon(t, dir)

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(d.cfg.SocketPath),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := em.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Second Close is a no-op — Close is idempotent.
	if err := em.Close(); err != nil {
		t.Errorf("second Close returned %v, want nil", err)
	}

	err = em.Emit(context.Background(), emitter.Event{
		Channel: "sdk", Tool: emitter.Tool{Name: "noop"}, Decision: "allowed",
	})
	if err == nil {
		t.Error("Emit after Close returned nil, want error")
	}
}

// TestEmit_ValidatesEvent checks that Emit returns an error immediately for
// events the daemon would hard-reject, before any dial attempt. These are
// caller bugs, not transient failures, so they must not be silently dropped.
func TestEmit_ValidatesEvent(t *testing.T) {
	em, err := emitter.NewDaemon(
		emitter.WithSocketPath("/nonexistent/events.sock"),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	ctx := context.Background()
	cases := []struct {
		name string
		ev   emitter.Event
	}{
		{
			"missing channel",
			emitter.Event{Tool: emitter.Tool{Name: "noop"}, Decision: "allowed"},
		},
		{
			"missing tool.name",
			emitter.Event{Channel: "sdk", Decision: "allowed"},
		},
		{
			"empty decision",
			emitter.Event{Channel: "sdk", Tool: emitter.Tool{Name: "noop"}},
		},
		{
			"unknown decision",
			emitter.Event{Channel: "sdk", Tool: emitter.Tool{Name: "noop"}, Decision: "maybe"},
		},
		{
			"invalid Input JSON",
			emitter.Event{Channel: "sdk", Tool: emitter.Tool{Name: "noop"}, Decision: "allowed", Input: json.RawMessage(`{bad}`)},
		},
		{
			"invalid Output JSON",
			emitter.Event{Channel: "sdk", Tool: emitter.Tool{Name: "noop"}, Decision: "allowed", Output: json.RawMessage(`[unclosed`)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := em.Emit(ctx, tc.ev); err == nil {
				t.Error("Emit returned nil, want error")
			}
		})
	}
}

// TestEmit_RejectsHalfPopulatedTarget pins the XOR validation: Target.System
// and Target.Resource must both be set or both empty. A half-populated Target
// produces a malformed ActionTarget in the receipt; the emitter catches it
// before the write so it is a caller error, not a transport failure.
func TestEmit_RejectsHalfPopulatedTarget(t *testing.T) {
	em, err := emitter.NewDaemon(
		emitter.WithSocketPath("/nonexistent/events.sock"),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	ctx := context.Background()
	base := emitter.Event{Channel: "claude-code", Tool: emitter.Tool{Name: "Read"}, Decision: "allowed"}

	t.Run("system without resource", func(t *testing.T) {
		ev := base
		ev.Target = emitter.Target{System: "filesystem"}
		if err := em.Emit(ctx, ev); err == nil {
			t.Error("Emit returned nil for system-only target; want error")
		}
	})
	t.Run("resource without system", func(t *testing.T) {
		ev := base
		ev.Target = emitter.Target{Resource: "/etc/hosts"}
		if err := em.Emit(ctx, ev); err == nil {
			t.Error("Emit returned nil for resource-only target; want error")
		}
	})
}

// TestEmit_RejectsOversizeTargetFields mirrors the daemon's per-field length
// caps client-side: an oversized Target.System or Target.Resource must be
// caught at Emit rather than silently dropped after a daemon-side rejection.
func TestEmit_RejectsOversizeTargetFields(t *testing.T) {
	em, err := emitter.NewDaemon(
		emitter.WithSocketPath("/nonexistent/events.sock"),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	ctx := context.Background()
	base := emitter.Event{Channel: "claude-code", Tool: emitter.Tool{Name: "Read"}, Decision: "allowed"}

	t.Run("oversize target_system", func(t *testing.T) {
		ev := base
		ev.Target = emitter.Target{
			System:   strings.Repeat("x", emitter.MaxIdentityFieldLen+1),
			Resource: "/etc/hosts",
		}
		if err := em.Emit(ctx, ev); err == nil {
			t.Error("Emit returned nil for oversize target_system; want error")
		}
	})
	t.Run("oversize target_resource", func(t *testing.T) {
		ev := base
		ev.Target = emitter.Target{
			System:   "filesystem",
			Resource: strings.Repeat("x", emitter.MaxTargetResourceLen+1),
		}
		if err := em.Emit(ctx, ev); err == nil {
			t.Error("Emit returned nil for oversize target_resource; want error")
		}
	})
}

// TestEmit_WithSessionIDOverride pins the OQ4 host-id forwarding path:
// when WithSessionID supplies a non-empty value, every receipt carries
// that exact id rather than a freshly generated UUID. Mirrors the
// integration scenario where a host (Claude Code, an agent loop) owns
// the session identifier and the emitter must propagate it untouched.
func TestEmit_WithSessionIDOverride(t *testing.T) {
	d := startEmitterDaemon(t, sockettest.ShortSocketDir(t))

	const hostSession = "host-supplied-session-9f3a"
	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(d.cfg.SocketPath),
		emitter.WithSessionID(hostSession),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = em.Close() })

	if got := em.SessionID(); got != hostSession {
		t.Fatalf("SessionID() = %q, want %q", got, hostSession)
	}

	if err := em.Emit(context.Background(), emitter.Event{
		Channel: "sdk", Tool: emitter.Tool{Name: "noop"}, Decision: "allowed",
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	receipts := waitForReceiptCount(t, d.cfg.DBPath, d.cfg.ChainID, 1, 5*time.Second)
	if got := receipts[0].Issuer.SessionID; got != hostSession {
		t.Errorf("Issuer.SessionID = %q, want %q", got, hostSession)
	}
}
