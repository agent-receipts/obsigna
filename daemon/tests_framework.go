//go:build integration && (linux || darwin)

// Framework for Phase 1 integration tests exercising the daemon with
// multi-SDK emitters. Provides daemon startup fixtures, receipt polling,
// and concurrent emitter orchestration.
package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/sockettest"
	"github.com/agent-receipts/ar/sdk/go/emitter"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// syncBuffer wraps bytes.Buffer with a mutex so daemon goroutines can write
// while the test goroutine reads via Trace(). The Pipeline-side traceMu
// already serialises concurrent daemon writes, but the test's read is on a
// separate goroutine and would race the writer without its own lock.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// DaemonFixture holds a running daemon instance and its configuration.
//
// daemonErr is written before done is closed (one writer goroutine), so any
// reader observing a closed done can read daemonErr without further
// synchronisation.
type DaemonFixture struct {
	Config     Config
	PublicKey  string // PEM-encoded public key
	cancel     func()
	done       chan struct{} // closed when daemon Run returns
	daemonErr  error         // result of Run; read only after done is closed
	traceBuf   *syncBuffer
	repoRoot   string
	emitTSPath string
	emitPyPath string
}

// StartDaemon starts a test daemon with a graceful shutdown deadline and
// returns a fixture with cleanup. The fixture will be cleaned up automatically
// via t.Cleanup.
func StartDaemon(t *testing.T) *DaemonFixture {
	t.Helper()
	return startDaemonFixture(t, 0)
}

// StartDaemonCrash starts a daemon that will not emit a terminal receipt on
// shutdown — the 1 ns ShutdownDeadline expires before EmitTerminator can
// write, leaving the chain open for resumption. Use this when testing chain
// resumption after an unclean shutdown / crash.
func StartDaemonCrash(t *testing.T) *DaemonFixture {
	t.Helper()
	return startDaemonFixture(t, time.Nanosecond)
}

// newDaemonConfig builds a fresh daemon Config with its own temp directories
// and a generated signing key, returning the config and the PEM-encoded public
// key. The daemon is NOT started: the socket path is absent until something
// binds it, so callers can either pass the config to StartDaemonFromConfig or
// drive the unbound socket path directly (e.g. to exercise an emitter's
// connect-failure path before the daemon comes up). TraceLog is deliberately
// left unset — each starter installs its own trace buffer.
//
// shutdownDeadline is passed directly to Config; 0 uses the daemon's built-in
// default (200 ms), 1 ns simulates a crash.
func newDaemonConfig(t *testing.T, shutdownDeadline time.Duration) (Config, string) {
	t.Helper()

	sockDir := sockettest.ShortSocketDir(t)
	dataDir := t.TempDir()

	cfg := Config{
		SocketPath: filepath.Join(sockDir, "events.sock"),
		DBPath:     filepath.Join(dataDir, "receipts.db"),
		KeyPath:    filepath.Join(dataDir, "signing.key"),
		// ShortSocketDir lives under /tmp to stay within the 104-byte
		// AF_UNIX sun_path limit on macOS — outside the per-platform safe
		// set, so opt into the documented escape hatch (issue #538).
		UnsafeSocketPath:     true,
		PublicKeyPath:        filepath.Join(dataDir, "signing.key.pub"),
		ChainID:              "test-chain",
		IssuerID:             "did:agent-receipts-daemon:test",
		VerificationMethodID: "did:agent-receipts-daemon:test#k1",
		Logger:               log.New(io.Discard, "", 0),
		ShutdownDeadline:     shutdownDeadline,
	}

	// Generate test key
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(cfg.KeyPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	pub := priv.Public().(ed25519.PublicKey)
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	return cfg, pubPEM
}

// startDaemonFixture creates a fresh daemon with its own temp directories and
// a generated signing key. shutdownDeadline is passed directly to Config; 0
// uses the daemon's built-in default (200 ms), 1 ns simulates a crash.
func startDaemonFixture(t *testing.T, shutdownDeadline time.Duration) *DaemonFixture {
	t.Helper()

	cfg, pubPEM := newDaemonConfig(t, shutdownDeadline)

	// Set up trace log for debugging
	traceBuf := &syncBuffer{}
	cfg.TraceLog = traceBuf

	// Resolve paths needed by emitter helpers (before goroutines use them)
	repoRoot := findSDKRoot(t)
	emitTSPath := findHelperScript(t, "emit_ts.mjs")
	emitPyPath := findHelperScript(t, "emit_py.py")

	// Start daemon
	ctx, cancel := context.WithCancel(context.Background())
	fix := &DaemonFixture{
		Config:     cfg,
		PublicKey:  pubPEM,
		cancel:     cancel,
		done:       make(chan struct{}),
		traceBuf:   traceBuf,
		repoRoot:   repoRoot,
		emitTSPath: emitTSPath,
		emitPyPath: emitPyPath,
	}
	go func() {
		fix.daemonErr = Run(ctx, cfg)
		close(fix.done)
	}()

	// Wait for socket to be ready (active listener, not just file presence)
	deadline := time.Now().Add(2 * time.Second)
	for {
		// Check if daemon exited early before trying to connect
		select {
		case <-fix.done:
			t.Fatalf("daemon exited early: %v\ntrace:\n%s", fix.daemonErr, fix.Trace())
		default:
		}

		conn, err := net.DialTimeout("unix", cfg.SocketPath, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("daemon socket %s did not become ready within 2s", cfg.SocketPath)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Cleanup on test end
	t.Cleanup(func() {
		cancel()
		select {
		case <-fix.done:
			if fix.daemonErr != nil {
				t.Logf("daemon Run returned: %v", fix.daemonErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("daemon did not shut down within 3s")
		}
	})

	return fix
}

// StartDaemonFromConfig starts a daemon with an existing config (e.g., for restart tests).
// Unlike StartDaemon, this reuses the same DB/key/socket paths instead of generating new ones,
// allowing a second daemon to resume the same chain from where the first left off.
func StartDaemonFromConfig(t *testing.T, cfg Config, pubPEM string) *DaemonFixture {
	t.Helper()

	// Reuse the provided config directly; paths and key have been pre-established.
	traceBuf := &syncBuffer{}
	cfg.TraceLog = traceBuf

	// Resolve paths needed by emitter helpers
	repoRoot := findSDKRoot(t)
	emitTSPath := findHelperScript(t, "emit_ts.mjs")
	emitPyPath := findHelperScript(t, "emit_py.py")

	ctx, cancel := context.WithCancel(context.Background())
	fix := &DaemonFixture{
		Config:     cfg,
		PublicKey:  pubPEM,
		cancel:     cancel,
		done:       make(chan struct{}),
		traceBuf:   traceBuf,
		repoRoot:   repoRoot,
		emitTSPath: emitTSPath,
		emitPyPath: emitPyPath,
	}
	go func() {
		fix.daemonErr = Run(ctx, cfg)
		close(fix.done)
	}()

	// Wait for socket to be ready (active listener, not just file presence)
	deadline := time.Now().Add(2 * time.Second)
	for {
		// Check if daemon exited early before trying to connect
		select {
		case <-fix.done:
			t.Fatalf("daemon exited early: %v\ntrace:\n%s", fix.daemonErr, fix.Trace())
		default:
		}

		conn, err := net.DialTimeout("unix", cfg.SocketPath, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("daemon socket %s did not become ready within 2s", cfg.SocketPath)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Cleanup on test end
	t.Cleanup(func() {
		cancel()
		select {
		case <-fix.done:
			if fix.daemonErr != nil {
				t.Logf("daemon Run returned: %v", fix.daemonErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("daemon did not shut down within 3s")
		}
	})

	return fix
}

// EmitGoFrame emits a frame using the Go SDK's emitter.
// Returns an error if the operation fails, allowing safe use from goroutines.
//
// Emit surfaces dial/write failures as errors by default (ADR-0025), so
// transient failures show up as test errors instead of silent drops — tests
// rely on at-least-once delivery. A single retry on dial failure absorbs the
// macOS-under-race case where the 25ms dial budget occasionally exceeds the
// runner's scheduler latency.
func (f *DaemonFixture) EmitGoFrame(t *testing.T, sessionID, channel string, toolName, toolServer, decision string) error {
	t.Helper()

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(f.Config.SocketPath),
		emitter.WithSessionID(sessionID),
		emitter.WithLogger(slog.Default()),
	)
	if err != nil {
		return fmt.Errorf("create emitter: %w", err)
	}
	defer em.Close()

	ev := emitter.Event{
		Channel: channel,
		Tool: emitter.Tool{
			Name:   toolName,
			Server: toolServer,
		},
		Decision: decision,
	}
	if err := em.Emit(context.Background(), ev); err == nil {
		return nil
	} else if !isTransientDialErr(err) {
		return err
	}
	// One retry — the dial timeout is 25ms and macOS CI runners under -race
	// occasionally need more. The daemon is alive (test framework waits for
	// it before calling us), so a retry pretty much always succeeds.
	time.Sleep(50 * time.Millisecond)
	return em.Emit(context.Background(), ev)
}

// isTransientDialErr classifies emitter errors that are worth retrying.
// The strict-errors mode wraps dial errors as "emitter: dial <path>: ...".
func isTransientDialErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "emitter: dial") ||
		strings.Contains(msg, "emitter: write")
}

// EmitGoFrameFull emits a frame using the Go SDK with full Event fields (Input, Output, Error).
// Returns an error if the operation fails, allowing safe use from goroutines.
func (f *DaemonFixture) EmitGoFrameFull(t *testing.T, sessionID string, event emitter.Event) error {
	t.Helper()

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(f.Config.SocketPath),
		emitter.WithSessionID(sessionID),
		emitter.WithLogger(slog.Default()),
	)
	if err != nil {
		return fmt.Errorf("create emitter: %w", err)
	}
	defer em.Close()

	err = em.Emit(context.Background(), event)
	return err
}

// EmitTSFrame spawns a Node.js subprocess to emit a frame via the TS SDK.
// Returns an error if the operation fails, allowing safe use from goroutines.
func (f *DaemonFixture) EmitTSFrame(t *testing.T, sessionID, channel string, toolName string, decision string) error {
	t.Helper()

	cmd := exec.Command("node", f.emitTSPath, f.Config.SocketPath, sessionID, channel, toolName, decision)
	cmd.Dir = f.repoRoot

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("TS emitter exited non-zero: %w\noutput:\n%s", err, out)
	}
	return nil
}

// EmitPythonFrame spawns a Python subprocess to emit a frame via the Python SDK.
// Uses uv run to manage dependencies in the sdk/py directory.
// Returns an error if the operation fails, allowing safe use from goroutines.
func (f *DaemonFixture) EmitPythonFrame(t *testing.T, sessionID, channel string, toolName string, decision string) error {
	t.Helper()

	// Use uv run from the sdk/py directory (where pyproject.toml is)
	cmd := exec.Command("uv", "run", "--", "python", f.emitPyPath, f.Config.SocketPath, sessionID, channel, toolName, decision)
	cmd.Dir = filepath.Join(f.repoRoot, "sdk", "py")

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Python emitter exited non-zero: %w\noutput:\n%s", err, out)
	}
	return nil
}

// WaitForReceiptCount polls the store until at least `count` receipts exist
// or the timeout is exceeded. Surfaces early daemon exit instead of silently
// timing out — without this, a daemon that crashes mid-test would just look
// like a slow test.
func (f *DaemonFixture) WaitForReceiptCount(t *testing.T, count int, timeout time.Duration) []receipt.AgentReceipt {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		// Detect daemon early exit before another store poll. f.done only
		// closes when Run returns; during the test that means the daemon
		// crashed (cleanup hasn't called cancel yet).
		select {
		case <-f.done:
			t.Fatalf("daemon exited early: %v\ntrace:\n%s", f.daemonErr, f.Trace())
		default:
		}

		s, err := store.OpenReadOnly(f.Config.DBPath)
		if err != nil {
			t.Fatalf("open store: %v\ntrace:\n%s", err, f.Trace())
		}
		got, err := s.GetChain(f.Config.ChainID)
		if closeErr := s.Close(); closeErr != nil {
			t.Logf("close store: %v", closeErr)
		}

		if err == nil && len(got) >= count {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d receipts in chain %s; got %d (err=%v)\ntrace:\n%s",
				count, f.Config.ChainID, len(got), err, f.Trace())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Trace returns the daemon's trace log output for debugging test failures.
func (f *DaemonFixture) Trace() string {
	return f.traceBuf.String()
}

// findSDKRoot locates the repo root by walking up from the current working
// directory until it finds the repo-root go.work file. The monorepo always
// has a committed go.work (see /AGENTS.md "Go workspace"), so falling back
// to a bare sdk/ directory match would only mask a misconfigured checkout.
func findSDKRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.work not found in any parent)")
		}
		dir = parent
	}
}

// findHelperScript locates a test helper script in daemon/helpers/.
func findHelperScript(t *testing.T, name string) string {
	t.Helper()
	root := findSDKRoot(t)
	helperPath := filepath.Join(root, "daemon", "helpers", name)
	if _, err := os.Stat(helperPath); err != nil {
		t.Fatalf("helper script not found: %s", helperPath)
	}
	return helperPath
}
