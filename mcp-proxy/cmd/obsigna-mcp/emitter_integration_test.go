//go:build linux || darwin

// Emitter integration tests verify that the mcp-proxy's emitToContext helper
// correctly forwards tool-call events to a running agent-receipts daemon via
// the Go SDK emitter. Tests run end-to-end against an in-process daemon so
// the full wire path (emitter → AF_UNIX socket → daemon pipeline → SQLite
// receipt store) is exercised. Build-tag-gated to linux/darwin because
// daemon.Run refuses to start on other platforms.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/mcp-proxy/configs"
	"github.com/agent-receipts/ar/sdk/go/emitter"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// shortSocketDirEmitter returns a temp directory with a short enough path that
// a socket inside it fits within the 104-byte AF_UNIX sun_path limit on macOS.
// t.TempDir() on macOS can produce ~119-char paths under /var/folders/…,
// exceeding the limit and tripping "bind: invalid argument".
func shortSocketDirEmitter(t *testing.T) string {
	t.Helper()
	base := "/tmp"
	if _, err := os.Stat(base); err != nil {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "arproxy*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func writeTestKeyForProxy(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

type testDaemonHandle struct {
	cfg      daemon.Config
	cancel   context.CancelFunc
	done     <-chan error
	stopOnce sync.Once
	stopErr  error
}

func startTestDaemon(t *testing.T, dir string) *testDaemonHandle {
	t.Helper()
	cfg := daemon.Config{
		SocketPath: filepath.Join(dir, "events.sock"),
		// shortSocketDirEmitter lives under /tmp to stay within the 104-byte
		// AF_UNIX sun_path limit on macOS — outside the daemon's per-platform
		// safe set, so opt into the documented escape hatch (issue #538).
		UnsafeSocketPath:     true,
		DBPath:               filepath.Join(dir, "receipts.db"),
		KeyPath:              filepath.Join(dir, "signing.key"),
		PublicKeyPath:        filepath.Join(dir, "signing.key.pub"),
		ChainID:              "mcp-proxy-emitter-test",
		IssuerID:             "did:agent-receipts-daemon:proxy-test",
		VerificationMethodID: "did:agent-receipts-daemon:proxy-test#k1",
		Logger:               log.New(io.Discard, "", 0),
	}
	if _, err := os.Stat(cfg.KeyPath); os.IsNotExist(err) {
		writeTestKeyForProxy(t, cfg.KeyPath)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx, cfg) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("socket %s did not appear within 2s", cfg.SocketPath)
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("daemon exited prematurely during startup: %v", err)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	d := &testDaemonHandle{cfg: cfg, cancel: cancel, done: done}
	t.Cleanup(func() { d.stop(t) })
	return d
}

func (d *testDaemonHandle) stop(t *testing.T) {
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
		if conn, err := net.Dial("unix", d.cfg.SocketPath); err == nil {
			conn.Close()
			d.stopErr = errors.New("socket still accepting connections after stop")
		}
	})
	if d.stopErr != nil {
		t.Fatal(d.stopErr)
	}
}

func waitForDaemonReceipts(t *testing.T, dbPath, chainID string, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		s, err := store.OpenReadOnly(dbPath)
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		got, err := s.GetChain(chainID)
		s.Close()
		if err == nil && len(got) >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d receipts in chain %s; got %d (err=%v)", want, chainID, len(got), err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// silentSlog returns a slog.Logger that discards every level. Tests pass it
// to emitter.NewDaemon so dial/write drops do not pollute `go test -v` output.
func silentSlog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newSilentEmitter returns an Emitter that discards its slog drop output.
func newSilentEmitter(t *testing.T, socketPath, sessionID string) *emitter.DaemonEmitter {
	t.Helper()
	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(socketPath),
		emitter.WithSessionID(sessionID),
		emitter.WithLogger(silentSlog()),
	)
	if err != nil {
		t.Fatalf("emitter.NewDaemon: %v", err)
	}
	t.Cleanup(func() { _ = em.Close() })
	return em
}

// TestEmitToContext_AllowedToolCall is the basic acceptance test: an "allowed"
// event forwarded through emitToContext materialises as a signed receipt in the
// daemon's chain. It exercises the full wire path without using the proxy's
// serve() function, so it isolates the emitToContext helper cleanly.
func TestEmitToContext_AllowedToolCall(t *testing.T) {
	d := startTestDaemon(t, shortSocketDirEmitter(t))

	em := newSilentEmitter(t, d.cfg.SocketPath, "proxy-test-session-allowed")

	emitToContext(em, "test-server", "read_file",
		json.RawMessage(`{"path":"/tmp/test.txt"}`),
		json.RawMessage(`{"content":"hello"}`),
		"",
		"allowed",
		"jsonrpc-req-42",
		"",
		"",
		"test-server",
		"/tmp/test.txt",
	)

	waitForDaemonReceipts(t, d.cfg.DBPath, d.cfg.ChainID, 1, 5*time.Second)

	// The wrapped JSON-RPC request id must reach action.idempotency_key
	// (spec §7.3.6): proxy → emitter frame → daemon build → signed receipt.
	s, err := store.OpenReadOnly(d.cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	receipts, err := s.GetChain(d.cfg.ChainID)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1", len(receipts))
	}
	if got := receipts[0].CredentialSubject.Action.IdempotencyKey; got != "jsonrpc-req-42" {
		t.Errorf("action.idempotency_key = %q, want %q", got, "jsonrpc-req-42")
	}

	// The resource identity passed through emitToContext must materialise on
	// action.target so cross-agent contention can draw edges (#852).
	target := receipts[0].CredentialSubject.Action.Target
	if target == nil {
		t.Fatal("action.target is nil; want system/resource populated")
	}
	if target.System != "test-server" || target.Resource != "/tmp/test.txt" {
		t.Errorf("action.target = {%q, %q}, want {%q, %q}",
			target.System, target.Resource, "test-server", "/tmp/test.txt")
	}
}

// TestEmitToContext_DeniedToolCall verifies that a "denied" decision (blocked by
// policy or rejected approval) is forwarded correctly. The daemon must accept
// the frame and produce a receipt with a failure outcome.
func TestEmitToContext_DeniedToolCall(t *testing.T) {
	d := startTestDaemon(t, shortSocketDirEmitter(t))

	em := newSilentEmitter(t, d.cfg.SocketPath, "proxy-test-session-denied")

	emitToContext(em, "test-server", "delete_secrets",
		json.RawMessage(`{"target":"all"}`),
		nil,
		"blocked by policy: delete_secrets matches block rule",
		"denied",
		"",
		"",
		"",
		"test-server",
		"all",
	)

	waitForDaemonReceipts(t, d.cfg.DBPath, d.cfg.ChainID, 1, 5*time.Second)
}

// TestEmitToContext_MultipleEvents verifies that several back-to-back calls
// through emitToContext produce monotonically sequenced receipts in the daemon.
func TestEmitToContext_MultipleEvents(t *testing.T) {
	d := startTestDaemon(t, shortSocketDirEmitter(t))

	em := newSilentEmitter(t, d.cfg.SocketPath, "proxy-test-session-multi")

	events := []struct {
		tool     string
		input    json.RawMessage
		output   json.RawMessage
		decision string
	}{
		{"read_file", json.RawMessage(`{"path":"/a"}`), json.RawMessage(`{"ok":true}`), "allowed"},
		{"write_file", json.RawMessage(`{"path":"/b","content":"x"}`), nil, "allowed"},
		{"delete_secrets", json.RawMessage(`{}`), nil, "denied"},
	}

	for _, ev := range events {
		emitToContext(em, "multi-server", ev.tool, ev.input, ev.output, "", ev.decision, "", "", "", "", "")
	}

	waitForDaemonReceipts(t, d.cfg.DBPath, d.cfg.ChainID, len(events), 5*time.Second)

	s, err := store.OpenReadOnly(d.cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	receipts, err := s.GetChain(d.cfg.ChainID)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(receipts) != len(events) {
		t.Fatalf("got %d receipts, want %d", len(receipts), len(events))
	}

	// Sequence numbers must be monotonically increasing from 1.
	for i, r := range receipts {
		if r.CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("receipt[%d]: sequence = %d, want %d", i, r.CredentialSubject.Chain.Sequence, i+1)
		}
	}
}

// TestEmitToContext_FireAndForgetWhenNoDaemon verifies the core ADR-0010
// fire-and-forget property: emitToContext MUST NOT block or panic when the
// daemon socket does not exist. The call should return quickly (well under
// 100ms) and log a drop.
func TestEmitToContext_FireAndForgetWhenNoDaemon(t *testing.T) {
	dir := shortSocketDirEmitter(t)
	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(filepath.Join(dir, "no-daemon.sock")),
		emitter.WithSessionID("proxy-test-noDaemon"),
		emitter.WithLogger(silentSlog()),
	)
	if err != nil {
		t.Fatalf("emitter.NewDaemon: %v", err)
	}
	defer em.Close()

	start := time.Now()
	// emitToContext logs the drop via log.Printf — that's fine for tests.
	emitToContext(em, "srv", "noop", nil, nil, "", "allowed", "", "", "", "", "")
	elapsed := time.Since(start)

	// 25ms dial timeout + 100ms write deadline = 125ms worst-case. We allow
	// double that to absorb scheduling jitter on slow CI machines.
	if elapsed > 250*time.Millisecond {
		t.Errorf("emitToContext blocked for %v; want <250ms (fire-and-forget contract)", elapsed)
	}
}

// TestEmitToContext_NilInputsAreValid verifies that nil input and output
// arguments are accepted without panic. emitter.Emit treats nil JSON fields as
// absent; the daemon skips hashing for missing payloads. The test uses a real
// (no-daemon) emitter so the full Emit call path is exercised.
func TestEmitToContext_NilInputsAreValid(t *testing.T) {
	dir := shortSocketDirEmitter(t)
	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(filepath.Join(dir, "no-daemon2.sock")),
		emitter.WithSessionID("proxy-test-nilinputs"),
		emitter.WithLogger(silentSlog()),
	)
	if err != nil {
		t.Fatalf("emitter.NewDaemon: %v", err)
	}
	defer em.Close()

	// nil input and output are valid: the emitter accepts them and the daemon
	// treats them as absent. No panic, no error returned.
	emitToContext(em, "srv", "tool-with-no-io", nil, nil, "", "allowed", "", "", "", "", "")
}

// TestEmitToContext_NilEmitterIsNoOp guards the nil-emitter path in serve():
// when em is nil (daemon socket empty or emitter init failed), emitToContext
// must silently return without panic. The nil guard in emitToContext makes the
// `if em != nil` check in serve() redundant for safety purposes, but the
// explicit guard at the call sites is kept for clarity.
func TestEmitToContext_NilEmitterIsNoOp(t *testing.T) {
	// Must not panic.
	emitToContext(nil, "srv", "tool", nil, nil, "", "allowed", "", "", "", "", "")
}

// TestEmitToContext_SessionIDPropagatesToReceipts verifies the ADR-0010 OQ4
// invariant that the proxy's session id (the same value the audit DB sees)
// is the issuer.session_id of every receipt the daemon writes. Without this
// the operator cannot correlate proxy logs with daemon-produced receipts.
func TestEmitToContext_SessionIDPropagatesToReceipts(t *testing.T) {
	d := startTestDaemon(t, shortSocketDirEmitter(t))

	const sid = "proxy-session-id-stability-2026-05"
	em := newSilentEmitter(t, d.cfg.SocketPath, sid)

	for i := 0; i < 3; i++ {
		emitToContext(em, "srv", "tool", json.RawMessage(`{"i":1}`), nil, "", "allowed", "", "", "", "", "")
	}

	waitForDaemonReceipts(t, d.cfg.DBPath, d.cfg.ChainID, 3, 5*time.Second)

	s, err := store.OpenReadOnly(d.cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	receipts, err := s.GetChain(d.cfg.ChainID)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	for i, r := range receipts {
		if r.Issuer.SessionID != sid {
			t.Errorf("receipt[%d]: issuer.session_id = %q; want %q", i, r.Issuer.SessionID, sid)
		}
	}
}

// TestEmitToContext_MappedToolForwardsActionType verifies issue #721 for the
// proxy: a tool that resolves to a real taxonomic type sends that type on the
// emitter frame, and the daemon uses it verbatim as action.type and resolves
// the matching risk_level from the taxonomy. `delete_file` maps to
// "data.api.delete" in the bundled github taxonomy (a high-risk data type), so
// the resulting receipt must carry that type and risk_level: high.
func TestEmitToContext_MappedToolForwardsActionType(t *testing.T) {
	d := startTestDaemon(t, shortSocketDirEmitter(t))

	em := newSilentEmitter(t, d.cfg.SocketPath, "proxy-test-session-mapped")

	mappings, err := configs.BundledTaxonomies()
	if err != nil {
		t.Fatalf("BundledTaxonomies: %v", err)
	}
	const tool = "delete_file"
	actionType := resolveActionType(tool, mappings)
	if actionType != "data.api.delete" {
		t.Fatalf("resolveActionType(%q) = %q; want %q (check bundled github taxonomy)", tool, actionType, "data.api.delete")
	}

	emitToContext(em, "github", tool,
		json.RawMessage(`{"path":"secrets.txt"}`), nil, "", "allowed", "", "", actionType, "", "")

	waitForDaemonReceipts(t, d.cfg.DBPath, d.cfg.ChainID, 1, 5*time.Second)

	s, err := store.OpenReadOnly(d.cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	receipts, err := s.GetChain(d.cfg.ChainID)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1", len(receipts))
	}
	action := receipts[0].CredentialSubject.Action
	if action.Type != "data.api.delete" {
		t.Errorf("action.type = %q; want %q (daemon must use the forwarded action_type verbatim)", action.Type, "data.api.delete")
	}
	if action.RiskLevel != receipt.RiskHigh {
		t.Errorf("action.risk_level = %q; want %q (daemon resolves risk from the taxonomic type)", action.RiskLevel, receipt.RiskHigh)
	}
}

// TestEmitToContext_UnknownToolOmitsActionType verifies the issue #721
// constraint that the proxy sends NO action_type for a tool that does not map
// to a real taxonomic type. resolveActionType returns "" for the unknown case,
// the emitter omits the frame field, and the daemon falls back to its synthetic
// "<channel>.<tool>" type (risk_level: medium).
func TestEmitToContext_UnknownToolOmitsActionType(t *testing.T) {
	d := startTestDaemon(t, shortSocketDirEmitter(t))

	em := newSilentEmitter(t, d.cfg.SocketPath, "proxy-test-session-unknown")

	mappings, err := configs.BundledTaxonomies()
	if err != nil {
		t.Fatalf("BundledTaxonomies: %v", err)
	}
	const tool = "totally_unmapped_tool_xyz"
	if at := resolveActionType(tool, mappings); at != "" {
		t.Fatalf("resolveActionType(%q) = %q; want empty (unmapped tool must not send a type)", tool, at)
	}

	// Mirror the proxy: an unmapped tool forwards an empty action_type.
	emitToContext(em, "github", tool,
		json.RawMessage(`{"q":"x"}`), nil, "", "allowed", "", "", resolveActionType(tool, mappings), "", "")

	waitForDaemonReceipts(t, d.cfg.DBPath, d.cfg.ChainID, 1, 5*time.Second)

	s, err := store.OpenReadOnly(d.cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	receipts, err := s.GetChain(d.cfg.ChainID)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1", len(receipts))
	}
	// With no forwarded action_type the daemon derives the synthetic
	// "<channel>.<tool>" type — "mcp.github.totally_unmapped_tool_xyz" — never a
	// guessed taxonomic value.
	if got := receipts[0].CredentialSubject.Action.Type; got != "mcp.github."+tool {
		t.Errorf("action.type = %q; want synthetic fallback %q", got, "mcp.github."+tool)
	}
}
