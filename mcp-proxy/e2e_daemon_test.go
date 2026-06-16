//go:build e2e && (linux || darwin)

package e2e_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// e2eDaemon is a live agent-receipts daemon started in-process for the
// full-stack e2e test. It owns an AF_UNIX socket the spawned proxy binary
// connects to over --socket.
//
// runErr is written before exited is closed (single writer goroutine), so any
// reader observing a closed exited can read runErr without further
// synchronisation.
type e2eDaemon struct {
	cfg    daemon.Config
	pubPEM string
	exited chan struct{} // closed when daemon.Run returns
	runErr error         // result of Run; read only after exited is closed
}

// startE2EDaemon brings up a real daemon on a short /tmp socket path and waits
// for it to accept connections. It returns the config (for the socket path and
// store location) and the PEM public key for receipt verification.
func startE2EDaemon(t *testing.T) *e2eDaemon {
	t.Helper()

	// Keep the socket under /tmp to stay within the 104-byte AF_UNIX sun_path
	// limit; opt into the documented escape hatch since /tmp is outside the
	// daemon's per-platform safe set (issue #538).
	dir, err := os.MkdirTemp("/tmp", "arproxye2e*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	cfg := daemon.Config{
		SocketPath:           filepath.Join(dir, "events.sock"),
		UnsafeSocketPath:     true,
		DBPath:               filepath.Join(dir, "receipts.db"),
		KeyPath:              filepath.Join(dir, "signing.key"),
		PublicKeyPath:        filepath.Join(dir, "signing.key.pub"),
		ChainID:              "mcp-proxy-e2e",
		IssuerID:             "did:agent-receipts-daemon:proxy-e2e",
		VerificationMethodID: "did:agent-receipts-daemon:proxy-e2e#k1",
		Logger:               log.New(io.Discard, "", 0),
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.KeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	d := &e2eDaemon{cfg: cfg, pubPEM: pubPEM, exited: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		d.runErr = daemon.Run(ctx, cfg)
		close(d.exited)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if conn, err := net.DialTimeout("unix", cfg.SocketPath, 100*time.Millisecond); err == nil {
			conn.Close()
			break
		}
		select {
		case <-d.exited:
			cancel()
			t.Fatalf("daemon exited during startup: %v", d.runErr)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("daemon socket %s did not become ready within 2s", cfg.SocketPath)
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Cleanup(func() {
		cancel()
		select {
		case <-d.exited:
		case <-time.After(3 * time.Second):
			t.Error("daemon did not shut down within 3s")
		}
	})

	return d
}

// TestE2EProxyEmitsReceiptToDaemon drives the compiled proxy binary, wired to a
// live daemon via --socket, through a real tool call and asserts a signed
// receipt lands in the daemon's chain. emitter_integration_test.go already
// covers the proxy's emitToContext helper in-process; this closes the remaining
// seam — that the shipped binary's --socket wiring (cmd/obsigna-mcp/main.go)
// actually forwards completed tool calls end to end: client → proxy process →
// AF_UNIX → daemon → SQLite.
func TestE2EProxyEmitsReceiptToDaemon(t *testing.T) {
	d := startE2EDaemon(t)

	stdin, scanner, cmd := startProxyWithSocket(t, d.cfg.SocketPath)

	// An allowed tool call: the mock server serves read_file, policy passes it,
	// and the proxy forwards the completed event to the daemon.
	sendJSON(t, stdin, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": "read_file", "arguments": map[string]any{"path": "/tmp/test"}},
	})

	resp := readResponse(t, scanner)
	if resp["error"] != nil {
		t.Fatalf("expected success for read_file, got error: %v", resp["error"])
	}

	// Emission is fire-and-forget relative to the JSON-RPC reply, so poll the
	// daemon's store rather than assuming the receipt is durable by reply time.
	receipts := d.waitForReceipts(t, 1, 5*time.Second)

	// Find the read_file receipt and verify it against the daemon's key.
	var found *receipt.AgentReceipt
	for i := range receipts {
		if receipts[i].CredentialSubject.Action.ToolName == "read_file" {
			found = &receipts[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no receipt with tool_name=read_file among %d receipts", len(receipts))
	}
	ok, err := receipt.Verify(*found, d.pubPEM)
	if err != nil || !ok {
		t.Errorf("receipt verify: ok=%v err=%v", ok, err)
	}

	waitForExit(t, stdin, cmd)
}

// waitForReceipts polls the daemon's read-only store until at least want
// receipts exist in the chain or the timeout elapses. It surfaces an early
// daemon exit directly instead of letting a crashed daemon look like a slow
// one: a closed exited channel during the test means Run returned before
// cleanup cancelled it.
func (d *e2eDaemon) waitForReceipts(t *testing.T, want int, timeout time.Duration) []receipt.AgentReceipt {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		select {
		case <-d.exited:
			t.Fatalf("daemon exited before %d receipts landed: %v", want, d.runErr)
		default:
		}

		s, err := store.OpenReadOnly(d.cfg.DBPath)
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		got, err := s.GetChain(d.cfg.ChainID)
		s.Close()
		if err == nil && len(got) >= want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d receipts in chain %s; got %d (err=%v)", want, d.cfg.ChainID, len(got), err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
