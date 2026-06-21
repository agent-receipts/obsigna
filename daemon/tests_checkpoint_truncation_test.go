package daemon_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"obsigna.dev/daemon/internal/anchor"
	"obsigna.dev/daemon/internal/chain"
	"obsigna.dev/daemon/internal/checkpoint"
	"obsigna.dev/daemon/internal/keysource"
	"obsigna.dev/daemon/internal/pipeline"
	"obsigna.dev/daemon/internal/socket"
	"obsigna.dev/daemon/internal/verifycli"
	"obsigna.dev/sdk/go/store"

	_ "modernc.org/sqlite"
)

// TestCheckpointAnchorCatchesTailTruncation is the verification-contract gate
// for ADR-0024 ("No tail truncation"): emit a chain, anchor a signed checkpoint
// per receipt, truncate the receipt-store tail, then run `verify
// --against-anchor` and assert it goes RED with a truncation reason. The same
// chain, verified WITHOUT the flag, must still report VALID — proving both that
// truncation is invisible to plain chain verification (the gap ADR-0008 names)
// and that the anchor closes it.
//
// Driven through the pipeline directly (no socket) so the gate is deterministic
// and fast; the daemon Config→Run→emitter wiring is covered separately by the
// integration test.
func TestCheckpointAnchorCatchesTailTruncation(t *testing.T) {
	const (
		chainID  = "trunc-chain"
		issuerID = "did:agent-receipts-daemon:test"
		vm       = issuerID + "#k1"
		total    = 5
		keep     = 3 // truncate the store back to this many receipts
	)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")
	keyPath, pubPath := writeTestKeypair(t, dir, vm)
	anchorPath := filepath.Join(dir, "anchor.ndjson")

	// --- emit + anchor -----------------------------------------------------
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	ks := keysource.NewFile(keyPath, vm)
	if err := ks.Init(); err != nil {
		t.Fatalf("keysource init: %v", err)
	}
	sink, err := anchor.OpenSink("file:" + anchorPath)
	if err != nil {
		t.Fatalf("open sink: %v", err)
	}
	emitter := checkpoint.NewEmitter([]anchor.Sink{sink}, ks, 1, nil)

	pp := pipeline.New(chain.New(chainID), ks, st, issuerID)
	pp.Checkpointer = emitter

	for i := 0; i < total; i++ {
		if err := pp.Process(sampleCheckpointFrame(t)); err != nil {
			t.Fatalf("process frame %d: %v", i, err)
		}
	}
	// Drain the async worker before reading the emitted counter; Observe enqueues
	// asynchronously so in-flight emissions may not have landed yet.
	if err := emitter.FlushAll(); err != nil {
		t.Fatalf("FlushAll: %v", err)
	}
	if got := emitter.Emitted(); got != total {
		t.Fatalf("emitted %d checkpoints, want %d", got, total)
	}
	if got := emitter.Failures(); got != 0 {
		t.Fatalf("emitter reported %d failures, want 0", got)
	}
	if err := emitter.Close(); err != nil {
		t.Fatalf("close emitter: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// --- happy path: head matches the latest checkpoint -------------------
	if code, out := runVerify(t, dbPath, pubPath, chainID, anchorPath); code != verifycli.ExitOK {
		t.Fatalf("pre-truncation verify exit = %d, want %d\n%s", code, verifycli.ExitOK, out)
	} else if !strings.Contains(out, "PASS") {
		t.Fatalf("pre-truncation anchor check did not PASS:\n%s", out)
	}

	// --- truncate the receipt-store tail ----------------------------------
	truncateChainTail(t, dbPath, chainID, keep)

	// Without the flag, a tail-truncated chain still verifies VALID: the
	// remaining receipts are internally consistent. This is the byte-identical
	// default behaviour the freeze guarantees.
	if code, out := runVerifyNoAnchor(t, dbPath, pubPath, chainID); code != verifycli.ExitOK {
		t.Fatalf("plain verify of truncated chain exit = %d, want %d (default behaviour must be unchanged)\n%s", code, verifycli.ExitOK, out)
	} else if !strings.Contains(out, "VALID") {
		t.Fatalf("plain verify of truncated chain should still report VALID:\n%s", out)
	}

	// With --against-anchor, the dropped tail is caught and verification fails.
	code, out := runVerify(t, dbPath, pubPath, chainID, anchorPath)
	if code != verifycli.ExitChainBad {
		t.Fatalf("post-truncation verify exit = %d, want %d (truncation must fail)\n%s", code, verifycli.ExitChainBad, out)
	}
	if !strings.Contains(strings.ToLower(out), "truncat") {
		t.Fatalf("post-truncation verify did not give a truncation reason:\n%s", out)
	}
}

// sampleCheckpointFrame builds a minimal valid live emitter frame.
func sampleCheckpointFrame(t *testing.T) socket.Frame {
	t.Helper()
	body, err := json.Marshal(pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    time.Now().UTC().Format(time.RFC3339),
		SessionID: "sess-trunc",
		Channel:   "mcp_proxy",
		Tool:      pipeline.EmitterTool{Server: "github", Name: "list_repos"},
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	return socket.Frame{
		Payload: body,
		Peer: socket.PeerCred{
			Platform: "linux",
			PID:      1234,
			UID:      1000,
			GID:      1000,
		},
	}
}

func writeTestKeypair(t *testing.T, dir, _ string) (keyPath, pubPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "signing.key")
	pubPath = filepath.Join(dir, "signing.key.pub")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return keyPath, pubPath
}

// truncateChainTail deletes every receipt in chainID with sequence > keep,
// standing in for an attacker who drops the tail of the receipt store.
func truncateChainTail(t *testing.T, dbPath, chainID string, keep int) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db for truncation: %v", err)
	}
	defer func() { _ = db.Close() }()
	res, err := db.Exec("DELETE FROM receipts WHERE chain_id = ? AND sequence > ?", chainID, keep)
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		t.Fatal("truncation deleted 0 rows — test setup is wrong")
	}
}

func runVerify(t *testing.T, dbPath, pubPath, chainID, anchorPath string) (int, string) {
	t.Helper()
	return runVerifyArgs(t, []string{
		"--db", dbPath, "--public-key", pubPath, "--chain-id", chainID, "--against-anchor", anchorPath,
	})
}

func runVerifyNoAnchor(t *testing.T, dbPath, pubPath, chainID string) (int, string) {
	t.Helper()
	return runVerifyArgs(t, []string{
		"--db", dbPath, "--public-key", pubPath, "--chain-id", chainID,
	})
}

func runVerifyArgs(t *testing.T, args []string) (int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := verifycli.Run(args, &stdout, &stderr, func(string) string { return "" })
	return code, stdout.String() + stderr.String()
}
