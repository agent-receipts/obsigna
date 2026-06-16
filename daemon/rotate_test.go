package daemon

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-receipts/ar/daemon/internal/anchor"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

func rotateTestConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")
	pubPath := keyPath + ".pub"
	if err := GenerateKey(keyPath, pubPath); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return Config{
		KeyPath:              keyPath,
		PublicKeyPath:        pubPath,
		DBPath:               filepath.Join(dir, "receipts.db"),
		ChainID:              "test-chain",
		IssuerID:             "did:agent-receipts-daemon:test",
		VerificationMethodID: "did:agent-receipts-daemon:test#k1",
		// SocketPath empty so the running-daemon guard is a no-op.
	}
}

// seedReceipt appends one ordinary receipt to the chain, signed with the key
// currently at cfg.KeyPath, and returns its hash for linking the next receipt.
func seedReceipt(t *testing.T, cfg Config, seq int, prev *string) string {
	t.Helper()
	privPEM, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	unsigned := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: cfg.IssuerID},
		Principal: receipt.Principal{ID: cfg.IssuerID},
		Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
		Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
		Chain:     receipt.Chain{Sequence: seq, PreviousReceiptHash: prev, ChainID: cfg.ChainID},
	})
	signed, err := receipt.Sign(unsigned, string(privPEM), cfg.VerificationMethodID)
	if err != nil {
		t.Fatalf("sign seed receipt: %v", err)
	}
	h, err := receipt.HashReceipt(signed)
	if err != nil {
		t.Fatalf("hash seed receipt: %v", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Insert(signed, h); err != nil {
		t.Fatalf("insert seed receipt: %v", err)
	}
	return h
}

func getStoredChain(t *testing.T, cfg Config) []receipt.AgentReceipt {
	t.Helper()
	st, err := store.OpenReadOnly(cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	receipts, err := st.GetChain(cfg.ChainID)
	if err != nil {
		t.Fatalf("get chain: %v", err)
	}
	return receipts
}

func verifyStoredChain(t *testing.T, cfg Config, genesisPubPEM string) receipt.ChainVerification {
	t.Helper()
	return receipt.VerifyChain(getStoredChain(t, cfg), genesisPubPEM)
}

func TestRotateKey(t *testing.T) {
	cfg := rotateTestConfig(t)

	// Genesis public key — the key the whole chain must verify from.
	genesisPub, err := os.ReadFile(cfg.PublicKeyPath)
	if err != nil {
		t.Fatalf("read genesis pub: %v", err)
	}

	// Seed one pre-rotation receipt so the rotation lands at seq 2.
	h1 := seedReceipt(t, cfg, 1, nil)

	summary, err := RotateKey(cfg)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if summary.Sequence != 2 {
		t.Errorf("rotation sequence = %d, want 2", summary.Sequence)
	}

	// The archived public key must equal the original genesis key.
	archived, err := os.ReadFile(summary.ArchivedPublicKey)
	if err != nil {
		t.Fatalf("read archived pub: %v", err)
	}
	if string(archived) != string(genesisPub) {
		t.Error("archived public key does not match the original genesis key")
	}

	// The published public key must now be the NEW key (differs from genesis).
	newPub, err := os.ReadFile(cfg.PublicKeyPath)
	if err != nil {
		t.Fatalf("read new pub: %v", err)
	}
	if string(newPub) == string(genesisPub) {
		t.Error("public key file was not swapped to the new key")
	}

	// The chain (seed + rotation) verifies from the genesis key, traversing
	// the rotation.
	cv := verifyStoredChain(t, cfg, string(genesisPub))
	if !cv.Valid {
		t.Fatalf("rotated chain failed to verify: brokenAt=%d err=%q", cv.BrokenAt, cv.Error)
	}

	// The rotation receipt links to the seed receipt and carries keyRotation.
	chain := getStoredChain(t, cfg)
	if len(chain) != 2 {
		t.Fatalf("chain length = %d, want 2", len(chain))
	}
	rot := chain[1]
	if rot.CredentialSubject.KeyRotation == nil {
		t.Fatal("rotation receipt has no keyRotation")
	}
	if rot.CredentialSubject.Chain.PreviousReceiptHash == nil ||
		*rot.CredentialSubject.Chain.PreviousReceiptHash != h1 {
		t.Errorf("rotation previous_receipt_hash = %v, want %s",
			rot.CredentialSubject.Chain.PreviousReceiptHash, h1)
	}
	if rot.CredentialSubject.KeyRotation.OldKeyFingerprint != summary.OldFingerprint {
		t.Errorf("rotation old_key_fingerprint = %s, want %s",
			rot.CredentialSubject.KeyRotation.OldKeyFingerprint, summary.OldFingerprint)
	}
	if rot.CredentialSubject.KeyRotation.NewKeyFingerprint != summary.NewFingerprint {
		t.Errorf("rotation new_key_fingerprint = %s, want %s",
			rot.CredentialSubject.KeyRotation.NewKeyFingerprint, summary.NewFingerprint)
	}

	// A post-rotation receipt signed by the NEW key (now at cfg.KeyPath) links
	// to the rotation receipt and still verifies under the genesis key.
	st, err := store.OpenReadOnly(cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	_, rotHash, _, err := st.GetChainTail(cfg.ChainID)
	_ = st.Close()
	if err != nil {
		t.Fatalf("get tail: %v", err)
	}
	seedReceipt(t, cfg, 3, &rotHash)
	cv = verifyStoredChain(t, cfg, string(genesisPub))
	if !cv.Valid {
		t.Fatalf("chain with post-rotation receipt failed: brokenAt=%d err=%q", cv.BrokenAt, cv.Error)
	}
	if cv.Length != 3 {
		t.Errorf("chain length = %d, want 3", cv.Length)
	}
}

func TestRotateKeyRefusesRunningDaemon(t *testing.T) {
	cfg := rotateTestConfig(t)
	sock := filepath.Join(t.TempDir(), "events.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("cannot listen on unix socket: %v", err)
	}
	defer func() { _ = ln.Close() }()
	cfg.SocketPath = sock

	if _, err := RotateKey(cfg); err == nil {
		t.Fatal("expected RotateKey to refuse while a daemon is listening, got nil")
	}
}

func TestRotateKeyAnchors(t *testing.T) {
	cfg := rotateTestConfig(t)
	cfg.AnchorLogPath = filepath.Join(filepath.Dir(cfg.KeyPath), "anchor.log")

	summary, err := RotateKey(cfg)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if summary.AnchoredTo != cfg.AnchorLogPath {
		t.Errorf("AnchoredTo = %q, want %q", summary.AnchoredTo, cfg.AnchorLogPath)
	}

	data, err := os.ReadFile(cfg.AnchorLogPath)
	if err != nil {
		t.Fatalf("read anchor log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("anchor log has %d lines, want 1", len(lines))
	}
	var rec anchor.Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("anchor record not JSON: %v", err)
	}
	if rec.EventType != anchor.EventTypeRotation {
		t.Errorf("anchor event_type = %q, want %q", rec.EventType, anchor.EventTypeRotation)
	}

	// The anchored payload is the rotation receipt's canonical form.
	chain := getStoredChain(t, cfg)
	rot := chain[len(chain)-1]
	canon, err := receipt.Canonicalize(rot)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(rec.Payload) != canon {
		t.Errorf("anchored payload does not match the stored rotation receipt's canonical form")
	}
}

func TestRotateKeyAnchorFailureAborts(t *testing.T) {
	cfg := rotateTestConfig(t)
	// A path under a regular file can never be opened (ENOTDIR), so the anchor
	// write fails — the rotation must abort with no local change.
	cfg.AnchorLogPath = filepath.Join(cfg.KeyPath, "nope", "anchor.log")
	origPriv, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := RotateKey(cfg); err == nil {
		t.Fatal("expected RotateKey to fail when the anchor is unwritable")
	}

	if chain := getStoredChain(t, cfg); len(chain) != 0 {
		t.Errorf("store has %d receipts, want 0 — an aborted rotation must commit nothing", len(chain))
	}
	nowPriv, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(nowPriv) != string(origPriv) {
		t.Error("signing key changed despite an aborted rotation")
	}
}

func TestRotateKeyGenesisPosition(t *testing.T) {
	cfg := rotateTestConfig(t)
	genesisPub, err := os.ReadFile(cfg.PublicKeyPath)
	if err != nil {
		t.Fatalf("read genesis pub: %v", err)
	}

	// Rotate on an empty store — the rotation is the genesis (seq 1) receipt.
	summary, err := RotateKey(cfg)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if summary.Sequence != 1 {
		t.Errorf("genesis rotation sequence = %d, want 1", summary.Sequence)
	}
	cv := verifyStoredChain(t, cfg, string(genesisPub))
	if !cv.Valid {
		t.Fatalf("genesis rotation chain failed: brokenAt=%d err=%q", cv.BrokenAt, cv.Error)
	}
}
