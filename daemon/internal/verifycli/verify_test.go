package verifycli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// fixtureChain writes a daemon-shaped DB at dbPath containing `count` valid
// signed receipts on chain `chainID`, and returns the matching public-key PEM
// path the verify CLI should be pointed at.
func fixtureChain(t *testing.T, dir, chainID string, count int) (dbPath, pubKeyPath string) {
	t.Helper()

	dbPath = filepath.Join(dir, "receipts.db")
	pubKeyPath = filepath.Join(dir, "signing.key.pub")

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
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubKeyPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var prevHash *string
	for i := 1; i <= count; i++ {
		unsigned := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: "did:test"},
			Principal: receipt.Principal{ID: "did:user:test"},
			Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
			Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
			Chain:     receipt.Chain{Sequence: i, PreviousReceiptHash: prevHash, ChainID: chainID},
		})
		signed, err := receipt.Sign(unsigned, privPEM, "did:test#k1")
		if err != nil {
			t.Fatal(err)
		}
		h, err := receipt.HashReceipt(signed)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(signed, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}
	return dbPath, pubKeyPath
}

// fixturePendingTailChain writes a valid signed chain whose final receipt is
// non-terminal with outcome.status == pending — the shape that VerifyChain
// flags as IncompleteToolRoundtrip. Returns the db path and public-key path.
func fixturePendingTailChain(t *testing.T, dir, chainID string, count int) (dbPath, pubKeyPath string) {
	t.Helper()

	dbPath = filepath.Join(dir, "receipts.db")
	pubKeyPath = filepath.Join(dir, "signing.key.pub")

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
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubKeyPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var prevHash *string
	for i := 1; i <= count; i++ {
		status := receipt.StatusSuccess
		if i == count {
			status = receipt.StatusPending
		}
		unsigned := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: "did:test"},
			Principal: receipt.Principal{ID: "did:user:test"},
			Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
			Outcome:   receipt.Outcome{Status: status},
			Chain:     receipt.Chain{Sequence: i, PreviousReceiptHash: prevHash, ChainID: chainID},
		})
		signed, err := receipt.Sign(unsigned, privPEM, "did:test#k1")
		if err != nil {
			t.Fatal(err)
		}
		h, err := receipt.HashReceipt(signed)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(signed, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}
	return dbPath, pubKeyPath
}

// fixtureRotatedChain builds a chain that has survived an offline key rotation:
// an ordinary receipt signed with the genesis key, a key_rotated receipt
// (signed with the genesis key, swapping in a new key), then an ordinary
// receipt signed with the post-rotation key. It returns the db path and the
// *published* public-key path — which, after rotation, holds the new key, not
// the genesis key. The superseded genesis key is left archived beside it as
// `<pub>.rotated-<fingerprint>` by daemon.RotateKey, which is what the verify
// CLI must rediscover. The returned chainID is fixed so callers pass it through.
func fixtureRotatedChain(t *testing.T, dir, chainID string) (dbPath, pubKeyPath string) {
	t.Helper()

	keyPath := filepath.Join(dir, "signing.key")
	pubKeyPath = keyPath + ".pub"
	dbPath = filepath.Join(dir, "receipts.db")
	if err := daemon.GenerateKey(keyPath, pubKeyPath); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cfg := daemon.Config{
		KeyPath:              keyPath,
		PublicKeyPath:        pubKeyPath,
		DBPath:               dbPath,
		ChainID:              chainID,
		IssuerID:             "did:test",
		VerificationMethodID: "did:test#k1",
		// SocketPath empty so the running-daemon guard is a no-op.
	}

	// seq 1: ordinary receipt signed with the genesis key.
	signSeed(t, cfg, 1, nil)
	// seq 2: rotation receipt — signed with the genesis (outgoing) key, archives
	// the genesis public key, and swaps the new key into pubKeyPath.
	if _, err := daemon.RotateKey(cfg); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	// seq 3: ordinary receipt signed with the new (post-rotation) key now at
	// keyPath — so a verifier that never traverses the rotation fails here too.
	prev := tailHash(t, dbPath, chainID)
	signSeed(t, cfg, 3, &prev)

	return dbPath, pubKeyPath
}

// signSeed appends one ordinary receipt at the given sequence, signed with the
// key currently at cfg.KeyPath, and inserts it into the store.
func signSeed(t *testing.T, cfg daemon.Config, seq int, prev *string) {
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
	s, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if err := s.Insert(signed, h); err != nil {
		t.Fatalf("insert seed receipt: %v", err)
	}
}

func tailHash(t *testing.T, dbPath, chainID string) string {
	t.Helper()
	s, err := store.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	_, h, found, err := s.GetChainTail(chainID)
	if err != nil {
		t.Fatalf("get chain tail: %v", err)
	}
	if !found {
		t.Fatalf("chain %s has no tail", chainID)
	}
	return h
}

func runOnce(t *testing.T, args []string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	// Empty env lookup so the test never accidentally inherits real
	// AGENTRECEIPTS_* values from the developer's shell.
	code = Run(args, &out, &errb, func(string) string { return "" })
	return code, out.String(), errb.String()
}

func TestRun_VerifiesGoodChain(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath := fixtureChain(t, dir, "chain-1", 3)

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	if !strings.Contains(stdout, "VALID (3 receipts)") {
		t.Errorf("stdout = %q, expected VALID with count", stdout)
	}
}

func TestRun_VerifiesSingleReceiptChain(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath := fixtureChain(t, dir, "chain-1", 1)

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	if !strings.Contains(stdout, "VALID (1 receipt)") {
		t.Errorf("stdout = %q, expected singular 'VALID (1 receipt)'", stdout)
	}
}

func TestRun_FlagsIncompleteToolRoundtrip(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath := fixturePendingTailChain(t, dir, "chain-1", 3)

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
	})
	// The advisory is informational only — it must not change the exit code.
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (incomplete roundtrip is advisory, not a break); stderr=%s", code, ExitOK, stderr)
	}
	if !strings.Contains(stdout, "incomplete tool roundtrip") {
		t.Errorf("stdout = %q, expected an incomplete-tool-roundtrip advisory line", stdout)
	}
	if !strings.Contains(stdout, "VALID") {
		t.Errorf("stdout = %q, expected the chain to still report VALID", stdout)
	}
}

// fixturePTYOpenChain writes a valid signed chain ending with a system.pty.open
// receipt that has no corresponding system.pty.close — the shape that VerifyChain
// flags as IncompleteSession. Returns the db path and public-key path.
func fixturePTYOpenChain(t *testing.T, dir, chainID string) (dbPath, pubKeyPath string) {
	t.Helper()

	dbPath = filepath.Join(dir, "receipts.db")
	pubKeyPath = filepath.Join(dir, "signing.key.pub")

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
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubKeyPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var prevHash *string
	for i := 1; i <= 2; i++ {
		unsigned := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: "did:test"},
			Principal: receipt.Principal{ID: "did:user:test"},
			Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
			Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
			Chain:     receipt.Chain{Sequence: i, PreviousReceiptHash: prevHash, ChainID: chainID},
		})
		signed, err := receipt.Sign(unsigned, privPEM, "did:test#k1")
		if err != nil {
			t.Fatal(err)
		}
		h, err := receipt.HashReceipt(signed)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(signed, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}
	// Append an unclosed pty.open receipt.
	openUnsigned := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: "did:test"},
		Principal: receipt.Principal{ID: "did:user:test"},
		Action:    receipt.Action{Type: receipt.ActionTypePTYOpen, RiskLevel: receipt.RiskCritical},
		Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
		Chain:     receipt.Chain{Sequence: 3, PreviousReceiptHash: prevHash, ChainID: chainID},
	})
	openSigned, err := receipt.Sign(openUnsigned, privPEM, "did:test#k1")
	if err != nil {
		t.Fatal(err)
	}
	openHash, err := receipt.HashReceipt(openSigned)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(openSigned, openHash); err != nil {
		t.Fatal(err)
	}
	return dbPath, pubKeyPath
}

func TestRun_FlagsIncompleteSession(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath := fixturePTYOpenChain(t, dir, "chain-1")

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
	})
	// The advisory is informational only — it must not change the exit code.
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (incomplete session is advisory, not a break); stderr=%s", code, ExitOK, stderr)
	}
	if !strings.Contains(stdout, "incomplete session") {
		t.Errorf("stdout = %q, expected an incomplete-session advisory line", stdout)
	}
	if !strings.Contains(stdout, "VALID") {
		t.Errorf("stdout = %q, expected the chain to still report VALID", stdout)
	}
}

func TestRun_ReportsBrokenChain(t *testing.T) {
	dir := t.TempDir()
	dbPath, _ := fixtureChain(t, dir, "chain-1", 2)

	// Use a *different* public key so signatures fail to verify.
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKIXPublicKey(otherPub)
	if err != nil {
		t.Fatal(err)
	}
	wrongPubPath := filepath.Join(dir, "wrong.pub")
	if err := os.WriteFile(wrongPubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", wrongPubPath,
		"--chain-id", "chain-1",
	})
	if code != ExitChainBad {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitChainBad, stderr)
	}
	if !strings.Contains(stdout, "BROKEN") || !strings.Contains(stdout, "BAD SIGNATURE") {
		t.Errorf("stdout = %q, expected BROKEN + BAD SIGNATURE lines", stdout)
	}
}

func TestRun_MissingPublicKeyIsUsageError(t *testing.T) {
	dir := t.TempDir()
	dbPath, _ := fixtureChain(t, dir, "chain-1", 1)

	code, _, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", filepath.Join(dir, "does-not-exist.pub"),
		"--chain-id", "chain-1",
	})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "read public key") {
		t.Errorf("stderr = %q, expected 'read public key' diagnostic", stderr)
	}
}

func TestRun_UnknownDBIsUsageError(t *testing.T) {
	dir := t.TempDir()
	_, pubKeyPath := fixtureChain(t, dir, "chain-1", 1)

	code, _, stderr := runOnce(t, []string{
		"--db", filepath.Join(dir, "no-such.db"),
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
	})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "open store") && !strings.Contains(stderr, "verify:") {
		t.Errorf("stderr = %q, expected open-store diagnostic", stderr)
	}
}

func TestRun_BadFlagIsUsageError(t *testing.T) {
	code, _, _ := runOnce(t, []string{"--bogus"})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
}

func TestRun_MalformedPublicKeyIsUsageError(t *testing.T) {
	dir := t.TempDir()
	dbPath, _ := fixtureChain(t, dir, "chain-1", 1)
	pubKeyPath := filepath.Join(dir, "garbage.pub")
	if err := os.WriteFile(pubKeyPath, []byte("not a pem block"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
	})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d (malformed key should be a usage error, not ExitChainBad)", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "invalid public key") {
		t.Errorf("stderr = %q, expected 'invalid public key' diagnostic", stderr)
	}
}

func TestRun_RejectsPositionalArgs(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath := fixtureChain(t, dir, "chain-1", 1)

	code, _, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
		"chain-1", // typo: chain-id passed positionally as well
	})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d (positional args should be a usage error)", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "unexpected positional argument") {
		t.Errorf("stderr = %q, expected unexpected-positional diagnostic", stderr)
	}
}

func TestRun_VerifiesRotatedChainFromPublishedKey(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath := fixtureRotatedChain(t, dir, "chain-1")

	// --public-key points at the *published* key, which after rotation is the
	// post-rotation key. The CLI must rediscover the archived genesis key and
	// verify the chain end-to-end through the rotation.
	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (rotated chain should verify from archived genesis key); stdout=%s stderr=%s", code, ExitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "VALID (3 receipts)") {
		t.Errorf("stdout = %q, expected VALID with 3 receipts", stdout)
	}
	if !strings.Contains(stderr, "chain is rotated; verifying from archived genesis key") {
		t.Errorf("stderr = %q, expected the rotated-chain genesis-key note", stderr)
	}
}

func TestRun_RotatedChainBrokenWhenGenesisArchiveMissing(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath := fixtureRotatedChain(t, dir, "chain-1")

	// Remove the archived genesis key so it can no longer be rediscovered. The
	// published key alone cannot verify receipt[0], so the chain must report
	// BROKEN at the first receipt rather than silently passing.
	archives, err := filepath.Glob(pubKeyPath + ".rotated-*")
	if err != nil || len(archives) == 0 {
		t.Fatalf("expected an archived genesis key beside %s (glob err=%v, matches=%v)", pubKeyPath, err, archives)
	}
	for _, a := range archives {
		if err := os.Remove(a); err != nil {
			t.Fatalf("remove archive %s: %v", a, err)
		}
	}

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
	})
	if code != ExitChainBad {
		t.Fatalf("exit = %d, want %d (missing genesis archive should fail, not pass); stderr=%s", code, ExitChainBad, stderr)
	}
	if !strings.Contains(stdout, "BROKEN at receipt 0") {
		t.Errorf("stdout = %q, expected BROKEN at receipt 0", stdout)
	}
	// Falling back to the published key means no genesis note is emitted.
	if strings.Contains(stderr, "verifying from archived genesis key") {
		t.Errorf("stderr = %q, expected no genesis-key note when no archive matches", stderr)
	}
}

func TestRun_RejectsRotatedChainNotEndingAtPublishedKey(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath := fixtureRotatedChain(t, dir, "chain-1")

	// Planted-archive forgery: the DB plus the archived genesis key form a
	// self-consistent rotated chain, but the operator's *pinned* published key is
	// an unrelated key the chain never rotates to. Overwrite the published key
	// with a fresh, unrelated Ed25519 key; the genesis archive beside it remains,
	// so resolution still anchors and VerifyChain still passes — only the
	// published-key binding should catch it.
	overwriteWithUnrelatedKey(t, pubKeyPath)

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
	})
	if code != ExitChainBad {
		t.Fatalf("exit = %d, want %d (a chain that does not terminate at the published key must fail); stdout=%s stderr=%s", code, ExitChainBad, stdout, stderr)
	}
	if !strings.Contains(stdout, "does not terminate at the published key") {
		t.Errorf("stdout = %q, expected the published-key binding failure", stdout)
	}
	if strings.Contains(stdout, "VALID") {
		t.Errorf("stdout = %q, a cryptographically-consistent but unpinned chain must not report VALID", stdout)
	}
}

func overwriteWithUnrelatedKey(t *testing.T, pubKeyPath string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRun_HelpFlagExitsCleanly(t *testing.T) {
	code, _, stderr := runOnce(t, []string{"-h"})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (asking for help is not an error)", code, ExitOK)
	}
	// The flag package writes the usage to fs.Output, which we redirected to
	// stderr. Sanity-check it lists at least one of our flags so a refactor
	// that drops the auto-generated usage block trips the test.
	if !strings.Contains(stderr, "--db") && !strings.Contains(stderr, "-db") {
		t.Errorf("stderr should mention --db; got %q", stderr)
	}
}
