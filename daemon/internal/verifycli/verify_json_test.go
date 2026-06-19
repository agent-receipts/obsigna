package verifycli

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decodeOutcome parses the --json stdout into a verifyOutcome, failing the test
// if stdout is not a single well-formed JSON object.
func decodeOutcome(t *testing.T, stdout string) verifyOutcome {
	t.Helper()
	var o verifyOutcome
	if err := json.Unmarshal([]byte(stdout), &o); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout=%q", err, stdout)
	}
	return o
}

func TestRun_JSONValidChain(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath := fixtureChain(t, dir, "chain-1", 3)

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
		"--json",
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	// --json must emit machine-readable output only: none of the human verdict
	// strings may leak onto stdout.
	if strings.Contains(stdout, "VALID") {
		t.Errorf("stdout = %q, --json must not emit the human 'VALID' line", stdout)
	}
	o := decodeOutcome(t, stdout)
	if !o.Verified || o.ExitCode != ExitOK {
		t.Errorf("outcome = %+v, want verified with exit_code 0", o)
	}
	if o.ChainID != "chain-1" {
		t.Errorf("chain_id = %q, want chain-1", o.ChainID)
	}
	if o.Length != 3 {
		t.Errorf("length = %d, want 3", o.Length)
	}
	if !strings.HasPrefix(o.Head, "sha256:") {
		t.Errorf("head = %q, want a sha256 chain head", o.Head)
	}
	if o.Advisories == nil {
		t.Error("advisories should serialise as [] for a clean chain, got null")
	}
	if len(o.Advisories) != 0 || o.BrokenAt != nil || o.Anchor != nil || len(o.Receipts) != 0 {
		t.Errorf("clean chain carried failure detail: %+v", o)
	}
}

func TestRun_JSONBrokenChainCarriesFailureDetail(t *testing.T) {
	dir := t.TempDir()
	dbPath, _ := fixtureChain(t, dir, "chain-1", 2)

	// A different public key makes every signature fail to verify.
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
		"--json",
	})
	if code != ExitChainBad {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitChainBad, stderr)
	}
	if strings.Contains(stdout, "BROKEN") {
		t.Errorf("stdout = %q, --json must not emit the human 'BROKEN' line", stdout)
	}
	o := decodeOutcome(t, stdout)
	if o.Verified || o.ExitCode != ExitChainBad {
		t.Errorf("outcome = %+v, want not-verified with exit_code 1", o)
	}
	if o.BrokenAt == nil || *o.BrokenAt != 0 {
		t.Errorf("broken_at = %v, want 0", o.BrokenAt)
	}
	if len(o.Receipts) != 2 {
		t.Fatalf("receipts = %+v, want 2 per-receipt statuses", o.Receipts)
	}
	if o.Receipts[0].Status != "bad_signature" {
		t.Errorf("receipts[0].status = %q, want bad_signature", o.Receipts[0].Status)
	}
	if o.Receipts[0].ReceiptID == "" {
		t.Error("receipts[0].receipt_id is empty")
	}
}

func TestRun_JSONSurfacesAdvisory(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath := fixturePendingTailChain(t, dir, "chain-1", 3)

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
		"--json",
	})
	// The advisory is informational only — it must not change the exit code.
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	o := decodeOutcome(t, stdout)
	if !o.Verified {
		t.Errorf("outcome = %+v, an incomplete-roundtrip chain still verifies", o)
	}
	if len(o.Advisories) != 1 || !strings.Contains(o.Advisories[0], "incomplete tool roundtrip") {
		t.Errorf("advisories = %v, want one incomplete-tool-roundtrip advisory", o.Advisories)
	}
}

func TestRun_JSONAnchorFailureIsStructured(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath := fixtureChain(t, dir, "chain-1", 2)

	// An anchor with no verified checkpoint for this chain (signed by an
	// unrelated key, checkpoints for a different chain) drives the anchor branch
	// to a structured failure without changing the chain's own verdict.
	signer, _ := newAnchorSigner(t)
	anchorPath := writeAnchor(t, signer, cp("other-chain", 1, "sha256:1"))

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
		"--against-anchor", anchorPath,
		"--json",
	})
	if code != ExitChainBad {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitChainBad, stderr)
	}
	o := decodeOutcome(t, stdout)
	if o.Anchor == nil {
		t.Fatalf("outcome carries no anchor block: %+v", o)
	}
	if o.Anchor.Result != "fail" {
		t.Errorf("anchor.result = %q, want fail", o.Anchor.Result)
	}
	if o.Anchor.Reason == "" {
		t.Error("anchor.reason is empty for a failed anchor check")
	}
	if o.Verified {
		t.Error("an anchor failure must not report verified=true")
	}
}
