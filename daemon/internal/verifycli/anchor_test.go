package verifycli

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-receipts/ar/daemon/internal/anchor"
	"github.com/agent-receipts/ar/daemon/internal/checkpoint"
)

type anchorTestSigner struct {
	priv ed25519.PrivateKey
}

func (s anchorTestSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }
func (s anchorTestSigner) VerificationMethod() string      { return "did:test#k1" }

func newAnchorSigner(t *testing.T) (anchorTestSigner, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return anchorTestSigner{priv: priv}, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// writeAnchor builds a real anchor file (via the shared FileLog format) holding
// the given checkpoints, each signed by signer. Returns the file path.
func writeAnchor(t *testing.T, signer checkpoint.Signer, cps ...checkpoint.Checkpoint) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "anchor.ndjson")
	log, err := anchor.OpenFileLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	for _, cp := range cps {
		signed, err := checkpoint.Sign(cp, signer)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		if err := log.Write(anchor.EventTypeCheckpoint, payload); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func cp(chainID string, seq int64, hash string) checkpoint.Checkpoint {
	return checkpoint.Checkpoint{ChainID: chainID, Sequence: seq, ReceiptHash: hash, Timestamp: "2026-06-16T00:00:00Z"}
}

func TestAnchorPassesWhenHeadMatches(t *testing.T) {
	signer, pub := newAnchorSigner(t)
	path := writeAnchor(t, signer,
		cp("c", 1, "sha256:a"), cp("c", 2, "sha256:b"), cp("c", 3, "sha256:head"))

	got := verifyAgainstAnchor(path, "c", pub, 3, "sha256:head", true)
	if !got.OK {
		t.Fatalf("expected PASS, got fail: %s", got.Reason)
	}
	if got.Checked != 1 {
		t.Errorf("Checked = %d, want 1 (only the latest checkpoint is read)", got.Checked)
	}
}

func TestAnchorDetectsTailTruncation(t *testing.T) {
	signer, pub := newAnchorSigner(t)
	// Anchor witnessed 5 receipts; the store now only has 3 (tail truncated).
	path := writeAnchor(t, signer,
		cp("c", 1, "sha256:1"), cp("c", 2, "sha256:2"), cp("c", 3, "sha256:3"),
		cp("c", 4, "sha256:4"), cp("c", 5, "sha256:5"))

	got := verifyAgainstAnchor(path, "c", pub, 3, "sha256:3", true)
	if got.OK {
		t.Fatal("expected FAIL for a truncated tail, got PASS")
	}
	if !got.Truncated {
		t.Errorf("expected Truncated=true, got reason: %s", got.Reason)
	}
	if !strings.Contains(got.Reason, "truncat") {
		t.Errorf("reason %q does not mention truncation", got.Reason)
	}
}

func TestAnchorDetectsWholeChainGone(t *testing.T) {
	signer, pub := newAnchorSigner(t)
	path := writeAnchor(t, signer, cp("c", 1, "sha256:1"), cp("c", 2, "sha256:2"))

	got := verifyAgainstAnchor(path, "c", pub, 0, "", false)
	if got.OK || !got.Truncated {
		t.Fatalf("expected truncation FAIL when store is empty but anchor has checkpoints; got %+v", got)
	}
}

func TestAnchorDetectsHeadHashTamper(t *testing.T) {
	signer, pub := newAnchorSigner(t)
	path := writeAnchor(t, signer, cp("c", 1, "sha256:1"), cp("c", 2, "sha256:realhead"))

	// Same sequence, different head hash → tamper, not truncation.
	got := verifyAgainstAnchor(path, "c", pub, 2, "sha256:forged", true)
	if got.OK {
		t.Fatal("expected FAIL for head-hash mismatch")
	}
	if got.Truncated {
		t.Error("hash mismatch at equal sequence is tamper, not truncation")
	}
	if !strings.Contains(got.Reason, "mismatch") {
		t.Errorf("reason %q does not mention mismatch", got.Reason)
	}
}

func TestAnchorDetectsStoreAheadOfAnchor(t *testing.T) {
	signer, pub := newAnchorSigner(t)
	path := writeAnchor(t, signer, cp("c", 1, "sha256:1"), cp("c", 2, "sha256:2"))

	got := verifyAgainstAnchor(path, "c", pub, 5, "sha256:5", true)
	if got.OK {
		t.Fatal("expected FAIL when the store head is ahead of the latest checkpoint")
	}
	if got.Truncated {
		t.Error("store-ahead is not a truncation")
	}
}

func TestAnchorRejectsForgedCheckpoint(t *testing.T) {
	signer, _ := newAnchorSigner(t)
	_, otherPub := newAnchorSigner(t) // verify against a DIFFERENT key
	path := writeAnchor(t, signer, cp("c", 1, "sha256:1"))

	got := verifyAgainstAnchor(path, "c", otherPub, 1, "sha256:1", true)
	if got.OK {
		t.Fatal("expected FAIL when checkpoint signature does not verify against the published key")
	}
}

func TestAnchorNoCheckpointForChain(t *testing.T) {
	signer, pub := newAnchorSigner(t)
	path := writeAnchor(t, signer, cp("other-chain", 1, "sha256:1"))

	got := verifyAgainstAnchor(path, "c", pub, 1, "sha256:1", true)
	if got.OK {
		t.Fatal("expected FAIL when no checkpoint exists for the chain")
	}
	if !strings.Contains(got.Reason, "no verified checkpoint") {
		t.Errorf("reason %q unexpected", got.Reason)
	}
}

func TestAnchorRejectsNonMonotonicLog(t *testing.T) {
	signer, pub := newAnchorSigner(t)
	// Duplicate sequence — a corrupted or tampered anchor log.
	path := writeAnchor(t, signer, cp("c", 1, "sha256:1"), cp("c", 1, "sha256:dup"))

	got := verifyAgainstAnchor(path, "c", pub, 1, "sha256:1", true)
	if got.OK {
		t.Fatal("expected FAIL for a non-monotonic checkpoint log")
	}
	if !strings.Contains(got.Reason, "increasing") {
		t.Errorf("reason %q does not flag the ordering problem", got.Reason)
	}
}

func TestAnchorRejectsOutOfOrderLog(t *testing.T) {
	signer, pub := newAnchorSigner(t)
	// seq 2 written before seq 1: the monotonic check runs in anchor FILE ORDER,
	// so this must fail. Sorting first would launder it into 1,2 and pass, hiding
	// a reordered/tampered log — guards against re-introducing a sort.
	path := writeAnchor(t, signer, cp("c", 2, "sha256:2"), cp("c", 1, "sha256:1"))

	got := verifyAgainstAnchor(path, "c", pub, 2, "sha256:2", true)
	if got.OK {
		t.Fatal("expected FAIL for an out-of-order checkpoint log")
	}
	if !strings.Contains(got.Reason, "increasing") {
		t.Errorf("reason %q does not flag the ordering problem", got.Reason)
	}
}
