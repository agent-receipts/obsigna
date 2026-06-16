package checkpoint

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// testSigner is an in-memory Ed25519 signer satisfying Signer, plus the PEM
// public key for Verify. No file or daemon plumbing — keeps the checkpoint
// crypto tests self-contained.
type testSigner struct {
	priv ed25519.PrivateKey
	vm   string
}

func (s testSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }
func (s testSigner) VerificationMethod() string      { return s.vm }

func newTestSigner(t *testing.T) (testSigner, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return testSigner{priv: priv, vm: "did:agent-receipts-daemon:test#k1"}, pubPEM
}

func sampleCheckpoint() Checkpoint {
	return Checkpoint{
		ChainID:     "2026-06-16",
		Sequence:    7,
		ReceiptHash: "sha256:" + "ab12",
		Timestamp:   "2026-06-16T12:00:00Z",
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	signer, pubPEM := newTestSigner(t)
	cp := sampleCheckpoint()

	signed, err := Sign(cp, signer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signed.VerificationMethod != signer.vm {
		t.Errorf("verification method = %q, want %q", signed.VerificationMethod, signer.vm)
	}
	if signed.Signature == "" || signed.Signature[0] != 'u' {
		t.Errorf("signature %q is not multibase base64url", signed.Signature)
	}
	// The wrapper must carry the same body it signed.
	if signed.Checkpoint != cp {
		t.Errorf("signed body = %+v, want %+v", signed.Checkpoint, cp)
	}

	ok, err := Verify(signed, pubPEM)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("Verify returned false for a freshly signed checkpoint")
	}
}

func TestVerifyDetectsBodyTamper(t *testing.T) {
	signer, pubPEM := newTestSigner(t)
	signed, err := Sign(sampleCheckpoint(), signer)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the head the checkpoint commits to: a verifier MUST reject it,
	// because the signature covers the body, not the wrapper.
	signed.ReceiptHash = "sha256:deadbeef"
	ok, err := Verify(signed, pubPEM)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("Verify accepted a checkpoint whose receipt_hash was altered after signing")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	signer, _ := newTestSigner(t)
	_, otherPub := newTestSigner(t)
	signed, err := Sign(sampleCheckpoint(), signer)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(signed, otherPub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("Verify accepted a checkpoint under an unrelated public key")
	}
}

func TestVerifyRejectsMalformedSignature(t *testing.T) {
	_, pubPEM := newTestSigner(t)
	cases := map[string]string{
		"empty":           "",
		"wrong multibase": "zXYZ",
		"bad base64":      "u!!!!",
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			s := Signed{Checkpoint: sampleCheckpoint(), Signature: sig}
			if _, err := Verify(s, pubPEM); err == nil {
				t.Errorf("Verify(%q) returned nil error; want a rejection", sig)
			}
		})
	}
}
