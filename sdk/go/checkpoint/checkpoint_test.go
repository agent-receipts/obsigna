package checkpoint

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// testSigner is the minimal Signer the package needs, backed by a freshly
// generated test key. Never a real key (AGENTS.md security rule).
type testSigner struct{ priv ed25519.PrivateKey }

func (s testSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }
func (s testSigner) VerificationMethod() string      { return "did:test#k1" }

func newSigner(t *testing.T) (testSigner, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return testSigner{priv: priv}, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func sampleCheckpoint() Checkpoint {
	return Checkpoint{ChainID: "c", Sequence: 3, ReceiptHash: "sha256:head", Timestamp: "2026-06-16T00:00:00Z"}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	signer, pub := newSigner(t)
	signed, err := Sign(sampleCheckpoint(), signer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signed.VerificationMethod != "did:test#k1" {
		t.Errorf("VerificationMethod = %q, want did:test#k1", signed.VerificationMethod)
	}
	if signed.Signature == "" || signed.Signature[0] != multibaseBase64URL[0] {
		t.Errorf("signature %q not multibase base64url (prefix %q)", signed.Signature, multibaseBase64URL)
	}
	ok, err := Verify(signed, pub)
	if err != nil {
		t.Fatalf("Verify returned error on authentic checkpoint: %v", err)
	}
	if !ok {
		t.Fatal("authentic checkpoint did not verify")
	}
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	signer, pub := newSigner(t)
	signed, err := Sign(sampleCheckpoint(), signer)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate a signed field after signing: the wrapper still parses, but the
	// re-canonicalised body no longer matches the signature → (false, nil).
	signed.ReceiptHash = "sha256:forged"
	ok, err := Verify(signed, pub)
	if err != nil {
		t.Fatalf("tampered body should be a clean (false, nil), got err: %v", err)
	}
	if ok {
		t.Fatal("tampered checkpoint verified as authentic")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	signer, _ := newSigner(t)
	_, otherPub := newSigner(t) // verify against a DIFFERENT key
	signed, err := Sign(sampleCheckpoint(), signer)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(signed, otherPub)
	if err != nil {
		t.Fatalf("wrong key should be a clean (false, nil), got err: %v", err)
	}
	if ok {
		t.Fatal("checkpoint verified under the wrong key")
	}
}

func TestVerifyRejectsMalformedSignature(t *testing.T) {
	signer, pub := newSigner(t)
	signed, err := Sign(sampleCheckpoint(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"empty":                  "",
		"single char":            "u",
		"wrong multibase prefix": "z" + signed.Signature[1:],
		"not base64url":          "u!!!not-base64!!!",
		"too short for ed25519":  "u" + signed.Signature[1:5],
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			bad := signed
			bad.Signature = sig
			ok, err := Verify(bad, pub)
			if ok {
				t.Fatal("malformed signature verified as authentic")
			}
			if err == nil {
				t.Fatal("malformed signature should return a non-nil error (could not be evaluated), got (false, nil)")
			}
		})
	}
}

func TestPublicKeyFromPEM(t *testing.T) {
	_, pub := newSigner(t)
	if _, err := PublicKeyFromPEM([]byte(pub)); err != nil {
		t.Fatalf("valid SPKI key rejected: %v", err)
	}
	for name, in := range map[string]string{
		"garbage":          "not a pem block",
		"wrong block type": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		"empty":            "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PublicKeyFromPEM([]byte(in)); err == nil {
				t.Fatalf("expected error for %s key", name)
			}
		})
	}
}

func TestVerifyReportsBadKey(t *testing.T) {
	signer, _ := newSigner(t)
	signed, err := Sign(sampleCheckpoint(), signer)
	if err != nil {
		t.Fatal(err)
	}
	// A signature that parses but a key that does not → error (could not evaluate),
	// distinct from a clean signature-mismatch failure.
	ok, err := Verify(signed, "not-a-key")
	if ok || err == nil {
		t.Fatalf("bad key should return (false, err), got ok=%v err=%v", ok, err)
	}
	if !strings.Contains(err.Error(), "PEM") {
		t.Errorf("error %q does not point at the key parse failure", err)
	}
}
