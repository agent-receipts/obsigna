package receipt

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RFC 8032 §7.1 well-known test public keys (raw 32-byte Ed25519), reused by
// the spec rotation-event vector. TEST 2 is the outgoing key (signs the
// rotation); TEST 3 is the incoming key.
const (
	rfc8032Test2PubHex = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	rfc8032Test3PubHex = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
)

func mustPEMFromHex(t *testing.T, hexKey string) string {
	t.Helper()
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		t.Fatalf("decode hex key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(raw))
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func loadRotationVector(t *testing.T) AgentReceipt {
	t.Helper()
	path := filepath.Join("..", "..", "..", "spec", "test-vectors", "rotation-event", "example.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rotation vector: %v", err)
	}
	var r AgentReceipt
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("unmarshal rotation vector: %v", err)
	}
	return r
}

// TestRotationVectorVerifies pins the spec rotation-event vector: a
// genesis-position key_rotated receipt signed by the outgoing key must verify,
// and the parsed keyRotation must carry the seven fields.
func TestRotationVectorVerifies(t *testing.T) {
	r := loadRotationVector(t)
	if r.CredentialSubject.KeyRotation == nil {
		t.Fatal("rotation vector did not unmarshal a keyRotation object")
	}
	kr := r.CredentialSubject.KeyRotation
	if kr.EventType != "key_rotated" || kr.SignedWith != "old" {
		t.Fatalf("unexpected rotation constants: event_type=%q signed_with=%q", kr.EventType, kr.SignedWith)
	}

	outgoingPEM := mustPEMFromHex(t, rfc8032Test2PubHex)
	cv := VerifyChain([]AgentReceipt{r}, outgoingPEM)
	if !cv.Valid {
		t.Fatalf("rotation vector failed to verify: brokenAt=%d err=%q", cv.BrokenAt, cv.Error)
	}
}

// TestRotationVectorCanonicalHash cross-checks our canonicalization against the
// value the vector README publishes for the receipt body (proof removed).
func TestRotationVectorCanonicalHash(t *testing.T) {
	r := loadRotationVector(t)
	got, err := HashReceipt(r)
	if err != nil {
		t.Fatalf("hash receipt: %v", err)
	}
	const want = "sha256:6983c9bd6fb24e844b90f7616315a914fdedc5fef8126e11d46149ba2f320457"
	if got != want {
		t.Fatalf("canonical hash mismatch:\n got %s\nwant %s", got, want)
	}
}

// TestVerifyRotationEventBindsIncomingKey checks the field-level rotation
// validation and that the returned PEM is the incoming (TEST 3) key.
func TestVerifyRotationEventBindsIncomingKey(t *testing.T) {
	r := loadRotationVector(t)
	outgoingPEM := mustPEMFromHex(t, rfc8032Test2PubHex)

	newKeyPEM, err := verifyRotationEvent(outgoingPEM, r.CredentialSubject.KeyRotation)
	if err != nil {
		t.Fatalf("verifyRotationEvent: %v", err)
	}
	wantPEM := mustPEMFromHex(t, rfc8032Test3PubHex)
	if newKeyPEM != wantPEM {
		t.Fatalf("incoming key PEM mismatch:\n got %q\nwant %q", newKeyPEM, wantPEM)
	}
}

func TestVerifyRotationEventRejects(t *testing.T) {
	outgoingPEM := mustPEMFromHex(t, rfc8032Test2PubHex)
	base := func() KeyRotation { return *loadRotationVector(t).CredentialSubject.KeyRotation }

	cases := []struct {
		name   string
		mutate func(*KeyRotation)
		want   string
	}{
		{"bad event_type", func(k *KeyRotation) { k.EventType = "rotated" }, "event_type"},
		{"bad signed_with", func(k *KeyRotation) { k.SignedWith = "new" }, "signed_with"},
		{"unsupported old_algorithm", func(k *KeyRotation) { k.OldAlgorithm = "ml-dsa" }, "old_algorithm"},
		{"unsupported new_algorithm", func(k *KeyRotation) { k.NewAlgorithm = "ml-dsa" }, "new_algorithm"},
		{"old fingerprint mismatch", func(k *KeyRotation) { k.OldKeyFingerprint = "sha256:" + strings.Repeat("0", 64) }, "old_key_fingerprint"},
		{"new fingerprint mismatch", func(k *KeyRotation) { k.NewKeyFingerprint = "sha256:" + strings.Repeat("0", 64) }, "new_key_fingerprint"},
		{"new_public_key not multibase", func(k *KeyRotation) { k.NewPublicKey = "z" + k.NewPublicKey[1:] }, "new_public_key"},
		{"new_public_key wrong length", func(k *KeyRotation) { k.NewPublicKey = "uAAAA" }, "new_public_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kr := base()
			tc.mutate(&kr)
			_, err := verifyRotationEvent(outgoingPEM, &kr)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

func multibaseKey(raw []byte) string {
	return "u" + base64.RawURLEncoding.EncodeToString(raw)
}

// rotationChainReceipt0 builds the rotation receipt (seq 1) signed by the
// outgoing key, handing over to the incoming key.
func rotationChainReceipt0(t *testing.T, outKP, inKP KeyPair, withRotation bool) AgentReceipt {
	t.Helper()
	outRaw, _ := parsePublicKey(outKP.PublicKey)
	inRaw, _ := parsePublicKey(inKP.PublicKey)
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "agent.key.rotate", RiskLevel: RiskHigh},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, PreviousReceiptHash: nil, ChainID: "chain_rot"},
	})
	if withRotation {
		unsigned.CredentialSubject.KeyRotation = &KeyRotation{
			EventType:         "key_rotated",
			NewPublicKey:      multibaseKey(inRaw),
			OldKeyFingerprint: keyFingerprint(outRaw),
			NewKeyFingerprint: keyFingerprint(inRaw),
			OldAlgorithm:      "ed25519",
			NewAlgorithm:      "ed25519",
			SignedWith:        "old",
		}
	}
	signed, err := Sign(unsigned, outKP.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatalf("sign rotation receipt: %v", err)
	}
	return signed
}

// TestRotationChainSwitchesKey proves the verifier adopts the incoming key for
// receipts after a rotation: a two-receipt chain whose successor is signed by
// the incoming key verifies under only the outgoing genesis key, precisely
// because the rotation receipt hands the key over.
func TestRotationChainSwitchesKey(t *testing.T) {
	outKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen outgoing: %v", err)
	}
	inKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen incoming: %v", err)
	}

	signed0 := rotationChainReceipt0(t, outKP, inKP, true)
	h0, err := HashReceipt(signed0)
	if err != nil {
		t.Fatalf("hash r0: %v", err)
	}
	r1 := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 2, PreviousReceiptHash: &h0, ChainID: "chain_rot"},
	})
	signed1, err := Sign(r1, inKP.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatalf("sign r1: %v", err)
	}

	cv := VerifyChain([]AgentReceipt{signed0, signed1}, outKP.PublicKey)
	if !cv.Valid {
		t.Fatalf("rotation chain failed: brokenAt=%d err=%q", cv.BrokenAt, cv.Error)
	}

	// Without the rotation handover, the successor signed by the incoming key
	// must fail under the outgoing key alone.
	noRot0 := rotationChainReceipt0(t, outKP, inKP, false)
	h0b, _ := HashReceipt(noRot0)
	r1b := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 2, PreviousReceiptHash: &h0b, ChainID: "chain_rot"},
	})
	noRot1, _ := Sign(r1b, inKP.PrivateKey, "did:agent:test#key-1")
	cv2 := VerifyChain([]AgentReceipt{noRot0, noRot1}, outKP.PublicKey)
	if cv2.Valid {
		t.Fatal("expected chain without rotation handover to fail successor signature, but it verified")
	}
}
