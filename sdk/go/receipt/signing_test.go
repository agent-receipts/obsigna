package receipt

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func TestGenerateKeyPairAndSignVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if kp.PublicKey == "" || kp.PrivateKey == "" {
		t.Fatal("expected non-empty keys")
	}

	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}

	if signed.Proof.Type != "Ed25519Signature2020" {
		t.Errorf("expected Ed25519Signature2020, got %s", signed.Proof.Type)
	}
	if signed.Proof.ProofPurpose != "assertionMethod" {
		t.Errorf("expected assertionMethod, got %s", signed.Proof.ProofPurpose)
	}
	if signed.Proof.ProofValue == "" {
		t.Fatal("expected non-empty proof value")
	}
	if signed.Proof.ProofValue[0] != 'u' {
		t.Errorf("expected multibase prefix 'u', got %c", signed.Proof.ProofValue[0])
	}

	valid, err := Verify(signed, kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("expected signature to be valid")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "unknown", RiskLevel: RiskMedium},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	signed, _ := Sign(unsigned, kp1.PrivateKey, "did:agent:test#key-1")

	valid, err := Verify(signed, kp2.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("expected signature to be invalid with wrong key")
	}
}

func TestSignRejectsEmptyPEM(t *testing.T) {
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	_, err := Sign(unsigned, "", "did:agent:test#key-1")
	if err == nil {
		t.Fatal("expected error for empty PEM key")
	}
}

func TestSignRejectsGarbagePEM(t *testing.T) {
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	_, err := Sign(unsigned, "not-a-pem-string!!!", "did:agent:test#key-1")
	if err == nil {
		t.Fatal("expected error for garbage PEM string")
	}
}

func TestVerifyRejectsWrongProofType(t *testing.T) {
	kp, _ := GenerateKeyPair()
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	// proof.type lives outside the signed bytes, so swapping it here leaves
	// the Ed25519 signature mathematically valid. Verify MUST still reject
	// the receipt — a verifier that ignores proof.type lets attackers swap in
	// a different scheme name and pass off a forged-but-structurally-valid
	// receipt.
	signed.Proof.Type = "RsaSignature2018"

	valid, err := Verify(signed, kp.PublicKey)
	if err == nil {
		t.Error("expected error for wrong proof.type")
	}
	if valid {
		t.Error("expected Verify=false for wrong proof.type")
	}
}

func TestVerifyRejectsEmptyProofValue(t *testing.T) {
	kp, _ := GenerateKeyPair()
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	signed.Proof.ProofValue = ""
	_, err := Verify(signed, kp.PublicKey)
	if err == nil {
		t.Fatal("expected error for empty proof value")
	}
}

func TestVerifyRejectsWrongLengthSignature(t *testing.T) {
	kp, _ := GenerateKeyPair()
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	// Valid base64 but too short (only 10 bytes).
	short := base64.RawURLEncoding.EncodeToString([]byte("tooshort!!"))
	signed.Proof.ProofValue = "u" + short
	_, err := Verify(signed, kp.PublicKey)
	if err == nil {
		t.Fatal("expected error for wrong-length signature")
	}
}

func TestSignRejectsRSAKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	_, err = Sign(unsigned, string(rsaPEM), "did:agent:test#key-1")
	if err == nil {
		t.Fatal("expected error for RSA key")
	}
	if !strings.Contains(err.Error(), "not Ed25519") {
		t.Errorf("expected 'not Ed25519' error, got: %v", err)
	}
}

func TestVerifyRejectsRSAPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	kp, _ := GenerateKeyPair()
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	_, err = Verify(signed, string(rsaPubPEM))
	if err == nil {
		t.Fatal("expected error for RSA public key")
	}
	if !strings.Contains(err.Error(), "not Ed25519") {
		t.Errorf("expected 'not Ed25519' error, got: %v", err)
	}
}

func TestVerifyRejectsTamperedReceipt(t *testing.T) {
	kp, _ := GenerateKeyPair()

	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "unknown", RiskLevel: RiskMedium},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	// Tamper with the receipt.
	signed.CredentialSubject.Action.Type = "filesystem.file.delete"

	valid, err := Verify(signed, kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("expected tampered receipt to fail verification")
	}
}

// signRawPayload signs a generic receipt payload (without a proof block) the
// same way Sign signs an UnsignedAgentReceipt, returning the full receipt bytes
// with the proof spliced in. It lets tests construct receipts whose signed
// payload carries fields the Go struct does not model.
func signRawPayload(t *testing.T, payload map[string]any, privateKeyPEM string) []byte {
	t.Helper()
	priv, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		t.Fatalf("parsePrivateKey: %v", err)
	}
	canonical, err := Canonicalize(payload)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	sig := ed25519.Sign(priv, []byte(canonical))
	payload["proof"] = map[string]any{
		"type":               ProofTypeEd25519Signature2020,
		"created":            "2026-01-01T00:00:00Z",
		"verificationMethod": "did:agent:test#key-1",
		"proofPurpose":       "assertionMethod",
		"proofValue":         multibaseBase64URL + base64.RawURLEncoding.EncodeToString(sig),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return raw
}

func TestVerifyRaw_MatchesVerifyForKnownFields(t *testing.T) {
	// For a receipt whose every field is known to the Go struct, VerifyRaw and
	// Verify operate on identical canonical bytes, so both must accept a valid
	// signature and both must reject a wrong key.
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyRaw(raw, kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("VerifyRaw rejected a validly-signed receipt")
	}

	other, _ := GenerateKeyPair()
	ok, err = VerifyRaw(raw, other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("VerifyRaw accepted a receipt under the wrong key")
	}
}

func TestVerifyRaw_AcceptsForwardCompatNestedField(t *testing.T) {
	// The reason VerifyRaw exists: a newer SDK can add a field nested inside
	// the signed payload (e.g. under credentialSubject) and sign over it. The
	// struct-based Verify drops that field on Unmarshal and false-negatives;
	// VerifyRaw canonicalizes the verbatim wire bytes and accepts the receipt.
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-fc"},
	})

	// Derive the payload from the real struct so field names match the wire
	// exactly, then splice in one field the current struct does not model.
	ub, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(ub, &payload); err != nil {
		t.Fatal(err)
	}
	payload["credentialSubject"].(map[string]any)["_future_nested"] = "v2"

	raw := signRawPayload(t, payload, kp.PrivateKey)

	ok, err := VerifyRaw(raw, kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("VerifyRaw rejected a validly-signed forward-compat receipt")
	}

	// Confirm the divergence is real: the struct path drops the nested field
	// before canonicalizing, so Verify computes different bytes and fails.
	var parsed AgentReceipt
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	structOK, err := Verify(parsed, kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if structOK {
		t.Fatal("expected struct-based Verify to false-negative on the nested field; VerifyRaw would then be redundant")
	}
}

func TestVerifyRaw_RejectsTamperedBytes(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a value inside the signed payload without touching the proof.
	tampered := strings.Replace(string(raw), "filesystem.file.read", "filesystem.file.delete", 1)
	if tampered == string(raw) {
		t.Fatal("tamper splice did not change the bytes")
	}

	ok, err := VerifyRaw([]byte(tampered), kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("VerifyRaw accepted tampered bytes")
	}
}

func TestVerifyRaw_RejectsWrongProofType(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}

	// Swap proof.type in the raw bytes. The Ed25519 signature stays valid, but
	// VerifyRaw must reject any scheme other than Ed25519Signature2020.
	swapped := strings.Replace(string(raw), ProofTypeEd25519Signature2020, "RsaSignature2018", 1)
	if swapped == string(raw) {
		t.Fatal("proof.type splice did not change the bytes")
	}

	ok, err := VerifyRaw([]byte(swapped), kp.PublicKey)
	if err == nil {
		t.Error("expected error for wrong proof.type")
	}
	if ok {
		t.Error("expected VerifyRaw=false for wrong proof.type")
	}
}

func TestVerifyRaw_RejectsMalformedInput(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"non-object array":  `[1,2,3]`,
		"non-object number": `42`,
		"non-object null":   `null`,
		"empty":             ``,
		"no proof block":    `{"id":"urn:r:1","credentialSubject":{"x":1}}`,
		"proof not object":  `{"id":"urn:r:1","proof":"u-AAA"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyRaw([]byte(body), kp.PublicKey); err == nil {
				t.Errorf("VerifyRaw(%q): err=nil, want error", body)
			}
		})
	}
}
