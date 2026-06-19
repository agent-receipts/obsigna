package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// The Agent Receipts spec uses base64url (u) rather than the W3C Data
// Integrity default base58btc (z).
const multibaseBase64URL = "u"

// ProofTypeEd25519Signature2020 is the only proof.type the spec accepts.
// Verifiers MUST reject any other value, even when proofValue happens to be a
// valid Ed25519 signature, so that consumers cannot be tricked into believing
// a receipt was signed under a different scheme.
const ProofTypeEd25519Signature2020 = "Ed25519Signature2020"

// GenerateKeyPair generates an Ed25519 key pair and returns PEM-encoded keys.
func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("generate ed25519 key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return KeyPair{}, fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return KeyPair{}, fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	return KeyPair{
		PublicKey:  string(pubPEM),
		PrivateKey: string(privPEM),
	}, nil
}

// Sign signs an unsigned receipt with an Ed25519 private key (PEM-encoded)
// and returns a complete AgentReceipt with proof.
func Sign(unsigned UnsignedAgentReceipt, privateKeyPEM string, verificationMethod string) (AgentReceipt, error) {
	privKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return AgentReceipt{}, err
	}

	canonical, err := Canonicalize(unsigned)
	if err != nil {
		return AgentReceipt{}, fmt.Errorf("canonicalize for signing: %w", err)
	}

	signature := ed25519.Sign(privKey, []byte(canonical))
	encoded := multibaseBase64URL + base64.RawURLEncoding.EncodeToString(signature)

	now := time.Now().UTC().Format(time.RFC3339)

	return AgentReceipt{
		Context:           unsigned.Context,
		ID:                unsigned.ID,
		Type:              unsigned.Type,
		Version:           unsigned.Version,
		Issuer:            unsigned.Issuer,
		IssuanceDate:      unsigned.IssuanceDate,
		CredentialSubject: unsigned.CredentialSubject,
		Proof: Proof{
			Type:               ProofTypeEd25519Signature2020,
			Created:            now,
			VerificationMethod: verificationMethod,
			ProofPurpose:       "assertionMethod",
			ProofValue:         encoded,
		},
	}, nil
}

// Verify checks the Ed25519 signature on a signed receipt.
//
// Verify canonicalizes a re-marshal of the Go struct, so any field a newer SDK
// added inside the signed payload (e.g. nested under credentialSubject) is
// dropped on the way in and does not contribute to the verified bytes — turning
// a genuinely valid signature into a false negative. When you hold the verbatim
// wire bytes (as a collector or auditor does), prefer VerifyRaw, which is to
// Verify what HashRawReceipt is to HashReceipt.
func Verify(r AgentReceipt, publicKeyPEM string) (bool, error) {
	unsigned := UnsignedAgentReceipt{
		Context:           r.Context,
		ID:                r.ID,
		Type:              r.Type,
		Version:           r.Version,
		Issuer:            r.Issuer,
		IssuanceDate:      r.IssuanceDate,
		CredentialSubject: r.CredentialSubject,
	}
	canonical, err := Canonicalize(unsigned)
	if err != nil {
		return false, fmt.Errorf("canonicalize for verification: %w", err)
	}
	return verifyCanonical(canonical, r.Proof.Type, r.Proof.ProofValue, publicKeyPEM)
}

// VerifyRaw checks the Ed25519 signature on a receipt directly from its on-wire
// JSON bytes, without round-tripping through the Go struct.
//
// This is the verification counterpart to HashRawReceipt: it canonicalizes the
// verbatim wire bytes (minus the proof block), so every field present on the
// wire — including ones the current Go struct does not know about — contributes
// to the verified payload. Sign canonicalizes the whole UnsignedAgentReceipt,
// so a newer SDK that adds and signs over a field nested in the payload produces
// a receipt that VerifyRaw accepts but the struct-based Verify rejects.
//
// The proof block is read from the raw bytes and stripped before
// canonicalization, matching Sign's "unsigned receipt" signing scheme.
//
// Returns an error if rawJSON is not a JSON object, carries no usable proof, or
// the proof encoding is malformed; returns (false, nil) when the signature is
// well-formed but does not verify against publicKeyPEM.
func VerifyRaw(rawJSON []byte, publicKeyPEM string) (bool, error) {
	var generic map[string]any
	if err := json.Unmarshal(rawJSON, &generic); err != nil {
		return false, fmt.Errorf("unmarshal raw receipt: %w", err)
	}
	// json.Unmarshal of "null" into *map sets generic to nil rather than
	// failing — reject explicitly, mirroring HashRawReceipt.
	if generic == nil {
		return false, errors.New("raw receipt is not a JSON object")
	}

	proofType, proofValue, err := rawProof(generic)
	if err != nil {
		return false, err
	}

	delete(generic, "proof")
	canonical, err := Canonicalize(generic)
	if err != nil {
		return false, fmt.Errorf("canonicalize raw receipt: %w", err)
	}

	return verifyCanonical(canonical, proofType, proofValue, publicKeyPEM)
}

// rawProof extracts proof.type and proof.proofValue from a raw receipt's
// generic representation. A missing field yields the empty string, which
// verifyCanonical rejects with the same error a struct receipt would produce.
func rawProof(generic map[string]any) (proofType, proofValue string, err error) {
	proof, ok := generic["proof"].(map[string]any)
	if !ok {
		return "", "", errors.New("raw receipt has no proof object")
	}
	proofType, _ = proof["type"].(string)
	proofValue, _ = proof["proofValue"].(string)
	return proofType, proofValue, nil
}

// verifyCanonical checks an Ed25519 proof over an already-canonicalized payload.
// It is the shared crypto core of Verify and VerifyRaw; the two differ only in
// how they derive the canonical bytes (struct re-marshal vs verbatim wire bytes).
func verifyCanonical(canonical, proofType, proofValue, publicKeyPEM string) (bool, error) {
	if proofType != ProofTypeEd25519Signature2020 {
		return false, fmt.Errorf("unsupported proof type %q: only %s is accepted", proofType, ProofTypeEd25519Signature2020)
	}
	if len(proofValue) < 2 {
		return false, errors.New("proof value too short")
	}
	if proofValue[0] != 'u' {
		return false, fmt.Errorf("unsupported multibase prefix: %q", proofValue[0])
	}

	signature, err := base64.RawURLEncoding.DecodeString(proofValue[1:])
	if err != nil {
		return false, fmt.Errorf("decode proof value: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature length: got %d, want %d", len(signature), ed25519.SignatureSize)
	}

	pubKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return false, err
	}

	return ed25519.Verify(pubKey, []byte(canonical), signature), nil
}

func parsePrivateKey(pemStr string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return edKey, nil
}

func parsePublicKey(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SPKI public key: %w", err)
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return edKey, nil
}
