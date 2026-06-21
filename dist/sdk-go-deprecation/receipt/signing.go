package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
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
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
const ProofTypeEd25519Signature2020 = "Ed25519Signature2020"

// GenerateKeyPair generates an Ed25519 key pair and returns PEM-encoded keys.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
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
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
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
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
func Verify(r AgentReceipt, publicKeyPEM string) (bool, error) {
	if r.Proof.Type != ProofTypeEd25519Signature2020 {
		return false, fmt.Errorf("unsupported proof type %q: only %s is accepted", r.Proof.Type, ProofTypeEd25519Signature2020)
	}
	if len(r.Proof.ProofValue) < 2 {
		return false, errors.New("proof value too short")
	}
	if r.Proof.ProofValue[0] != 'u' {
		return false, fmt.Errorf("unsupported multibase prefix: %q", r.Proof.ProofValue[0])
	}

	signature, err := base64.RawURLEncoding.DecodeString(r.Proof.ProofValue[1:])
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
