package receipt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
)

// v1Alg is the ADR-0012 ciphersuite tag (human-readable, not the numeric triple).
// Maps to RFC 9180: KEM=DHKEM(X25519, HKDF-SHA256) (0x0020), KDF=HKDF-SHA256 (0x0001),
// AEAD=AES-256-GCM (0x0002).
const v1Alg = "hpke-x25519-hkdf-sha256-aes-256-gcm"

// DisclosureRecipient is one entry in the recipients array of a DisclosureEnvelope.
// Field names match RFC 9180 §4.1 vocabulary ("enc", not "encap").
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
type DisclosureRecipient struct {
	KID string `json:"kid"`
	Enc string `json:"enc"` // HPKE encapsulated key; unpadded base64url, exactly 43 chars for X25519
}

// DisclosureEnvelope is the v1 asymmetric encryption envelope for parameters_disclosure
// as specified in ADR-0012 (amendment 2026-05-18). The signed receipt commits to the
// ciphertext; only the holder of the forensic private key can recover the plaintext.
//
// Field ordering here matches JSON marshal order; JCS will sort them alphabetically
// (alg, ct, recipients, v) regardless, so the struct tag order does not affect
// the canonical bytes.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
type DisclosureEnvelope struct {
	V          string                `json:"v"`
	Alg        string                `json:"alg"`
	Recipients []DisclosureRecipient `json:"recipients"`
	CT         string                `json:"ct"` // AEAD ciphertext; unpadded base64url
}

// ForensicKeyPair holds raw X25519 key bytes (32 bytes each) for forensic
// disclosure (ADR-0012). Unlike the Ed25519 KeyPair used for signing, these are
// raw bytes, not PEM-encoded, because X25519 has no standard PKCS8 PEM convention
// in widespread use and raw bytes compose more naturally with HPKE library APIs.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
type ForensicKeyPair struct {
	PublicKey  []byte // 32 bytes; share with emitters so they can encrypt disclosures
	PrivateKey []byte // 32 bytes; keep offline; required to decrypt disclosures
}

// disclosureSuite returns the pinned HPKE suite for v1 envelopes.
func disclosureSuite() hpke.Suite {
	return hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
}

// GenerateForensicKeyPair generates an X25519 key pair for forensic disclosure.
// The public key is shared with emitters; the private key must be kept offline
// (separate from the Ed25519 signing key per ADR-0001 / ADR-0012).
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
func GenerateForensicKeyPair() (ForensicKeyPair, error) {
	suite := disclosureSuite()
	kemID, _, _ := suite.Params()
	pub, priv, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		return ForensicKeyPair{}, fmt.Errorf("generate forensic key pair: %w", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return ForensicKeyPair{}, fmt.Errorf("marshal forensic public key: %w", err)
	}
	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return ForensicKeyPair{}, fmt.Errorf("marshal forensic private key: %w", err)
	}
	return ForensicKeyPair{PublicKey: pubBytes, PrivateKey: privBytes}, nil
}

// EncryptDisclosure encrypts params as a v1 HPKE disclosure envelope
// (ADR-0012, ciphersuite hpke-x25519-hkdf-sha256-aes-256-gcm).
//
// params is JCS-canonicalized before encryption so that cross-SDK decryptors
// and verifiers see the same canonical plaintext bytes.
//
// kid identifies the recipient key (did:key DID URL or sha256:<hex> fingerprint).
// recipientPublicKey is the 32-byte X25519 forensic public key.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
func EncryptDisclosure(params map[string]any, recipientPublicKey []byte, kid string) (*DisclosureEnvelope, error) {
	return encryptWithReader(params, recipientPublicKey, kid, rand.Reader)
}

// encryptDisclosureWithSeed is like EncryptDisclosure but derives the HPKE ephemeral
// key deterministically from ikmE. circl's Sender.Setup reads ikmE from the io.Reader
// and internally applies DHKEM(X25519) DeriveKeyPair (RFC 9180 §4.1) — HKDF over the
// seed — to produce the ephemeral scalar; it does NOT use ikmE directly as the scalar.
// This is confirmed by vector-1: ikmE = RFC 9180 §A.1.1 ikmE produces enc = pkEm from
// that same RFC section, which is X25519(skEm, basepoint) where skEm = DeriveKeyPair(ikmE).
//
// Use only in tests for reproducible cross-SDK vectors. ikmE MUST be 32 bytes.
// Production code MUST use EncryptDisclosure (random ephemeral key per operation).
// Reusing ikmE across real encryptions breaks confidentiality.
func encryptDisclosureWithSeed(params map[string]any, recipientPublicKey []byte, kid string, ikmE []byte) (*DisclosureEnvelope, error) {
	if len(ikmE) != 32 {
		return nil, fmt.Errorf("ikmE must be 32 bytes, got %d", len(ikmE))
	}
	return encryptWithReader(params, recipientPublicKey, kid, bytes.NewReader(ikmE))
}

func encryptWithReader(params map[string]any, recipientPublicKey []byte, kid string, rnd io.Reader) (*DisclosureEnvelope, error) {
	if params == nil {
		return nil, fmt.Errorf("params must not be nil; pass an empty map for no parameters")
	}
	if len(recipientPublicKey) != 32 {
		return nil, fmt.Errorf("recipientPublicKey must be 32 bytes, got %d", len(recipientPublicKey))
	}
	if kid == "" {
		return nil, fmt.Errorf("kid must not be empty")
	}

	suite := disclosureSuite()
	kemID, _, _ := suite.Params()

	pubKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshal recipient public key: %w", err)
	}

	// Canonicalize params (RFC 8785 JCS) before encryption so all SDKs encrypt
	// the same bytes for the same parameters object.
	canonical, err := Canonicalize(params)
	if err != nil {
		return nil, fmt.Errorf("canonicalize disclosure params: %w", err)
	}

	// info = "" and AAD = "" per ADR-0012 amendment §8: no out-of-band context
	// binding at the HPKE layer (the receipt signature already authenticates the
	// parameters_disclosure field).
	sender, err := suite.NewSender(pubKey, []byte{})
	if err != nil {
		return nil, fmt.Errorf("create HPKE sender: %w", err)
	}
	enc, sealer, err := sender.Setup(rnd)
	if err != nil {
		return nil, fmt.Errorf("HPKE sender setup: %w", err)
	}
	ct, err := sealer.Seal([]byte(canonical), []byte{})
	if err != nil {
		return nil, fmt.Errorf("HPKE seal: %w", err)
	}

	return &DisclosureEnvelope{
		V:   "1",
		Alg: v1Alg,
		Recipients: []DisclosureRecipient{{
			KID: kid,
			Enc: base64.RawURLEncoding.EncodeToString(enc),
		}},
		CT: base64.RawURLEncoding.EncodeToString(ct),
	}, nil
}

// DecryptDisclosure recovers the plaintext parameters from a v1 HPKE disclosure
// envelope. recipientPrivateKey is the 32-byte X25519 forensic private key.
// The returned map reflects the JCS-canonical plaintext written by EncryptDisclosure.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
func DecryptDisclosure(env *DisclosureEnvelope, recipientPrivateKey []byte) (map[string]any, error) {
	if env == nil {
		return nil, fmt.Errorf("disclosure envelope must not be nil")
	}
	if env.V != "1" {
		return nil, fmt.Errorf("unsupported envelope version %q", env.V)
	}
	if env.Alg != v1Alg {
		return nil, fmt.Errorf("unsupported algorithm %q", env.Alg)
	}
	if len(env.Recipients) != 1 {
		return nil, fmt.Errorf("v1 envelope must have exactly 1 recipient, got %d", len(env.Recipients))
	}

	suite := disclosureSuite()
	kemID, _, _ := suite.Params()

	if len(recipientPrivateKey) != 32 {
		return nil, fmt.Errorf("recipientPrivateKey must be 32 bytes, got %d", len(recipientPrivateKey))
	}

	privKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshal recipient private key: %w", err)
	}

	enc, err := base64.RawURLEncoding.DecodeString(env.Recipients[0].Enc)
	if err != nil {
		return nil, fmt.Errorf("decode enc: %w", err)
	}
	ct, err := base64.RawURLEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, fmt.Errorf("decode ct: %w", err)
	}

	receiver, err := suite.NewReceiver(privKey, []byte{})
	if err != nil {
		return nil, fmt.Errorf("create HPKE receiver: %w", err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, fmt.Errorf("HPKE receiver setup: %w", err)
	}
	plaintext, err := opener.Open(ct, []byte{})
	if err != nil {
		return nil, fmt.Errorf("HPKE open: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(plaintext, &result); err != nil {
		return nil, fmt.Errorf("unmarshal decrypted params: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("decrypted plaintext is not a JSON object (got null)")
	}
	return result, nil
}
