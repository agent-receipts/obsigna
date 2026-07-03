// Package did implements did:key v0.7 generation and resolution per
// ADR-0007 (docs/adr/0007-did-method-strategy.md, "Implementation spec —
// did:key v0.7 wire format"). This is the normative wire shape all SDKs and
// the hub re-verifier conform to; do not diverge from the ADR without
// updating it and spec/test-vectors/did-key/vectors.json first.
package did

import (
	"crypto/ed25519"
	"fmt"
	"strings"
)

// prefix is the literal ASCII prefix every did:key identifier begins with:
// the "did:key:" method prefix followed by the "z" multibase prefix
// character for base58btc.
const prefix = "did:key:z"

// multicodecEd25519 is the two-byte unsigned-varint multicodec identifier
// for an Ed25519 public key (0xed 0x01), prepended to the raw key bytes
// before base58btc encoding.
var multicodecEd25519 = [2]byte{0xed, 0x01}

// payloadLen is the decoded payload length: 2-byte multicodec prefix plus
// the 32-byte raw Ed25519 public key (RFC 8032 §5.1.5).
const payloadLen = 2 + ed25519.PublicKeySize

// maxEncodedLen bounds the base58btc-encoded payload length Resolve accepts,
// checked before decoding. A 34-byte payload always encodes to at most 47
// base58btc characters (ceil(34*8 / log2(58))); 64 leaves a generous margin
// while rejecting oversized input before it reaches the decoder, whose
// big-integer multiply-accumulate loop costs O(n^2) in the input length.
const maxEncodedLen = 64

// VerificationMethod is a single entry in a DID Document's
// verificationMethod array.
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// Document is a resolved did:key DID Document, per ADR-0007's "DID Document
// shape". Fields are ordered to match the ADR's worked example; JSON
// encoders are not required to preserve this order since object member
// order is not semantically meaningful, but keeping it stable makes fixture
// diffs readable.
type Document struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string             `json:"authentication"`
	AssertionMethod    []string             `json:"assertionMethod"`
}

// FromPublicKey derives the did:key identifier for an Ed25519 public key:
// did:key:z<base58btc(0xed01 || pubkey)>. Returns an error if pub is not
// exactly 32 bytes.
func FromPublicKey(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("did: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	payload := make([]byte, 0, payloadLen)
	payload = append(payload, multicodecEd25519[:]...)
	payload = append(payload, pub...)
	return prefix + base58btcEncode(payload), nil
}

// Resolve implements the ADR-0007 resolution algorithm: given a did:key
// identifier, decode and validate it, then construct the resolved DID
// Document. Resolution is purely a function of the input string — no
// network access or out-of-band state is consulted.
//
// Resolve rejects any string that does not begin with the literal prefix
// "did:key:z", any base58btc-invalid character, any decoded payload whose
// length is not exactly 34 bytes, and any multicodec other than 0xed01.
func Resolve(id string) (Document, error) {
	if !strings.HasPrefix(id, prefix) {
		return Document{}, fmt.Errorf("did: %q does not have the required %q prefix", id, prefix)
	}

	// zAndPayload is the "z<X>" substring: the multibase prefix character
	// plus the base58btc-encoded payload. It doubles as the verification
	// method fragment and publicKeyMultibase value per the ADR's DID
	// Document shape.
	zAndPayload := id[len("did:key:"):]

	encoded := zAndPayload[1:]
	if len(encoded) > maxEncodedLen {
		return Document{}, fmt.Errorf("did: encoded payload is %d characters, exceeds maximum of %d", len(encoded), maxEncodedLen)
	}

	payload, err := base58btcDecode(encoded)
	if err != nil {
		return Document{}, fmt.Errorf("did: invalid base58btc encoding: %w", err)
	}
	if len(payload) != payloadLen {
		return Document{}, fmt.Errorf("did: decoded payload must be %d bytes, got %d", payloadLen, len(payload))
	}
	if payload[0] != multicodecEd25519[0] || payload[1] != multicodecEd25519[1] {
		return Document{}, fmt.Errorf("did: unsupported multicodec %02x%02x, only ed01 (Ed25519) is accepted", payload[0], payload[1])
	}

	vmID := id + "#" + zAndPayload
	return Document{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/multikey/v1",
		},
		ID: id,
		VerificationMethod: []VerificationMethod{{
			ID:                 vmID,
			Type:               "Multikey",
			Controller:         id,
			PublicKeyMultibase: zAndPayload,
		}},
		Authentication:  []string{vmID},
		AssertionMethod: []string{vmID},
	}, nil
}
