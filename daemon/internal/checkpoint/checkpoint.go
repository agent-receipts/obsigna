// Package checkpoint defines the daemon's out-of-band, additive truncation
// anchor (ADR-0008 follow-through; spike per #600).
//
// A checkpoint is a small Ed25519-signed claim about a chain's HEAD —
// {chain_id, sequence, receipt_hash, timestamp} — emitted to one or more
// append-only sinks the agent UID cannot rewrite. Receipts stay a linear
// verifiable-credential chain; the checkpoint is a SEPARATE signed artifact.
//
// IRREVERSIBLE DESIGN CONSTRAINT (ADR-0008): a checkpoint is additive and
// out-of-band. It does NOT touch the receipt schema, the receipt hash chain,
// @context, or the issuer DID — nothing cryptographically bound into receipts
// carries an anchor reference. Anchoring is out-of-band by design, the same
// rationale as the issuer-DID and /context/v1 freezes. If closing the
// truncation gap ever appears to require an in-receipt anchor field, the
// design is wrong — do not move the freeze.
//
// The truncation-detection mechanism this realises is exactly Option B of
// ADR-0008 §3 ("out-of-band commitment"): the verifier obtains the expected
// head out of band (here, the signed checkpoint) and fails when the observed
// chain does not match. The checkpoint payload is canonicalised through the
// EXISTING RFC 8785 JCS path (receipt.Canonicalize) so a checkpoint signs and
// verifies byte-identically to every other signed artifact in the project.
package checkpoint

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

// multibaseBase64URL mirrors the receipt proof encoding: signatures are
// base64url (multibase prefix "u"), not the W3C default base58btc ("z"). A
// checkpoint signature is therefore decoded the same way a receipt proofValue
// is, so the two cannot drift.
const multibaseBase64URL = "u"

// Checkpoint is the signed claim about a chain HEAD. The four fields are the
// entire signed body; nothing else is canonicalised. Sequence is the head
// receipt's chain sequence and ReceiptHash is its "sha256:<hex>" hash, so a
// verifier can compare both the position and the content of the head it
// observes in the store against the head the daemon last anchored.
type Checkpoint struct {
	ChainID     string `json:"chain_id"`
	Sequence    int64  `json:"sequence"`
	ReceiptHash string `json:"receipt_hash"`
	Timestamp   string `json:"timestamp"`
}

// Signed is a Checkpoint plus its detached signature. It is the artifact
// written to sinks: the embedded Checkpoint fields are the signed body, and
// VerificationMethod/Signature let any reader verify it against the daemon's
// published key without a side channel. The signature covers ONLY the
// Checkpoint body (re-canonicalised on verify), never the wrapper fields —
// identical to how a receipt's proof covers the unsigned receipt, not the
// proof block.
type Signed struct {
	Checkpoint
	VerificationMethod string `json:"verification_method"`
	Signature          string `json:"signature"`
}

// Signer is the minimal signing surface a checkpoint needs. keysource.KeySource
// satisfies it, so checkpoints are signed by the same daemon key as receipts
// without the checkpoint package depending on the daemon's key plumbing.
type Signer interface {
	Sign(message []byte) ([]byte, error)
	VerificationMethod() string
}

// Sign canonicalises cp via the RFC 8785 JCS path and signs it, returning the
// Signed artifact ready to hand to a sink. The signature is the raw 64-byte
// Ed25519 form, multibase base64url-encoded to match receipt proofValues.
func Sign(cp Checkpoint, signer Signer) (Signed, error) {
	canonical, err := receipt.Canonicalize(cp)
	if err != nil {
		return Signed{}, fmt.Errorf("canonicalize checkpoint: %w", err)
	}
	sig, err := signer.Sign([]byte(canonical))
	if err != nil {
		return Signed{}, fmt.Errorf("sign checkpoint: %w", err)
	}
	return Signed{
		Checkpoint:         cp,
		VerificationMethod: signer.VerificationMethod(),
		Signature:          multibaseBase64URL + base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

// Verify checks s's signature against the PEM/SPKI Ed25519 public key. It
// re-canonicalises the embedded Checkpoint body (the wrapper fields are never
// signed) and validates the detached signature. A malformed signature, wrong
// key type, or mismatch returns (false, err) — checkpoint verification failure
// is surfaced, never swallowed.
func Verify(s Signed, publicKeyPEM string) (bool, error) {
	if len(s.Signature) < 2 {
		return false, errors.New("checkpoint signature too short")
	}
	if s.Signature[0] != multibaseBase64URL[0] {
		return false, fmt.Errorf("unsupported multibase prefix %q (want %q)", s.Signature[0], multibaseBase64URL)
	}
	sig, err := base64.RawURLEncoding.DecodeString(s.Signature[1:])
	if err != nil {
		return false, fmt.Errorf("decode checkpoint signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid checkpoint signature length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}
	pub, err := ed25519PublicFromPEM(publicKeyPEM)
	if err != nil {
		return false, err
	}
	canonical, err := receipt.Canonicalize(s.Checkpoint)
	if err != nil {
		return false, fmt.Errorf("canonicalize checkpoint: %w", err)
	}
	return ed25519.Verify(pub, []byte(canonical), sig), nil
}

// ed25519PublicFromPEM decodes PEM/SPKI bytes into an Ed25519 public key,
// rejecting any other key type or malformed input.
func ed25519PublicFromPEM(publicKeyPEM string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("PEM decode failed (no PUBLIC KEY block)")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("PEM block type is %q, want PUBLIC KEY", block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SPKI public key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want ed25519.PublicKey", parsed)
	}
	return pub, nil
}
