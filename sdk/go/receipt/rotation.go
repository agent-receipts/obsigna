package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// algorithmEd25519 is the only signature algorithm the protocol supports
// (ADR-0001). Cross-algorithm rotation (e.g. Ed25519 → ML-DSA) is deferred to
// the algorithm-agility work and is rejected by verifiers until then.
const algorithmEd25519 = "ed25519"

// keyFingerprint returns the ADR-0015 fingerprint of a raw public key: the
// SHA-256 of the raw key bytes, rendered as sha256:<lowercase hex>. The raw
// bytes are the algorithm's canonical encoding (Ed25519: the 32-byte public
// key per RFC 8032 §5.1.5) — never an SPKI/PEM wrapper or a backend handle.
func keyFingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// decodeMultibaseEd25519Key decodes a multibase-"u" base64url string (the
// encoding ADR-0001 uses for proof.proofValue, applied here to raw public-key
// bytes) into a 32-byte Ed25519 public key.
func decodeMultibaseEd25519Key(s string) ([]byte, error) {
	if len(s) == 0 || s[0] != 'u' {
		return nil, fmt.Errorf("expected multibase %q prefix", "u")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s[1:])
	if err != nil {
		return nil, fmt.Errorf("base64url decode: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d key bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return raw, nil
}

// ed25519RawToPEM wraps a raw 32-byte Ed25519 public key in PEM-encoded SPKI,
// the form the signature verifier consumes.
func ed25519RawToPEM(raw []byte) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(raw))
	if err != nil {
		return "", fmt.Errorf("marshal SPKI public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// verifyRotationEvent validates the rotation-event fields of a key_rotated
// receipt against the outgoing (currently active) public key and returns the
// PEM-encoded incoming key that subsequent receipts must verify against.
//
// It implements the field-level checks of the ADR-0015 verifier traversal: the
// constant fields, the supported-algorithm guard, the old-key fingerprint
// consistency check against the outgoing key, and the new-key fingerprint check
// against the inline new_public_key. The rotation receipt's own signature is
// verified separately by the caller (it is signed with the outgoing key, so the
// chain verifier's normal per-receipt check covers it).
func verifyRotationEvent(activeKeyPEM string, kr *KeyRotation) (newKeyPEM string, err error) {
	if kr.EventType != "key_rotated" {
		return "", fmt.Errorf("event_type must be %q, got %q", "key_rotated", kr.EventType)
	}
	if kr.SignedWith != "old" {
		return "", fmt.Errorf("signed_with must be %q, got %q", "old", kr.SignedWith)
	}
	if kr.OldAlgorithm != algorithmEd25519 {
		return "", fmt.Errorf("unsupported old_algorithm %q: only %q is supported", kr.OldAlgorithm, algorithmEd25519)
	}
	if kr.NewAlgorithm != algorithmEd25519 {
		return "", fmt.Errorf("unsupported new_algorithm %q: only %q is supported", kr.NewAlgorithm, algorithmEd25519)
	}

	outRaw, err := parsePublicKey(activeKeyPEM)
	if err != nil {
		return "", fmt.Errorf("parse outgoing key: %w", err)
	}
	if got := keyFingerprint(outRaw); got != kr.OldKeyFingerprint {
		return "", fmt.Errorf("old_key_fingerprint mismatch: outgoing key is %s, field says %s", got, kr.OldKeyFingerprint)
	}

	newRaw, err := decodeMultibaseEd25519Key(kr.NewPublicKey)
	if err != nil {
		return "", fmt.Errorf("decode new_public_key: %w", err)
	}
	if got := keyFingerprint(newRaw); got != kr.NewKeyFingerprint {
		return "", fmt.Errorf("new_key_fingerprint mismatch: new_public_key hashes to %s, field says %s", got, kr.NewKeyFingerprint)
	}

	newKeyPEM, err = ed25519RawToPEM(newRaw)
	if err != nil {
		return "", fmt.Errorf("encode incoming key: %w", err)
	}
	return newKeyPEM, nil
}
