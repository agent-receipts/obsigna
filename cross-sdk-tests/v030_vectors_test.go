//go:build integration

package crosssdk_test

// Test runner for cross-sdk-tests/v030_vectors.json (ADR-0012 envelope,
// ADR-0010 daemon-attested fields). Pins:
//
//   - Schema validation of each v0.3.0 receipt against
//     spec/schema/agent-receipt.schema.json.
//   - Signature verification against the shared Ed25519 test key.
//   - Byte-identical receipt-hash reproduction (Canonicalize + SHA-256 of the
//     unsigned form).
//
// The v0.3.0 receipts carry typed Action fields (parameters_disclosure as the
// HPKE envelope, peer_credential, emitter_metadata) that the Go SDK's
// `receipt.Action` struct does not yet model (PR-C's scope, not PR-B's). The
// tests therefore work on map[string]any / json.RawMessage and use low-level
// crypto/ed25519, mirroring the SDK's canonicalize-then-sign flow.
//
// Gated behind the `integration` build tag for the same reason as the legacy
// canonicalization_vectors tests.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"testing"

	"obsigna.dev/sdk/go/receipt"
)

const v030VectorsPath = "v030_vectors.json"

// v030File matches the layout of v030_vectors.json. Each receipt is kept as
// json.RawMessage so the harness can canonicalize and verify without needing
// a typed Action model for the new envelope / peer_credential / emitter_metadata
// fields.
type v030File struct {
	Comment string `json:"$comment"`
	Version string `json:"version"`
	Keys    struct {
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	} `json:"keys"`
	Envelope struct {
		Description          string          `json:"description"`
		EnvelopeSourceVector string          `json:"envelopeSourceVector"`
		Receipt              json.RawMessage `json:"receipt"`
		ExpectedReceiptHash  string          `json:"expectedReceiptHash"`
		ExpectedValid        bool            `json:"expectedValid"`
	} `json:"parametersDisclosureEnvelopeReceipt"`
	DaemonAttested struct {
		Description         string          `json:"description"`
		Receipt             json.RawMessage `json:"receipt"`
		ExpectedReceiptHash string          `json:"expectedReceiptHash"`
		ExpectedValid       bool            `json:"expectedValid"`
	} `json:"peerCredentialEmitterMetadataReceipt"`
	RootCred struct {
		Description         string          `json:"description"`
		Receipt             json.RawMessage `json:"receipt"`
		ExpectedReceiptHash string          `json:"expectedReceiptHash"`
		ExpectedValid       bool            `json:"expectedValid"`
	} `json:"peerCredentialRootReceipt"`
}

func loadV030(t *testing.T) v030File {
	t.Helper()
	data, err := os.ReadFile(v030VectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", v030VectorsPath, err)
	}
	var f v030File
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse %s: %v", v030VectorsPath, err)
	}
	if f.Version != "0.3.0" {
		t.Fatalf("v030 vectors file version = %q, want 0.3.0", f.Version)
	}
	return f
}

// TestV030VectorsValidateAgainstSchema runs each pinned v0.3.0 receipt
// through the spec schema, locking in that the envelope and daemon-attested
// shapes match the documentation-of-record.
func TestV030VectorsValidateAgainstSchema(t *testing.T) {
	schema := loadSchema(t)
	f := loadV030(t)

	cases := []struct {
		name    string
		receipt json.RawMessage
	}{
		{"parametersDisclosureEnvelopeReceipt", f.Envelope.Receipt},
		{"peerCredentialEmitterMetadataReceipt", f.DaemonAttested.Receipt},
		{"peerCredentialRootReceipt", f.RootCred.Receipt},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var doc any
			if err := json.Unmarshal(c.receipt, &doc); err != nil {
				t.Fatalf("unmarshal receipt: %v", err)
			}
			if err := schema.Validate(doc); err != nil {
				t.Errorf("%s does not validate against agent-receipt.schema.json:\n%v", c.name, err)
			}
		})
	}
}

// TestV030ReceiptHashAndSignature verifies that each v0.3.0 receipt's
// signature still verifies and its receipt hash reproduces the pinned
// expectedReceiptHash byte-for-byte. Both are computed via the SDK's
// Canonicalize (so any regression in JCS would show up here cross-cutting all
// three SDKs once they wire in this file).
func TestV030ReceiptHashAndSignature(t *testing.T) {
	f := loadV030(t)

	pub, err := parseEd25519PublicPEMTest(f.Keys.PublicKey)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	cases := []struct {
		name string
		raw  json.RawMessage
		want string
	}{
		{"parametersDisclosureEnvelopeReceipt", f.Envelope.Receipt, f.Envelope.ExpectedReceiptHash},
		{"peerCredentialEmitterMetadataReceipt", f.DaemonAttested.Receipt, f.DaemonAttested.ExpectedReceiptHash},
		{"peerCredentialRootReceipt", f.RootCred.Receipt, f.RootCred.ExpectedReceiptHash},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var asMap map[string]any
			if err := json.Unmarshal(c.raw, &asMap); err != nil {
				t.Fatalf("unmarshal receipt to map: %v", err)
			}
			proofMap, ok := asMap["proof"].(map[string]any)
			if !ok {
				t.Fatal("receipt missing proof")
			}

			// Verify proof.type is the only one the spec permits.
			if pt, _ := proofMap["type"].(string); pt != "Ed25519Signature2020" {
				t.Fatalf("proof.type = %q, want Ed25519Signature2020", pt)
			}
			proofValue, _ := proofMap["proofValue"].(string)
			if len(proofValue) < 2 || proofValue[0] != 'u' {
				t.Fatalf("proof.proofValue %q: missing u multibase prefix", proofValue)
			}
			sig, err := base64.RawURLEncoding.DecodeString(proofValue[1:])
			if err != nil {
				t.Fatalf("decode proofValue: %v", err)
			}
			if len(sig) != ed25519.SignatureSize {
				t.Fatalf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
			}

			// Strip proof; canonicalize the remainder.
			unsigned := make(map[string]any, len(asMap)-1)
			for k, v := range asMap {
				if k == "proof" {
					continue
				}
				unsigned[k] = v
			}
			canonical, err := receipt.Canonicalize(unsigned)
			if err != nil {
				t.Fatalf("canonicalize unsigned: %v", err)
			}

			// Signature must verify against the canonical bytes.
			if !ed25519.Verify(pub, []byte(canonical), sig) {
				t.Errorf("signature does not verify")
			}

			// Hash must equal expectedReceiptHash byte-for-byte.
			h := sha256.Sum256([]byte(canonical))
			got := "sha256:" + hex.EncodeToString(h[:])
			if got != c.want {
				t.Errorf("receipt hash\n  got:  %s\n  want: %s", got, c.want)
			}
		})
	}
}

// parseEd25519PublicPEMTest is duplicated locally so the test does not depend
// on unexported helpers in sdk/go/receipt. It mirrors signing.go's parser.
func parseEd25519PublicPEMTest(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("decode PEM public key: no PEM block found")
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
