//go:build integration

package crosssdk_test

// Test runner for cross-sdk-tests/v040_vectors.json (action.idempotency_key,
// spec §7.3.6 / ADR-0019 §S5 / #480). Pins:
//
//   - Schema validation of each v0.4.0 receipt against
//     spec/schema/agent-receipt.schema.json.
//   - Signature verification + byte-identical receipt-hash reproduction for the
//     receipt carrying action.idempotency_key.
//   - The duplicate-idempotency_key chain verifies as valid with exactly one
//     warning (retries are legitimate; spec §7.3.6).
//
// Gated behind the `integration` build tag like the other vector runners.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"obsigna.dev/sdk/go/receipt"
)

const v040VectorsPath = "v040_vectors.json"

type v040File struct {
	Comment string `json:"$comment"`
	Version string `json:"version"`
	Keys    struct {
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	} `json:"keys"`
	Idempotency struct {
		Description         string          `json:"description"`
		IdempotencyKey      string          `json:"idempotencyKey"`
		Receipt             json.RawMessage `json:"receipt"`
		ExpectedReceiptHash string          `json:"expectedReceiptHash"`
		ExpectedValid       bool            `json:"expectedValid"`
	} `json:"idempotencyKeyReceipt"`
	DuplicateChain struct {
		Description          string            `json:"description"`
		DuplicateKey         string            `json:"duplicateKey"`
		Receipts             []json.RawMessage `json:"receipts"`
		ExpectedValid        bool              `json:"expectedValid"`
		ExpectedWarningCount int               `json:"expectedWarningCount"`
	} `json:"duplicateIdempotencyChain"`
}

func loadV040(t *testing.T) v040File {
	t.Helper()
	data, err := os.ReadFile(v040VectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", v040VectorsPath, err)
	}
	var f v040File
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse %s: %v", v040VectorsPath, err)
	}
	if f.Version != "0.4.0" {
		t.Fatalf("v040 vectors file version = %q, want 0.4.0", f.Version)
	}
	return f
}

// TestV040VectorsValidateAgainstSchema runs each pinned v0.4.0 receipt through
// the spec schema, locking in that action.idempotency_key matches the schema.
func TestV040VectorsValidateAgainstSchema(t *testing.T) {
	schema := loadSchema(t)
	f := loadV040(t)

	receipts := []json.RawMessage{f.Idempotency.Receipt}
	receipts = append(receipts, f.DuplicateChain.Receipts...)

	for i, raw := range receipts {
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("unmarshal receipt %d: %v", i, err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("receipt %d does not validate against agent-receipt.schema.json:\n%v", i, err)
		}
	}
}

// TestV040IdempotencyReceiptHashAndSignature verifies the signature and the
// byte-identical receipt hash of the receipt carrying action.idempotency_key.
func TestV040IdempotencyReceiptHashAndSignature(t *testing.T) {
	f := loadV040(t)

	pub, err := receipt.ParsePublicKey(f.Keys.PublicKey)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	var asMap map[string]any
	if err := json.Unmarshal(f.Idempotency.Receipt, &asMap); err != nil {
		t.Fatalf("unmarshal receipt to map: %v", err)
	}
	proofMap, ok := asMap["proof"].(map[string]any)
	if !ok {
		t.Fatal("receipt missing proof")
	}
	proofValue, _ := proofMap["proofValue"].(string)
	if len(proofValue) < 2 || proofValue[0] != 'u' {
		t.Fatalf("proof.proofValue %q: missing u multibase prefix", proofValue)
	}
	sig, err := base64.RawURLEncoding.DecodeString(proofValue[1:])
	if err != nil {
		t.Fatalf("decode proofValue: %v", err)
	}

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
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		t.Errorf("signature does not verify")
	}
	h := sha256.Sum256([]byte(canonical))
	got := "sha256:" + hex.EncodeToString(h[:])
	if got != f.Idempotency.ExpectedReceiptHash {
		t.Errorf("receipt hash\n  got:  %s\n  want: %s", got, f.Idempotency.ExpectedReceiptHash)
	}
}

// TestV040DuplicateChainWarns confirms the shared-idempotency_key chain
// verifies as valid and surfaces exactly one duplicate-key warning naming the
// shared key (spec §7.3.6). This is the cross-SDK contract the TS and Python
// runners assert against the same vector file.
func TestV040DuplicateChainWarns(t *testing.T) {
	f := loadV040(t)

	receipts := make([]receipt.AgentReceipt, 0, len(f.DuplicateChain.Receipts))
	for i, raw := range f.DuplicateChain.Receipts {
		var r receipt.AgentReceipt
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("unmarshal duplicate-chain receipt %d: %v", i, err)
		}
		receipts = append(receipts, r)
	}

	result := receipt.VerifyChain(receipts, f.Keys.PublicKey)
	if result.Valid != f.DuplicateChain.ExpectedValid {
		t.Errorf("chain valid = %v, want %v (broken at %d: %s)", result.Valid, f.DuplicateChain.ExpectedValid, result.BrokenAt, result.Error)
	}
	if len(result.Warnings) != f.DuplicateChain.ExpectedWarningCount {
		t.Fatalf("warning count = %d, want %d: %v", len(result.Warnings), f.DuplicateChain.ExpectedWarningCount, result.Warnings)
	}
	if f.DuplicateChain.ExpectedWarningCount > 0 {
		if !strings.Contains(result.Warnings[0], f.DuplicateChain.DuplicateKey) {
			t.Errorf("warning %q does not name duplicate key %q", result.Warnings[0], f.DuplicateChain.DuplicateKey)
		}
	}
}
