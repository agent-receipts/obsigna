//go:build integration

package crosssdk_test

// Test runner for cross-sdk-tests/v050_vectors.json (issuer.runtime open
// sub-object, spec §4.3.1 / ADR-0026). Pins:
//
//   - Schema validation of each v0.5.0 receipt against
//     spec/schema/agent-receipt.schema.json (issuer.runtime + context v2).
//   - Signature verification + byte-identical receipt-hash reproduction for the
//     sub-agent receipt carrying issuer.runtime and the root-agent receipt that
//     omits it.
//   - The Go SDK round-trips issuer.runtime.agent_id / agent_type.
//
// Gated behind the `integration` build tag like the other vector runners.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"obsigna.dev/sdk/go/receipt"
)

const v050VectorsPath = "v050_vectors.json"

type v050ReceiptSection struct {
	Description         string          `json:"description"`
	Receipt             json.RawMessage `json:"receipt"`
	ExpectedReceiptHash string          `json:"expectedReceiptHash"`
	ExpectedValid       bool            `json:"expectedValid"`
}

type v050File struct {
	Comment string `json:"$comment"`
	Version string `json:"version"`
	Keys    struct {
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	} `json:"keys"`
	Runtime   v050ReceiptSection `json:"runtimeReceipt"`
	Extended  v050ReceiptSection `json:"extendedRuntimeReceipt"`
	RootAgent v050ReceiptSection `json:"rootAgentReceipt"`
}

func loadV050(t *testing.T) v050File {
	t.Helper()
	data, err := os.ReadFile(v050VectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", v050VectorsPath, err)
	}
	var f v050File
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse %s: %v", v050VectorsPath, err)
	}
	if f.Version != "0.5.0" {
		t.Fatalf("v050 vectors file version = %q, want 0.5.0", f.Version)
	}
	return f
}

// TestV050VectorsValidateAgainstSchema runs each pinned v0.5.0 receipt through
// the spec schema, locking in that issuer.runtime and context v2 validate.
func TestV050VectorsValidateAgainstSchema(t *testing.T) {
	schema := loadSchema(t)
	f := loadV050(t)

	for _, sec := range []v050ReceiptSection{f.Runtime, f.Extended, f.RootAgent} {
		var doc any
		if err := json.Unmarshal(sec.Receipt, &doc); err != nil {
			t.Fatalf("unmarshal %q: %v", sec.Description, err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("%q does not validate against agent-receipt.schema.json:\n%v", sec.Description, err)
		}
	}
}

// TestV050ReceiptHashAndSignature verifies the signature and byte-identical
// receipt hash of both the runtime-bearing and root-agent receipts.
func TestV050ReceiptHashAndSignature(t *testing.T) {
	f := loadV050(t)

	pub, err := receipt.ParsePublicKey(f.Keys.PublicKey)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	for _, sec := range []v050ReceiptSection{f.Runtime, f.Extended, f.RootAgent} {
		var asMap map[string]any
		if err := json.Unmarshal(sec.Receipt, &asMap); err != nil {
			t.Fatalf("%q: unmarshal receipt to map: %v", sec.Description, err)
		}
		proofMap, ok := asMap["proof"].(map[string]any)
		if !ok {
			t.Fatalf("%q: receipt missing proof", sec.Description)
		}
		proofValue, _ := proofMap["proofValue"].(string)
		if len(proofValue) < 2 || proofValue[0] != 'u' {
			t.Fatalf("%q: proof.proofValue %q missing u multibase prefix", sec.Description, proofValue)
		}
		sig, err := base64.RawURLEncoding.DecodeString(proofValue[1:])
		if err != nil {
			t.Fatalf("%q: decode proofValue: %v", sec.Description, err)
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
			t.Fatalf("%q: canonicalize unsigned: %v", sec.Description, err)
		}
		if !ed25519.Verify(pub, []byte(canonical), sig) {
			t.Errorf("%q: signature does not verify", sec.Description)
		}
		h := sha256.Sum256([]byte(canonical))
		got := "sha256:" + hex.EncodeToString(h[:])
		if got != sec.ExpectedReceiptHash {
			t.Errorf("%q: receipt hash\n  got:  %s\n  want: %s", sec.Description, got, sec.ExpectedReceiptHash)
		}
	}
}

// TestV050RuntimeRoundTrips confirms the Go SDK reads issuer.runtime members
// from the runtime-bearing receipt and that the root-agent receipt has no
// runtime.
func TestV050RuntimeRoundTrips(t *testing.T) {
	f := loadV050(t)

	var runtimeReceipt receipt.AgentReceipt
	if err := json.Unmarshal(f.Runtime.Receipt, &runtimeReceipt); err != nil {
		t.Fatalf("unmarshal runtime receipt: %v", err)
	}
	rt := runtimeReceipt.Issuer.Runtime
	if rt == nil {
		t.Fatal("runtime receipt issuer.runtime is nil, want populated")
	}
	if rt.AgentID != "a3e49db54342a92d4" {
		t.Errorf("runtime.agent_id = %q, want a3e49db54342a92d4", rt.AgentID)
	}
	if rt.AgentType != "general-purpose" {
		t.Errorf("runtime.agent_type = %q, want general-purpose", rt.AgentType)
	}

	var rootReceipt receipt.AgentReceipt
	if err := json.Unmarshal(f.RootAgent.Receipt, &rootReceipt); err != nil {
		t.Fatalf("unmarshal root receipt: %v", err)
	}
	if rootReceipt.Issuer.Runtime != nil {
		t.Errorf("root receipt issuer.runtime = %+v, want nil", rootReceipt.Issuer.Runtime)
	}
}

// TestV050ExtendedRuntimePreservedThroughStruct is the open-container gate: a
// runtime key the Go SDK does not model (trace_id) MUST survive a round-trip
// through the typed AgentReceipt struct and still hash to the pinned digest.
// HashReceipt re-marshals the struct (it does not hash raw bytes), so this
// fails if Runtime drops unknown keys — exactly the cross-SDK divergence the
// Extra field exists to prevent.
func TestV050ExtendedRuntimePreservedThroughStruct(t *testing.T) {
	f := loadV050(t)

	var r receipt.AgentReceipt
	if err := json.Unmarshal(f.Extended.Receipt, &r); err != nil {
		t.Fatalf("unmarshal extended receipt: %v", err)
	}
	if r.Issuer.Runtime == nil {
		t.Fatal("extended receipt issuer.runtime is nil, want populated")
	}
	raw, ok := r.Issuer.Runtime.Extra["trace_id"]
	if !ok {
		t.Fatalf("issuer.runtime.Extra missing trace_id; Extra = %v", r.Issuer.Runtime.Extra)
	}
	var traceID string
	if err := json.Unmarshal(raw, &traceID); err != nil {
		t.Fatalf("decode trace_id: %v", err)
	}
	if traceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("trace_id = %q, want 4bf92f3577b34da6a3ce929d0e0e4736", traceID)
	}

	// The struct round-trip (unmarshal → HashReceipt re-marshal) must reproduce
	// the pinned hash, proving trace_id was not dropped.
	got, err := receipt.HashReceipt(r)
	if err != nil {
		t.Fatalf("hash extended receipt: %v", err)
	}
	if got != f.Extended.ExpectedReceiptHash {
		t.Errorf("extended receipt struct round-trip hash\n  got:  %s\n  want: %s", got, f.Extended.ExpectedReceiptHash)
	}
}
