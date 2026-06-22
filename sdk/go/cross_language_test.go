//go:build integration

package integration_test

import (
	"encoding/json"
	"os"
	"testing"

	"obsigna.dev/sdk/go/receipt"
)

type testVectors struct {
	Keys             vectorKeys             `json:"keys"`
	Canonicalization vectorCanonicalization `json:"canonicalization"`
	Hashing          vectorHashing          `json:"hashing"`
	Signing          vectorSigning          `json:"signing"`
}

type vectorKeys struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

type vectorCanonicalization struct {
	SimpleInput     any    `json:"simpleInput"`
	SimpleExpected  string `json:"simpleExpected"`
	ReceiptInput    any    `json:"receiptInput"`
	ReceiptExpected string `json:"receiptExpected"`
}

type vectorHashing struct {
	SimpleInput     string `json:"simpleInput"`
	SimpleExpected  string `json:"simpleExpected"`
	ReceiptExpected string `json:"receiptExpected"`
}

type vectorSigning struct {
	Unsigned           json.RawMessage `json:"unsigned"`
	Signed             json.RawMessage `json:"signed"`
	VerificationMethod string          `json:"verificationMethod"`
}

func loadVectors(t *testing.T, path string) testVectors {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v testVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

// TestCrossLanguageTSCanonicalization verifies the Go SDK produces the same
// canonical JSON as the TypeScript SDK.
func TestCrossLanguageTSCanonicalization(t *testing.T) {
	v := loadVectors(t, "../../sdk/py/tests/fixtures/ts_vectors.json")

	t.Run("simple_object", func(t *testing.T) {
		got, err := receipt.Canonicalize(v.Canonicalization.SimpleInput)
		if err != nil {
			t.Fatal(err)
		}
		if got != v.Canonicalization.SimpleExpected {
			t.Errorf("got  %s\nwant %s", got, v.Canonicalization.SimpleExpected)
		}
	})

	t.Run("receipt", func(t *testing.T) {
		got, err := receipt.Canonicalize(v.Canonicalization.ReceiptInput)
		if err != nil {
			t.Fatal(err)
		}
		if got != v.Canonicalization.ReceiptExpected {
			t.Errorf("got  %s\nwant %s", got, v.Canonicalization.ReceiptExpected)
		}
	})
}

// TestCrossLanguageTSHashing verifies the Go SDK produces the same SHA-256
// hashes as the TypeScript SDK.
func TestCrossLanguageTSHashing(t *testing.T) {
	v := loadVectors(t, "../../sdk/py/tests/fixtures/ts_vectors.json")

	t.Run("simple_string", func(t *testing.T) {
		got := receipt.SHA256Hash(v.Hashing.SimpleInput)
		if got != v.Hashing.SimpleExpected {
			t.Errorf("got %s, want %s", got, v.Hashing.SimpleExpected)
		}
	})

	t.Run("receipt_hash", func(t *testing.T) {
		var signed receipt.AgentReceipt
		if err := json.Unmarshal(v.Signing.Signed, &signed); err != nil {
			t.Fatal(err)
		}
		got, err := receipt.HashReceipt(signed)
		if err != nil {
			t.Fatal(err)
		}
		if got != v.Hashing.ReceiptExpected {
			t.Errorf("got %s, want %s", got, v.Hashing.ReceiptExpected)
		}
	})
}

// TestCrossLanguageTSSignatureVerifiesInGo verifies that a receipt signed by
// the TypeScript SDK (or regenerated with the shared key) can be verified by Go.
func TestCrossLanguageTSSignatureVerifiesInGo(t *testing.T) {
	v := loadVectors(t, "../../sdk/py/tests/fixtures/ts_vectors.json")

	var signed receipt.AgentReceipt
	if err := json.Unmarshal(v.Signing.Signed, &signed); err != nil {
		t.Fatal(err)
	}

	valid, err := receipt.Verify(signed, v.Keys.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("TS-signed receipt did not verify in Go")
	}
}

// TestCrossLanguageTSSignatureFailsWithWrongKey verifies that a wrong key
// correctly rejects the signature.
func TestCrossLanguageTSSignatureFailsWithWrongKey(t *testing.T) {
	v := loadVectors(t, "../../sdk/py/tests/fixtures/ts_vectors.json")

	var signed receipt.AgentReceipt
	if err := json.Unmarshal(v.Signing.Signed, &signed); err != nil {
		t.Fatal(err)
	}

	otherKP, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	valid, err := receipt.Verify(signed, otherKP.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("signature should not verify with wrong key")
	}
}

// TestCrossLanguageTSSignatureFailsWhenTampered verifies that tampering
// with the receipt invalidates the signature.
func TestCrossLanguageTSSignatureFailsWhenTampered(t *testing.T) {
	v := loadVectors(t, "../../sdk/py/tests/fixtures/ts_vectors.json")

	var signed receipt.AgentReceipt
	if err := json.Unmarshal(v.Signing.Signed, &signed); err != nil {
		t.Fatal(err)
	}

	signed.CredentialSubject.Action.Type = "filesystem.file.delete"

	valid, err := receipt.Verify(signed, v.Keys.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("tampered receipt should not verify")
	}
}

const pyVectorsPath = "../../cross-sdk-tests/py_vectors.json"

// TestCrossLanguagePyCanonicalization verifies Go canonicalization matches
// the Python SDK's canonicalization output.
func TestCrossLanguagePyCanonicalization(t *testing.T) {
	v := loadVectors(t, pyVectorsPath)

	t.Run("simple_object", func(t *testing.T) {
		got, err := receipt.Canonicalize(v.Canonicalization.SimpleInput)
		if err != nil {
			t.Fatal(err)
		}
		if got != v.Canonicalization.SimpleExpected {
			t.Errorf("got  %s\nwant %s", got, v.Canonicalization.SimpleExpected)
		}
	})

	t.Run("receipt", func(t *testing.T) {
		got, err := receipt.Canonicalize(v.Canonicalization.ReceiptInput)
		if err != nil {
			t.Fatal(err)
		}
		if got != v.Canonicalization.ReceiptExpected {
			t.Errorf("got  %s\nwant %s", got, v.Canonicalization.ReceiptExpected)
		}
	})
}

// TestCrossLanguagePyHashing verifies Go SHA-256 hashing matches the Python SDK.
func TestCrossLanguagePyHashing(t *testing.T) {
	v := loadVectors(t, pyVectorsPath)

	t.Run("simple_string", func(t *testing.T) {
		got := receipt.SHA256Hash(v.Hashing.SimpleInput)
		if got != v.Hashing.SimpleExpected {
			t.Errorf("got %s, want %s", got, v.Hashing.SimpleExpected)
		}
	})

	t.Run("receipt_hash", func(t *testing.T) {
		var signed receipt.AgentReceipt
		if err := json.Unmarshal(v.Signing.Signed, &signed); err != nil {
			t.Fatal(err)
		}
		got, err := receipt.HashReceipt(signed)
		if err != nil {
			t.Fatal(err)
		}
		if got != v.Hashing.ReceiptExpected {
			t.Errorf("got %s, want %s", got, v.Hashing.ReceiptExpected)
		}
	})
}

// TestCrossLanguagePySignatureVerifiesInGo verifies a Python-signed receipt
// can be verified by the Go SDK.
func TestCrossLanguagePySignatureVerifiesInGo(t *testing.T) {
	v := loadVectors(t, pyVectorsPath)

	var signed receipt.AgentReceipt
	if err := json.Unmarshal(v.Signing.Signed, &signed); err != nil {
		t.Fatal(err)
	}

	valid, err := receipt.Verify(signed, v.Keys.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("Python-signed receipt did not verify in Go")
	}
}

// TestCrossLanguagePySignatureFailsWithWrongKey verifies wrong-key rejection
// for Python-signed receipts.
func TestCrossLanguagePySignatureFailsWithWrongKey(t *testing.T) {
	v := loadVectors(t, pyVectorsPath)

	var signed receipt.AgentReceipt
	if err := json.Unmarshal(v.Signing.Signed, &signed); err != nil {
		t.Fatal(err)
	}

	otherKP, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	valid, err := receipt.Verify(signed, otherKP.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("signature should not verify with wrong key")
	}
}

// TestCrossLanguagePySignatureFailsWhenTampered verifies tampering with a
// Python-signed receipt invalidates the signature.
func TestCrossLanguagePySignatureFailsWhenTampered(t *testing.T) {
	v := loadVectors(t, pyVectorsPath)

	var signed receipt.AgentReceipt
	if err := json.Unmarshal(v.Signing.Signed, &signed); err != nil {
		t.Fatal(err)
	}

	signed.CredentialSubject.Action.Type = "filesystem.file.delete"

	valid, err := receipt.Verify(signed, v.Keys.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("tampered receipt should not verify")
	}
}

const malformedVectorsPath = "../../cross-sdk-tests/malformed_vectors.json"

type malformedVectorsFile struct {
	Description string             `json:"description"`
	Keys        vectorKeys         `json:"keys"`
	Receipts    []malformedReceipt `json:"receipts"`
	Chains      []malformedChain   `json:"chains"`
}

type malformedReceipt struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Receipt     json.RawMessage `json:"receipt"`
}

type malformedChain struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Receipts    []json.RawMessage `json:"receipts"`
}

func loadMalformed(t *testing.T) malformedVectorsFile {
	t.Helper()
	data, err := os.ReadFile(malformedVectorsPath)
	if err != nil {
		t.Fatalf("read malformed vectors: %v", err)
	}
	var v malformedVectorsFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse malformed vectors: %v", err)
	}
	return v
}

// TestCrossLanguageMalformedReceiptsRejected runs every receipt-level case in
// the shared malformed_vectors.json corpus through Go's Verify and asserts
// that none of them succeed. A new SDK regression that silently accepts a
// mutated receipt would surface here without any per-SDK test churn.
func TestCrossLanguageMalformedReceiptsRejected(t *testing.T) {
	v := loadMalformed(t)
	if len(v.Receipts) == 0 {
		t.Fatal("malformed_vectors.json: no receipt cases found")
	}

	for _, c := range v.Receipts {
		t.Run(c.name(), func(t *testing.T) {
			var r receipt.AgentReceipt
			if err := json.Unmarshal(c.Receipt, &r); err != nil {
				// Some cases may carry shapes pydantic/zod accept but Go
				// rejects at unmarshal time — that still counts as rejection.
				return
			}
			valid, err := receipt.Verify(r, v.Keys.PublicKey)
			if err == nil && valid {
				t.Errorf("Go Verify accepted malformed case %q (%s)", c.Name, c.Description)
			}
		})
	}
}

// name returns a Go-test-safe subtest name.
func (c malformedReceipt) name() string { return c.Name }

// TestCrossLanguageMalformedChainsRejected runs every chain-level case in the
// corpus through VerifyChain and asserts the chain does not validate.
func TestCrossLanguageMalformedChainsRejected(t *testing.T) {
	v := loadMalformed(t)
	if len(v.Chains) == 0 {
		t.Fatal("malformed_vectors.json: no chain cases found")
	}

	for _, c := range v.Chains {
		t.Run(c.Name, func(t *testing.T) {
			receipts := make([]receipt.AgentReceipt, 0, len(c.Receipts))
			for _, raw := range c.Receipts {
				var r receipt.AgentReceipt
				if err := json.Unmarshal(raw, &r); err != nil {
					// A chain entry that Go can't even unmarshal is rejected
					// at the parse layer — that still satisfies the "SDK
					// rejected it" contract, so count it as success and move
					// on to the next case.
					return
				}
				receipts = append(receipts, r)
			}
			result := receipt.VerifyChain(receipts, v.Keys.PublicKey)
			if result.Valid {
				t.Errorf("VerifyChain accepted malformed chain %q (%s)", c.Name, c.Description)
			}
		})
	}
}
