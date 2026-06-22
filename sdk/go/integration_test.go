//go:build integration

package integration_test

import (
	"testing"

	"obsigna.dev/sdk/go/receipt"
	"obsigna.dev/sdk/go/store"
	"obsigna.dev/sdk/go/taxonomy"
)

func TestReceiptFullLifecycle(t *testing.T) {
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	chainID := "test-chain-lifecycle"
	issuerDID := "did:agent:test"
	principalDID := "did:user:alice"

	mappings := []taxonomy.TaxonomyMapping{
		{ToolName: "read_file", ActionType: "filesystem.file.read"},
		{ToolName: "write_file", ActionType: "filesystem.file.modify"},
		{ToolName: "delete_file", ActionType: "filesystem.file.delete"},
		{ToolName: "run_command", ActionType: "system.command.execute"},
		{ToolName: "navigate", ActionType: "system.browser.navigate"},
	}
	tools := []string{"read_file", "write_file", "delete_file", "run_command", "navigate"}

	var prevHash *string
	for i, toolName := range tools {
		classification := taxonomy.ClassifyToolCall(toolName, mappings)
		if classification.ActionType == "unknown" {
			t.Fatalf("tool %q classified as unknown", toolName)
		}

		unsigned := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: issuerDID},
			Principal: receipt.Principal{ID: principalDID},
			Action: receipt.Action{
				Type:      classification.ActionType,
				RiskLevel: classification.RiskLevel,
			},
			Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
			Chain: receipt.Chain{
				Sequence:            i + 1,
				PreviousReceiptHash: prevHash,
				ChainID:             chainID,
			},
		})

		signed, err := receipt.Sign(unsigned, kp.PrivateKey, issuerDID+"#key-1")
		if err != nil {
			t.Fatalf("sign receipt %d: %v", i, err)
		}

		h, err := receipt.HashReceipt(signed)
		if err != nil {
			t.Fatalf("hash receipt %d: %v", i, err)
		}

		if err := s.Insert(signed, h); err != nil {
			t.Fatalf("store receipt %d: %v", i, err)
		}

		prevHash = &h
	}

	// Retrieve and verify the chain.
	chain, err := s.GetChain(chainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 5 {
		t.Fatalf("expected 5 receipts, got %d", len(chain))
	}

	result := receipt.VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Fatalf("chain verification failed: broken at %d, error: %s", result.BrokenAt, result.Error)
	}

	// Verify via store method.
	storeResult, err := s.VerifyStoredChain(chainID, kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !storeResult.Valid {
		t.Fatalf("store chain verification failed: broken at %d", storeResult.BrokenAt)
	}

	// Check stats.
	stats, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 5 {
		t.Errorf("expected Total=5, got %d", stats.Total)
	}
	if stats.Chains != 1 {
		t.Errorf("expected Chains=1, got %d", stats.Chains)
	}
}

func TestChainTamperDetection(t *testing.T) {
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	chainID := "test-chain-tamper"
	issuerDID := "did:agent:test"

	// Build a 3-receipt chain.
	var prevHash *string
	for i := 0; i < 3; i++ {
		unsigned := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: issuerDID},
			Principal: receipt.Principal{ID: "did:user:bob"},
			Action: receipt.Action{
				Type:      "filesystem.file.read",
				RiskLevel: receipt.RiskLow,
			},
			Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
			Chain: receipt.Chain{
				Sequence:            i + 1,
				PreviousReceiptHash: prevHash,
				ChainID:             chainID,
			},
		})

		signed, err := receipt.Sign(unsigned, kp.PrivateKey, issuerDID+"#key-1")
		if err != nil {
			t.Fatal(err)
		}
		h, err := receipt.HashReceipt(signed)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(signed, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	// Retrieve the chain and tamper with the middle receipt.
	chain, err := s.GetChain(chainID)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper: change the action type of the second receipt.
	chain[1].CredentialSubject.Action.Type = "filesystem.file.delete"

	result := receipt.VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Fatal("expected tampered chain to be invalid")
	}
	// The tampered receipt at index 1 should break signature verification.
	if result.BrokenAt != 1 {
		t.Errorf("expected BrokenAt=1, got %d", result.BrokenAt)
	}

	// Re-retrieve from store (untampered) and verify it's still valid.
	pristine, err := s.GetChain(chainID)
	if err != nil {
		t.Fatal(err)
	}
	pristineResult := receipt.VerifyChain(pristine, kp.PublicKey)
	if !pristineResult.Valid {
		t.Fatalf("pristine chain should be valid, broken at %d", pristineResult.BrokenAt)
	}
}
