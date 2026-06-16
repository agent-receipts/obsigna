package receipt

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCreateSetsDefaults(t *testing.T) {
	r := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:alice"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	if !strings.HasPrefix(r.ID, "urn:receipt:") {
		t.Errorf("expected urn:receipt: prefix, got %s", r.ID)
	}
	if !strings.HasPrefix(r.CredentialSubject.Action.ID, "act_") {
		t.Errorf("expected act_ prefix, got %s", r.CredentialSubject.Action.ID)
	}
	if r.IssuanceDate == "" {
		t.Error("expected issuance date to be set")
	}
	if r.CredentialSubject.Action.Timestamp == "" {
		t.Error("expected action timestamp to be set")
	}
	if r.Version != Version {
		t.Errorf("expected version %s, got %s", Version, r.Version)
	}
	if len(r.Context) != 2 {
		t.Errorf("expected 2 context entries, got %d", len(r.Context))
	}
	if len(r.Type) != 2 {
		t.Errorf("expected 2 type entries, got %d", len(r.Type))
	}
}

func TestCreateWithZeroValueInputs(t *testing.T) {
	// Empty Issuer.ID and empty Action.Type should not panic.
	r := Create(CreateInput{
		Issuer:    Issuer{ID: ""},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	if r.ID == "" {
		t.Error("expected receipt ID to be generated")
	}
	if r.IssuanceDate == "" {
		t.Error("expected issuance date to be set")
	}
}

func TestCreatePreservesExplicitActionID(t *testing.T) {
	r := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:alice"},
		Action:    Action{ID: "act_custom", Type: "unknown", RiskLevel: RiskMedium, Timestamp: "2024-01-01T00:00:00Z"},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	if r.CredentialSubject.Action.ID != "act_custom" {
		t.Errorf("expected act_custom, got %s", r.CredentialSubject.Action.ID)
	}
	if r.CredentialSubject.Action.Timestamp != "2024-01-01T00:00:00Z" {
		t.Errorf("expected explicit timestamp, got %s", r.CredentialSubject.Action.Timestamp)
	}
}

func TestCreateWithOptionalFields(t *testing.T) {
	truncated := true
	r := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:alice"},
		Action:    Action{Type: "unknown", RiskLevel: RiskMedium},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
		Intent:    &Intent{PromptPreview: "do the thing", PromptPreviewTruncated: &truncated},
		Authorization: &Authorization{
			Scopes:    []string{"read", "write"},
			GrantedAt: "2024-01-01T00:00:00Z",
		},
	})

	if r.CredentialSubject.Intent == nil {
		t.Fatal("expected intent to be set")
	}
	if r.CredentialSubject.Intent.PromptPreview != "do the thing" {
		t.Errorf("unexpected prompt preview: %s", r.CredentialSubject.Intent.PromptPreview)
	}
	if r.CredentialSubject.Authorization == nil {
		t.Fatal("expected authorization to be set")
	}
	if len(r.CredentialSubject.Authorization.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(r.CredentialSubject.Authorization.Scopes))
	}
}

func TestCreatePreservesCorrelationID(t *testing.T) {
	const want = "toolu_01AAAAAAAAAAAAAAAAAAAAAA"
	r := Create(CreateInput{
		Issuer:        Issuer{ID: "did:agent:test"},
		Principal:     Principal{ID: "did:user:alice"},
		Action:        Action{Type: "mcp.tool_call", RiskLevel: RiskLow},
		Outcome:       Outcome{Status: StatusSuccess},
		Chain:         Chain{Sequence: 1, ChainID: "chain-1"},
		CorrelationID: want,
	})
	if got := r.CredentialSubject.CorrelationID; got != want {
		t.Errorf("CorrelationID = %q, want %q", got, want)
	}
}

func TestCreateOmitsEmptyCorrelationID(t *testing.T) {
	r := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:alice"},
		Action:    Action{Type: "mcp.tool_call", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	if r.CredentialSubject.CorrelationID != "" {
		t.Errorf("expected empty CorrelationID, got %q", r.CredentialSubject.CorrelationID)
	}
	// Verify it's absent from the canonical JSON (omitempty).
	canonical, err := Canonicalize(r)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if strings.Contains(canonical, "correlation_id") {
		t.Errorf("canonical JSON contains correlation_id when field is empty: %s", canonical)
	}
}

func TestCreatePreservesDelegation(t *testing.T) {
	del := &Delegation{
		ParentChainID:   "root-chain",
		ParentReceiptID: "urn:receipt:parent-uuid",
		Delegator:       Delegator{ID: "did:agent-receipts-daemon:host"},
	}
	r := Create(CreateInput{
		Issuer:     Issuer{ID: "did:agent:test"},
		Principal:  Principal{ID: "did:user:alice"},
		Action:     Action{Type: "mcp.tool_call", RiskLevel: RiskLow},
		Outcome:    Outcome{Status: StatusSuccess},
		Chain:      Chain{Sequence: 1, ChainID: "root-chain/agent/abc"},
		Delegation: del,
	})
	got := r.CredentialSubject.Delegation
	if got == nil {
		t.Fatal("expected delegation to be set, got nil")
	}
	if got.ParentChainID != del.ParentChainID {
		t.Errorf("ParentChainID = %q, want %q", got.ParentChainID, del.ParentChainID)
	}
	if got.ParentReceiptID != del.ParentReceiptID {
		t.Errorf("ParentReceiptID = %q, want %q", got.ParentReceiptID, del.ParentReceiptID)
	}
	if got.Delegator.ID != del.Delegator.ID {
		t.Errorf("Delegator.ID = %q, want %q", got.Delegator.ID, del.Delegator.ID)
	}
}

func TestCreateOmitsNilDelegation(t *testing.T) {
	r := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:alice"},
		Action:    Action{Type: "mcp.tool_call", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	if r.CredentialSubject.Delegation != nil {
		t.Errorf("expected nil Delegation on root-chain receipt, got %+v", r.CredentialSubject.Delegation)
	}
	// Verify absent from canonical JSON.
	canonical, err := Canonicalize(r)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if strings.Contains(canonical, "delegation") {
		t.Errorf("canonical JSON contains delegation when nil: %s", canonical)
	}
}

func TestCreateReversalOfPreserved(t *testing.T) {
	validURN := "urn:receipt:00000000-0000-0000-0000-000000000001"
	r := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:alice"},
		Action:    Action{Type: "filesystem.file.write", RiskLevel: RiskMedium},
		Outcome:   Outcome{Status: StatusSuccess, ReversalOf: validURN},
		Chain:     Chain{Sequence: 2, ChainID: "chain-1"},
	})

	if r.CredentialSubject.Outcome.ReversalOf != validURN {
		t.Errorf("expected ReversalOf %s, got %s", validURN, r.CredentialSubject.Outcome.ReversalOf)
	}

	// Verify the field serializes to reversal_of in JSON.
	data, err := json.Marshal(r.CredentialSubject.Outcome)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !strings.Contains(string(data), `"reversal_of"`) {
		t.Errorf("expected reversal_of in JSON output, got: %s", data)
	}
}

func TestCreateReversalOfEmptyOmitted(t *testing.T) {
	r := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:alice"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	data, err := json.Marshal(r.CredentialSubject.Outcome)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(data), "reversal_of") {
		t.Errorf("expected reversal_of absent when empty, got: %s", data)
	}
}

func TestCreateReversalOfInvalidPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on invalid ReversalOf, but none occurred")
		}
	}()

	Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:alice"},
		Action:    Action{Type: "filesystem.file.write", RiskLevel: RiskMedium},
		Outcome:   Outcome{Status: StatusSuccess, ReversalOf: "not-a-valid-urn"},
		Chain:     Chain{Sequence: 2, ChainID: "chain-1"},
	})
}
