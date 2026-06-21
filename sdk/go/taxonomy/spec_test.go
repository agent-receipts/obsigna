//go:build integration

package taxonomy

import (
	"encoding/json"
	"os"
	"testing"

	"obsigna.dev/sdk/go/receipt"
)

type specTaxonomy struct {
	Version string                `json:"version"`
	Domains map[string]specDomain `json:"domains"`
}

type specDomain struct {
	Description string       `json:"description"`
	Actions     []specAction `json:"actions"`
}

type specAction struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	RiskLevel   string `json:"risk_level"`
}

// TestTaxonomyMatchesSpec verifies that the Go SDK's built-in action types
// match the spec's canonical action-types.json for domains that the SDK
// implements (filesystem and system).
func TestTaxonomyMatchesSpec(t *testing.T) {
	data, err := os.ReadFile("../../../spec/spec/taxonomy/action-types.json")
	if err != nil {
		t.Fatalf("read spec taxonomy: %v", err)
	}

	var spec specTaxonomy
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse spec taxonomy: %v", err)
	}

	// The Go SDK implements filesystem and system domains.
	implementedDomains := []string{"filesystem", "system"}

	for _, domainName := range implementedDomains {
		domain, ok := spec.Domains[domainName]
		if !ok {
			t.Fatalf("spec missing domain %q", domainName)
		}

		for _, specAction := range domain.Actions {
			t.Run(specAction.Type, func(t *testing.T) {
				entry := GetActionType(specAction.Type)
				if entry == nil {
					t.Fatalf("Go SDK missing action type %q", specAction.Type)
				}

				if entry.Description != specAction.Description {
					t.Errorf("description mismatch:\n  got:  %s\n  want: %s", entry.Description, specAction.Description)
				}

				if string(entry.RiskLevel) != specAction.RiskLevel {
					t.Errorf("risk_level mismatch: got %s, want %s", entry.RiskLevel, specAction.RiskLevel)
				}
			})
		}
	}
}

// TestAllSDKActionsExistInSpec verifies that every action type the Go SDK
// defines (except "unknown") is present in the spec.
func TestAllSDKActionsExistInSpec(t *testing.T) {
	data, err := os.ReadFile("../../../spec/spec/taxonomy/action-types.json")
	if err != nil {
		t.Fatalf("read spec taxonomy: %v", err)
	}

	var spec specTaxonomy
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse spec taxonomy: %v", err)
	}

	// Build a set of all spec action types.
	specTypes := make(map[string]bool)
	for _, domain := range spec.Domains {
		for _, action := range domain.Actions {
			specTypes[action.Type] = true
		}
	}

	for _, entry := range AllActions() {
		// "unknown" is the SDK's fallback entry, and
		// DiagnosticRoundtripActionType ("doctor.agent-receipts-doctor.roundtrip")
		// classifies a daemon/CLI self-check (the agent-receipts doctor round-trip
		// probe) rather than an agent tool call — neither belongs in the
		// agent-action taxonomy the spec enumerates.
		if entry.Type == "unknown" || entry.Type == DiagnosticRoundtripActionType {
			continue
		}
		if !specTypes[entry.Type] {
			t.Errorf("Go SDK defines %q but it is not in the spec", entry.Type)
		}
	}
}

// TestRiskLevelConsistency verifies that risk levels assigned in the Go SDK
// match those in the spec, catching any accidental divergence.
func TestRiskLevelConsistency(t *testing.T) {
	data, err := os.ReadFile("../../../spec/spec/taxonomy/action-types.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec specTaxonomy
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}

	validRiskLevels := map[receipt.RiskLevel]bool{
		receipt.RiskLow:      true,
		receipt.RiskMedium:   true,
		receipt.RiskHigh:     true,
		receipt.RiskCritical: true,
	}

	for _, domain := range spec.Domains {
		for _, action := range domain.Actions {
			rl := receipt.RiskLevel(action.RiskLevel)
			if !validRiskLevels[rl] {
				t.Errorf("spec action %q has invalid risk_level %q", action.Type, action.RiskLevel)
			}
		}
	}
}
