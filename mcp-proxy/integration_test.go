//go:build integration

package integration_test

import (
	"testing"

	"obsigna.dev/mcp-proxy/internal/audit"
	"obsigna.dev/mcp-proxy/internal/policy"
	"obsigna.dev/sdk/go/taxonomy"
)

// TestToolClassificationFallback verifies that prefix-based classification
// provides the correct action type when no taxonomy mapping exists.
// Receipts are emitted to the daemon (ADR-0010); this test exercises the
// classification logic the proxy uses when building the emitter event.
func TestToolClassificationFallback(t *testing.T) {
	toolName := "list_issues"

	// Taxonomy has no mapping for list_issues → falls back to ClassifyOperation.
	classification := taxonomy.ClassifyToolCall(toolName, nil)
	if classification.ActionType != "unknown" {
		t.Errorf("expected 'unknown' from taxonomy for unmapped tool, got %q", classification.ActionType)
	}

	opType := audit.ClassifyOperation(toolName)
	if opType != "read" {
		t.Errorf("expected prefix fallback to 'read' for list_issues, got %q", opType)
	}
}

// TestPolicyWithRiskScoring exercises the combined classify + score + evaluate
// pipeline that the proxy runs before forwarding events to the daemon. Persistence
// and redaction live in the daemon now (see daemon/internal/pipeline) and are
// covered by daemon tests, not here.
func TestPolicyWithRiskScoring(t *testing.T) {
	engine := policy.NewEngine(policy.DefaultRules())

	tests := []struct {
		tool       string
		args       map[string]any
		wantAction string
	}{
		{"read_file", nil, "pass"},
		{"delete_secrets", nil, "block"},
		{"send_message", nil, "flag"},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			opType := audit.ClassifyOperation(tt.tool)
			riskScore, _ := audit.ScoreRisk(tt.tool, tt.args)

			decision := engine.Evaluate(policy.EvalContext{
				ToolName:      tt.tool,
				ServerName:    "test-server",
				OperationType: opType,
				RiskScore:     riskScore,
			})

			if decision.Action != tt.wantAction {
				t.Errorf("tool %q: expected action %q, got %q (opType=%s, risk=%d, rule=%s)",
					tt.tool, tt.wantAction, decision.Action, opType, riskScore, decision.RuleName)
			}
		})
	}
}
