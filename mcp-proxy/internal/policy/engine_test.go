package policy

import "testing"

func TestEvaluatePass(t *testing.T) {
	engine := NewEngine(DefaultRules())
	d := engine.Evaluate(EvalContext{
		ToolName:      "read_file",
		ServerName:    "filesystem",
		OperationType: "read",
		RiskScore:     0,
	})
	if d.Action != "pass" {
		t.Errorf("expected pass, got %s", d.Action)
	}
}

func TestEvaluateBlock(t *testing.T) {
	engine := NewEngine(DefaultRules())
	d := engine.Evaluate(EvalContext{
		ToolName:      "delete_secrets",
		ServerName:    "vault",
		OperationType: "delete",
		RiskScore:     80,
	})
	if d.Action != "block" {
		t.Errorf("expected block, got %s (rule: %s)", d.Action, d.RuleName)
	}
}

func TestEvaluatePause(t *testing.T) {
	engine := NewEngine(DefaultRules())
	d := engine.Evaluate(EvalContext{
		ToolName:      "update_auth_config",
		ServerName:    "settings",
		OperationType: "write",
		RiskScore:     60,
	})
	if d.Action != "pause" {
		t.Errorf("expected pause, got %s (rule: %s)", d.Action, d.RuleName)
	}
}

func TestEvaluateFlag(t *testing.T) {
	engine := NewEngine(DefaultRules())
	d := engine.Evaluate(EvalContext{
		ToolName:      "send_message",
		ServerName:    "slack",
		OperationType: "write",
		RiskScore:     20,
	})
	if d.Action != "flag" {
		t.Errorf("expected flag, got %s (rule: %s)", d.Action, d.RuleName)
	}
}

func TestMostRestrictiveWins(t *testing.T) {
	risk30 := 30
	rules := []Rule{
		{Name: "flag_all", Enabled: true, Action: "flag"},
		{Name: "pause_risky", Enabled: true, MinRiskScore: &risk30, Action: "pause"},
	}
	engine := NewEngine(rules)
	d := engine.Evaluate(EvalContext{RiskScore: 50})
	if d.Action != "pause" {
		t.Errorf("expected pause (most restrictive), got %s", d.Action)
	}
}

func TestEmptyRulesPass(t *testing.T) {
	engine := NewEngine([]Rule{})
	d := engine.Evaluate(EvalContext{
		ToolName:  "anything",
		RiskScore: 100,
	})
	if d.Action != "pass" {
		t.Errorf("expected pass with no rules, got %s", d.Action)
	}
}

func TestCombinedToolPatternAndRiskScore(t *testing.T) {
	risk40 := 40
	rules := []Rule{
		{
			Name:         "block_dangerous_delete",
			Enabled:      true,
			ToolPattern:  "delete_*",
			MinRiskScore: &risk40,
			Action:       "block",
		},
	}
	engine := NewEngine(rules)

	// Matches both tool pattern and risk score — should block.
	d := engine.Evaluate(EvalContext{ToolName: "delete_files", RiskScore: 50})
	if d.Action != "block" {
		t.Errorf("expected block, got %s", d.Action)
	}

	// Matches tool pattern but NOT risk score — should pass.
	d = engine.Evaluate(EvalContext{ToolName: "delete_files", RiskScore: 30})
	if d.Action != "pass" {
		t.Errorf("expected pass (risk below threshold), got %s", d.Action)
	}

	// Matches risk score but NOT tool pattern — should pass.
	d = engine.Evaluate(EvalContext{ToolName: "read_file", RiskScore: 50})
	if d.Action != "pass" {
		t.Errorf("expected pass (tool pattern mismatch), got %s", d.Action)
	}
}

func TestDisabledRulesSkipped(t *testing.T) {
	rules := []Rule{
		{Name: "block_all", Enabled: false, Action: "block"},
	}
	engine := NewEngine(rules)
	d := engine.Evaluate(EvalContext{})
	if d.Action != "pass" {
		t.Errorf("expected pass (rule disabled), got %s", d.Action)
	}
}

func TestDescribe(t *testing.T) {
	rules := DefaultRules()
	engine := NewEngine(rules)
	s := engine.Describe()

	wantTotal := len(rules)
	wantEnabled := 0
	for _, r := range rules {
		if r.Enabled {
			wantEnabled++
		}
	}

	if s.TotalRules != wantTotal {
		t.Errorf("expected %d total rules, got %d", wantTotal, s.TotalRules)
	}
	if s.EnabledRules != wantEnabled {
		t.Errorf("expected %d enabled rules, got %d", wantEnabled, s.EnabledRules)
	}

	wantPause := "pause_high_risk"
	found := false
	for _, r := range s.PauseRules {
		if r == wantPause {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected pause rule %q in Describe().PauseRules, got %v", wantPause, s.PauseRules)
	}

	if !s.NeedsApprover() {
		t.Error("expected Summary.NeedsApprover() to be true when pause rules exist")
	}
}

func TestDescribeEmpty(t *testing.T) {
	engine := NewEngine([]Rule{})
	s := engine.Describe()
	if s.TotalRules != 0 || s.EnabledRules != 0 {
		t.Errorf("expected empty summary, got %+v", s)
	}
	if s.NeedsApprover() {
		t.Error("expected NeedsApprover=false with no rules")
	}
}

func TestDescribeDisabled(t *testing.T) {
	engine := NewEngine([]Rule{
		{Name: "off_pause", Enabled: false, Action: "pause"},
		{Name: "on_flag", Enabled: true, Action: "flag"},
	})
	s := engine.Describe()
	if s.EnabledRules != 1 {
		t.Errorf("expected 1 enabled rule, got %d", s.EnabledRules)
	}
	if len(s.PauseRules) != 0 {
		t.Errorf("expected no pause rules (disabled), got %v", s.PauseRules)
	}
	if len(s.DisabledRules) != 1 || s.DisabledRules[0] != "off_pause" {
		t.Errorf("expected [off_pause] in DisabledRules, got %v", s.DisabledRules)
	}
}

func TestMalformedToolPatternDisablesRule(t *testing.T) {
	rules := []Rule{
		{Name: "bad_tool_pattern", Enabled: true, ToolPattern: "delete[*", Action: "block"},
	}
	engine := NewEngine(rules)
	if engine.rules[0].Enabled {
		t.Error("expected rule with malformed tool pattern to be disabled")
	}
	d := engine.Evaluate(EvalContext{ToolName: "delete_secrets"})
	if d.Action != "pass" {
		t.Errorf("expected pass (rule disabled), got %s", d.Action)
	}
}

func TestMalformedServerPatternDisablesRule(t *testing.T) {
	rules := []Rule{
		{Name: "bad_server_pattern", Enabled: true, ServerPattern: "[a-", Action: "block"},
	}
	engine := NewEngine(rules)
	if engine.rules[0].Enabled {
		t.Error("expected rule with malformed server pattern to be disabled")
	}
}

func TestWellFormedPatternsStayEnabled(t *testing.T) {
	rules := []Rule{
		{Name: "ok", Enabled: true, ToolPattern: "delete_*", ServerPattern: "vault?", Action: "block"},
	}
	engine := NewEngine(rules)
	if !engine.rules[0].Enabled {
		t.Error("expected rule with well-formed patterns to remain enabled")
	}
}

func TestDisabledRuleWithBadPatternNotValidated(t *testing.T) {
	// A rule that's already disabled shouldn't trigger the malformed-pattern
	// log/disable path; it's simply skipped.
	rules := []Rule{
		{Name: "off_bad_pattern", Enabled: false, ToolPattern: "rm[[", Action: "block"},
	}
	engine := NewEngine(rules)
	if engine.rules[0].Enabled {
		t.Error("expected already-disabled rule to remain disabled")
	}
}

func TestHasPauseRules(t *testing.T) {
	// Default rules include pause_high_risk.
	engine := NewEngine(DefaultRules())
	if !engine.HasPauseRules() {
		t.Error("expected HasPauseRules=true for default rules")
	}

	// Flag-only rules should not require the approval server.
	engine = NewEngine([]Rule{
		{Name: "flag_only", Enabled: true, Action: "flag"},
	})
	if engine.HasPauseRules() {
		t.Error("expected HasPauseRules=false for flag-only rules")
	}

	// Empty rules.
	engine = NewEngine([]Rule{})
	if engine.HasPauseRules() {
		t.Error("expected HasPauseRules=false for empty rules")
	}

	// Disabled pause rule should not count.
	engine = NewEngine([]Rule{
		{Name: "disabled_pause", Enabled: false, Action: "pause"},
	})
	if engine.HasPauseRules() {
		t.Error("expected HasPauseRules=false when pause rule is disabled")
	}
}
