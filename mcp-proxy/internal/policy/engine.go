// Package policy implements the YAML-based policy engine for the MCP proxy.
package policy

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Action severity ordering (higher = more restrictive).
var actionSeverity = map[string]int{
	"pass":  0,
	"flag":  1,
	"pause": 2,
	"block": 3,
}

// Rule defines a policy rule.
type Rule struct {
	Name           string   `yaml:"name"`
	Description    string   `yaml:"description"`
	Enabled        bool     `yaml:"enabled"`
	ToolPattern    string   `yaml:"tool_pattern,omitempty"`
	ServerPattern  string   `yaml:"server_pattern,omitempty"`
	OperationTypes []string `yaml:"operation_types,omitempty"`
	MinRiskScore   *int     `yaml:"min_risk_score,omitempty"`
	Action         string   `yaml:"action"` // pass, flag, pause, block
}

// RulesConfig is the top-level YAML structure.
type RulesConfig struct {
	Rules []Rule `yaml:"rules"`
}

// EvalContext holds the context for evaluating a tool call against rules.
type EvalContext struct {
	ToolName      string
	ServerName    string
	OperationType string
	RiskScore     int
}

// Decision is the result of evaluating rules.
type Decision struct {
	Action   string
	RuleName string
	Reason   string
}

// Engine evaluates policy rules against tool calls.
type Engine struct {
	rules []Rule
}

// NewEngine creates a policy engine with the given rules.
// It validates that all rule actions are known and that tool/server patterns
// are well-formed globs; invalid rules are logged and disabled to prevent
// silent misconfiguration.
func NewEngine(rules []Rule) *Engine {
	validated := make([]Rule, len(rules))
	copy(validated, rules)
	for i := range validated {
		if !validated[i].Enabled {
			continue
		}
		if _, ok := actionSeverity[validated[i].Action]; !ok {
			log.Printf("mcp-proxy: policy rule %q has unknown action %q — disabling", validated[i].Name, validated[i].Action)
			validated[i].Enabled = false
			continue
		}
		if pattern, ok := badPattern(validated[i]); ok {
			log.Printf("mcp-proxy: policy rule %q has malformed glob pattern %q — disabling", validated[i].Name, pattern)
			validated[i].Enabled = false
		}
	}
	return &Engine{rules: validated}
}

// badPattern reports whether rule's tool or server pattern is not a valid
// glob, returning the offending pattern.
func badPattern(rule Rule) (string, bool) {
	if rule.ToolPattern != "" {
		if _, err := filepath.Match(rule.ToolPattern, ""); err != nil {
			return rule.ToolPattern, true
		}
	}
	if rule.ServerPattern != "" {
		if _, err := filepath.Match(rule.ServerPattern, ""); err != nil {
			return rule.ServerPattern, true
		}
	}
	return "", false
}

// LoadRules loads policy rules from a YAML file.
func LoadRules(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	var config RulesConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	return config.Rules, nil
}

// Evaluate checks all rules and returns the most restrictive matching action.
func (e *Engine) Evaluate(ctx EvalContext) Decision {
	best := Decision{Action: "pass"}

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		if !matchesRule(rule, ctx) {
			continue
		}
		if actionSeverity[rule.Action] > actionSeverity[best.Action] {
			best = Decision{
				Action:   rule.Action,
				RuleName: rule.Name,
				Reason:   rule.Description,
			}
		}
	}

	return best
}

// HasPauseRules reports whether any enabled rule uses the "pause" action.
// When no pause rules exist, the approval HTTP server is unnecessary.
func (e *Engine) HasPauseRules() bool {
	for _, rule := range e.rules {
		if rule.Enabled && rule.Action == "pause" {
			return true
		}
	}
	return false
}

// Summary describes the loaded ruleset at a glance, for boot-time diagnostics.
type Summary struct {
	TotalRules    int
	EnabledRules  int
	PauseRules    []string
	BlockRules    []string
	FlagRules     []string
	DisabledRules []string
}

// NeedsApprover reports whether at least one enabled rule requires an
// approver to be configured in order to resolve — i.e. any pause rule.
func (s Summary) NeedsApprover() bool {
	return len(s.PauseRules) > 0
}

// Describe returns a structured snapshot of the loaded rules.
func (e *Engine) Describe() Summary {
	s := Summary{TotalRules: len(e.rules)}
	for _, r := range e.rules {
		if !r.Enabled {
			s.DisabledRules = append(s.DisabledRules, r.Name)
			continue
		}
		s.EnabledRules++
		switch r.Action {
		case "pause":
			s.PauseRules = append(s.PauseRules, r.Name)
		case "block":
			s.BlockRules = append(s.BlockRules, r.Name)
		case "flag":
			s.FlagRules = append(s.FlagRules, r.Name)
		}
	}
	return s
}

func matchesRule(rule Rule, ctx EvalContext) bool {
	if rule.ToolPattern != "" {
		if !globMatch(rule.ToolPattern, ctx.ToolName) {
			return false
		}
	}
	if rule.ServerPattern != "" {
		if !globMatch(rule.ServerPattern, ctx.ServerName) {
			return false
		}
	}
	if len(rule.OperationTypes) > 0 {
		found := false
		for _, op := range rule.OperationTypes {
			if op == ctx.OperationType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if rule.MinRiskScore != nil && ctx.RiskScore < *rule.MinRiskScore {
		return false
	}
	return true
}

// globMatch does case-insensitive glob matching via filepath.Match, which
// supports *, ?, and [...] character classes. Patterns are validated at
// engine construction time (see NewEngine/badPattern); a malformed pattern
// here just falls through to a non-match.
func globMatch(pattern, value string) bool {
	pattern = strings.ToLower(pattern)
	value = strings.ToLower(value)
	matched, _ := filepath.Match(pattern, value)
	return matched
}
