// Package taxonomy provides tool call classification and the built-in action type registry.
package taxonomy

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

// ActionTypeEntry describes a known action type.
type ActionTypeEntry struct {
	Type        string            `json:"type"`
	Description string            `json:"description"`
	RiskLevel   receipt.RiskLevel `json:"risk_level"`
}

// TaxonomyMapping maps a tool name to an action type.
type TaxonomyMapping struct {
	ToolName   string `json:"tool_name"`
	ActionType string `json:"action_type"`
}

// TaxonomyConfig is the JSON configuration for taxonomy mappings.
type TaxonomyConfig struct {
	Mappings []TaxonomyMapping `json:"mappings"`
}

// ClassificationResult holds the result of classifying a tool call.
type ClassificationResult struct {
	ActionType string            `json:"action_type"`
	RiskLevel  receipt.RiskLevel `json:"risk_level"`
}

// Built-in action types.
var (
	FilesystemActions = []ActionTypeEntry{
		{Type: "filesystem.file.create", Description: "Create a file", RiskLevel: receipt.RiskLow},
		{Type: "filesystem.file.read", Description: "Read a file", RiskLevel: receipt.RiskLow},
		{Type: "filesystem.file.modify", Description: "Modify a file", RiskLevel: receipt.RiskMedium},
		{Type: "filesystem.file.delete", Description: "Delete a file", RiskLevel: receipt.RiskHigh},
		{Type: "filesystem.file.move", Description: "Move or rename a file", RiskLevel: receipt.RiskMedium},
		{Type: "filesystem.directory.create", Description: "Create a directory", RiskLevel: receipt.RiskLow},
		{Type: "filesystem.directory.delete", Description: "Delete a directory", RiskLevel: receipt.RiskHigh},
		{Type: "filesystem.directory.list", Description: "List directory contents", RiskLevel: receipt.RiskLow},
	}

	SystemActions = []ActionTypeEntry{
		{Type: "system.application.launch", Description: "Launch an application", RiskLevel: receipt.RiskLow},
		{Type: "system.application.control", Description: "Control an application via UI automation", RiskLevel: receipt.RiskMedium},
		{Type: "system.settings.modify", Description: "Modify system or app settings", RiskLevel: receipt.RiskHigh},
		{Type: "system.command.execute", Description: "Execute a shell command", RiskLevel: receipt.RiskHigh},
		{Type: "system.code.execute", Description: "Execute code in a sandbox code interpreter", RiskLevel: receipt.RiskHigh},
		{Type: receipt.ActionTypePTYOpen, Description: "Open an interactive PTY session", RiskLevel: receipt.RiskCritical},
		{Type: receipt.ActionTypePTYClose, Description: "Close a PTY session", RiskLevel: receipt.RiskHigh},
		{Type: "system.browser.navigate", Description: "Navigate to a URL", RiskLevel: receipt.RiskLow},
		{Type: "system.browser.form_submit", Description: "Submit a web form", RiskLevel: receipt.RiskMedium},
		{Type: "system.browser.authenticate", Description: "Log into a service", RiskLevel: receipt.RiskHigh},
	}

	DataActions = []ActionTypeEntry{
		{Type: "data.api.read", Description: "Read data from an external API", RiskLevel: receipt.RiskLow},
		{Type: "data.api.write", Description: "Write data to an external API", RiskLevel: receipt.RiskMedium},
		{Type: "data.api.delete", Description: "Delete data via an external API", RiskLevel: receipt.RiskHigh},
	}

	NetworkActions = []ActionTypeEntry{
		{Type: "network.egress.observed", Description: "Observed outbound network connection crossing a sandbox boundary", RiskLevel: receipt.RiskMedium},
	}

	// DiagnosticActions classify daemon/CLI self-checks rather than agent tool
	// calls. They are low risk by construction — the daemon emits them, not an
	// agent — but they land in the real chain like any other event so operators
	// can see (and filter) them.
	DiagnosticActions = []ActionTypeEntry{
		{Type: DiagnosticRoundtripActionType, Description: "agent-receipts doctor synthetic round-trip probe (diagnostic.roundtrip)", RiskLevel: receipt.RiskLow},
	}

	UnknownAction = ActionTypeEntry{
		Type:        "unknown",
		Description: "Tool call that does not map to any known action type",
		RiskLevel:   receipt.RiskMedium,
	}
)

// DiagnosticRoundtripActionType is the action.type the daemon derives for the
// `agent-receipts doctor` synthetic round-trip event. The daemon builds
// action.type structurally as "<channel>.<tool.name>", so the doctor probe's
// channel ("doctor") and tool name ("agent-receipts-doctor.roundtrip") yield
// this value. It is registered as a low-risk built-in so the probe is
// classified rather than falling back to UnknownAction (RiskMedium).
const DiagnosticRoundtripActionType = "doctor.agent-receipts-doctor.roundtrip"

var actionMap map[string]ActionTypeEntry

func init() {
	actionMap = make(map[string]ActionTypeEntry)
	for _, e := range FilesystemActions {
		actionMap[e.Type] = e
	}
	for _, e := range SystemActions {
		actionMap[e.Type] = e
	}
	for _, e := range DataActions {
		actionMap[e.Type] = e
	}
	for _, e := range NetworkActions {
		actionMap[e.Type] = e
	}
	for _, e := range DiagnosticActions {
		actionMap[e.Type] = e
	}
	actionMap[UnknownAction.Type] = UnknownAction
}

// AllActions returns all built-in action type entries.
func AllActions() []ActionTypeEntry {
	out := make([]ActionTypeEntry, 0, len(FilesystemActions)+len(SystemActions)+len(DataActions)+len(NetworkActions)+len(DiagnosticActions)+1)
	out = append(out, FilesystemActions...)
	out = append(out, SystemActions...)
	out = append(out, DataActions...)
	out = append(out, NetworkActions...)
	out = append(out, DiagnosticActions...)
	out = append(out, UnknownAction)
	return out
}

// GetActionType returns the entry for the given type, or nil if unknown.
func GetActionType(actionType string) *ActionTypeEntry {
	e, ok := actionMap[actionType]
	if !ok {
		return nil
	}
	return &e
}

// ResolveActionType returns the entry for the given type, falling back to
// UnknownAction if the type is not in the registry.
func ResolveActionType(actionType string) ActionTypeEntry {
	if e, ok := actionMap[actionType]; ok {
		return e
	}
	return UnknownAction
}

// ClassifyToolCall classifies a tool name into an action type and risk level
// using the provided mappings. If no mapping matches, the result is "unknown".
func ClassifyToolCall(toolName string, mappings []TaxonomyMapping) ClassificationResult {
	actionType := "unknown"
	for _, m := range mappings {
		if m.ToolName == toolName {
			actionType = m.ActionType
			break
		}
	}
	entry := ResolveActionType(actionType)
	return ClassificationResult{
		ActionType: entry.Type,
		RiskLevel:  entry.RiskLevel,
	}
}

// LoadTaxonomyConfig loads taxonomy mappings from a JSON file.
func LoadTaxonomyConfig(path string) ([]TaxonomyMapping, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read taxonomy config: %w", err)
	}

	var config TaxonomyConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse taxonomy config: %w", err)
	}

	seen := make(map[string]bool)
	for _, m := range config.Mappings {
		if m.ToolName == "" || m.ActionType == "" {
			return nil, fmt.Errorf("invalid mapping: tool_name and action_type must be non-empty")
		}
		if seen[m.ToolName] {
			return nil, fmt.Errorf("duplicate mapping for tool_name %q", m.ToolName)
		}
		seen[m.ToolName] = true
	}

	return config.Mappings, nil
}
