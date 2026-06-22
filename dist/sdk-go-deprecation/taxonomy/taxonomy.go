// Package taxonomy provides tool call classification and the built-in action type registry.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the
// canonical module obsigna.dev/sdk/go instead (see ADR-0023).
package taxonomy

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/agent-receipts/sdk-go/receipt"
)

// ActionTypeEntry describes a known action type.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
type ActionTypeEntry struct {
	Type        string            `json:"type"`
	Description string            `json:"description"`
	RiskLevel   receipt.RiskLevel `json:"risk_level"`
}

// TaxonomyMapping maps a tool name to an action type.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
type TaxonomyMapping struct {
	ToolName   string `json:"tool_name"`
	ActionType string `json:"action_type"`
}

// TaxonomyConfig is the JSON configuration for taxonomy mappings.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
type TaxonomyConfig struct {
	Mappings []TaxonomyMapping `json:"mappings"`
}

// ClassificationResult holds the result of classifying a tool call.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
type ClassificationResult struct {
	ActionType string            `json:"action_type"`
	RiskLevel  receipt.RiskLevel `json:"risk_level"`
}

// Built-in action types.
var (
	// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
	FilesystemActions = []ActionTypeEntry{
		{Type: "filesystem.file.create", Description: "Create a file", RiskLevel: receipt.RiskLow},
		{Type: "filesystem.file.read", Description: "Read a file", RiskLevel: receipt.RiskLow},
		{Type: "filesystem.file.modify", Description: "Modify a file", RiskLevel: receipt.RiskMedium},
		{Type: "filesystem.file.delete", Description: "Delete a file", RiskLevel: receipt.RiskHigh},
		{Type: "filesystem.file.move", Description: "Move or rename a file", RiskLevel: receipt.RiskMedium},
		{Type: "filesystem.directory.create", Description: "Create a directory", RiskLevel: receipt.RiskLow},
		{Type: "filesystem.directory.delete", Description: "Delete a directory", RiskLevel: receipt.RiskHigh},
	}

	// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
	SystemActions = []ActionTypeEntry{
		{Type: "system.application.launch", Description: "Launch an application", RiskLevel: receipt.RiskLow},
		{Type: "system.application.control", Description: "Control an application via UI automation", RiskLevel: receipt.RiskMedium},
		{Type: "system.settings.modify", Description: "Modify system or app settings", RiskLevel: receipt.RiskHigh},
		{Type: "system.command.execute", Description: "Execute a shell command", RiskLevel: receipt.RiskHigh},
		{Type: "system.browser.navigate", Description: "Navigate to a URL", RiskLevel: receipt.RiskLow},
		{Type: "system.browser.form_submit", Description: "Submit a web form", RiskLevel: receipt.RiskMedium},
		{Type: "system.browser.authenticate", Description: "Log into a service", RiskLevel: receipt.RiskHigh},
	}

	// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
	DataActions = []ActionTypeEntry{
		{Type: "data.api.read", Description: "Read data from an external API", RiskLevel: receipt.RiskLow},
		{Type: "data.api.write", Description: "Write data to an external API", RiskLevel: receipt.RiskMedium},
		{Type: "data.api.delete", Description: "Delete data via an external API", RiskLevel: receipt.RiskHigh},
	}

	// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
	UnknownAction = ActionTypeEntry{
		Type:        "unknown",
		Description: "Tool call that does not map to any known action type",
		RiskLevel:   receipt.RiskMedium,
	}
)

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
	actionMap[UnknownAction.Type] = UnknownAction
}

// AllActions returns all built-in action type entries.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
func AllActions() []ActionTypeEntry {
	out := make([]ActionTypeEntry, 0, len(FilesystemActions)+len(SystemActions)+len(DataActions)+1)
	out = append(out, FilesystemActions...)
	out = append(out, SystemActions...)
	out = append(out, DataActions...)
	out = append(out, UnknownAction)
	return out
}

// GetActionType returns the entry for the given type, or nil if unknown.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
func GetActionType(actionType string) *ActionTypeEntry {
	e, ok := actionMap[actionType]
	if !ok {
		return nil
	}
	return &e
}

// ResolveActionType returns the entry for the given type, falling back to
// UnknownAction if the type is not in the registry.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
func ResolveActionType(actionType string) ActionTypeEntry {
	if e, ok := actionMap[actionType]; ok {
		return e
	}
	return UnknownAction
}

// ClassifyToolCall classifies a tool name into an action type and risk level
// using the provided mappings. If no mapping matches, the result is "unknown".
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
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
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
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
