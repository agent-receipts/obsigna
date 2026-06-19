// Package risk holds the receipt-free primitives shared between the receipt
// taxonomy and any classifier that must run without importing receipt — the
// risk levels and the action.type string constants that carry no crypto.
//
// It is a leaf package: it imports nothing from this module (and no crypto), so
// callers that classify tool calls (e.g. the thin MCP proxy, ADR-0033) can
// depend on it without pulling in the receipt writer surface ADR-0010 reserves
// for the daemon. The receipt package re-exports these as type aliases and const
// re-exports, so receipt.RiskLevel / receipt.RiskLow / receipt.ActionTypePTYOpen
// remain interchangeable with their risk counterparts everywhere.
package risk

// Level classifies the security risk of an action.
type Level string

const (
	Low      Level = "low"
	Medium   Level = "medium"
	High     Level = "high"
	Critical Level = "critical"
)

// ActionTypePTYOpen and ActionTypePTYClose are the action.type values for PTY
// lifecycle events (ADR-0027 §/pty). They live here, free of crypto and the
// receipt package, so the taxonomy registry can reference them without importing
// receipt.
const (
	ActionTypePTYOpen  = "system.pty.open"
	ActionTypePTYClose = "system.pty.close"
)
