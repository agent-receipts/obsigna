// Package receipt provides types and functions for creating, signing, and
// verifying Action Receipts — W3C Verifiable Credentials for AI agent actions.
package receipt

import (
	"encoding/json"
	"fmt"
)

// Protocol constants (unexported to prevent mutation).
var (
	protocolContext        = []string{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v2"}
	protocolCredentialType = []string{"VerifiableCredential", "AgentReceipt"}
)

// Context returns a copy of the W3C VC context array.
func Context() []string { return append([]string{}, protocolContext...) }

// CredentialType returns a copy of the credential type array.
func CredentialType() []string { return append([]string{}, protocolCredentialType...) }

const Version = "0.5.0"

// RiskLevel classifies the security risk of an action.
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// ChainStatus is the issuer-asserted termination reason carried in
// chain.status (spec §7.3.3). Wire values are ChainStatusComplete and
// ChainStatusInterrupted only — ChainStatusUnknown is verifier-derived
// and MUST NOT be emitted by issuers.
type ChainStatus string

const (
	ChainStatusComplete    ChainStatus = "complete"
	ChainStatusInterrupted ChainStatus = "interrupted"
	ChainStatusUnknown     ChainStatus = "unknown"
)

// IsValidWireValue reports whether v is one of the two values an issuer may
// write to chain.status. Verifier-only "unknown" returns false.
func (v ChainStatus) IsValidWireValue() bool {
	return v == ChainStatusComplete || v == ChainStatusInterrupted
}

// OutcomeStatus represents the result of an action.
type OutcomeStatus string

const (
	StatusSuccess OutcomeStatus = "success"
	StatusFailure OutcomeStatus = "failure"
	StatusPending OutcomeStatus = "pending"
)

// ActionTypePTYOpen and ActionTypePTYClose are the action.type values for PTY
// lifecycle events (ADR-0027 §/pty). Defined here so chain.go can reference
// them without importing the taxonomy package (which imports receipt).
const (
	ActionTypePTYOpen  = "system.pty.open"
	ActionTypePTYClose = "system.pty.close"
)

// Operator identifies the AI model executing actions.
type Operator struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Issuer represents the agent that issued the receipt.
type Issuer struct {
	ID        string    `json:"id"`
	Type      string    `json:"type,omitempty"`
	Name      string    `json:"name,omitempty"`
	Operator  *Operator `json:"operator,omitempty"`
	Model     string    `json:"model,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	Runtime   *Runtime  `json:"runtime,omitempty"`
}

// Runtime is the open container for runtime/observability metadata the issuing
// runtime attaches to an action (ADR-0026). It is intentionally extensible: the
// fields below are documented members, but the JSON-LD context types it @json
// and the schema does not close it, so additional runtime keys (e.g. future
// trace-context identifiers) may be added without a protocol-version bump.
//
// Runtime is present whenever any member is set. The agent-identity members
// (AgentID/AgentType) appear only on sub-agent receipts, but the observability
// members (Model/Usage/CaptureMethod) also appear on root-agent receipts — so
// consumers MUST NOT assume Issuer.Runtime is nil on a root-chain receipt.
//
// Unlike the rest of the receipt struct (whose unknown fields are dropped on a
// round-trip — see HashRawReceipt), Runtime PRESERVES unknown keys via Extra so
// the Go, TS, and Python SDKs all keep runtime open at the typed layer. A key
// added by a newer SDK therefore survives an older Go SDK's HashReceipt/Sign
// round-trip and stays byte-identical across languages.
type Runtime struct {
	// AgentID identifies the sub-agent that issued the receipt. Absent for the
	// root agent.
	AgentID string
	// AgentType is the runtime-reported agent type label (e.g. "general-purpose").
	AgentType string
	// Model is the model the runtime observed producing this action (e.g. a
	// transcript-derived "claude-opus-4-8"). It is observability-oriented
	// (ADR-0026 D5) and distinct from the identity-bearing top-level
	// issuer.model: runtime.model records what an auditor can *correlate* the
	// call with, not what they verify identity against. Absent when unknown.
	Model string
	// Usage is the token-usage object exactly as the agent runtime reported it
	// (input/output/cache tokens). It is stored verbatim and never recomputed,
	// so field names and shape track the runtime's own report across versions.
	// Absent when unknown.
	Usage json.RawMessage
	// CaptureMethod records how Model/Usage were captured (e.g. "transcript"),
	// so transcript-derived receipts can be distinguished from receipts enriched
	// by other ingesters (OTLP, daemon). Absent when unknown.
	CaptureMethod string
	// Extra holds runtime keys this SDK version does not model as typed fields,
	// preserved verbatim so they survive a round-trip and hash identically.
	Extra map[string]json.RawMessage
}

// MarshalJSON emits agent_id / agent_type (when non-empty) alongside every Extra
// key, so unknown runtime members round-trip. Key ordering is irrelevant:
// Canonicalize re-sorts per RFC 8785.
func (r Runtime) MarshalJSON() ([]byte, error) {
	// +5 reserves space for every typed member emitted below (agent_id,
	// agent_type, model, usage, capture_method) so a fully-populated runtime
	// does not reallocate the map.
	m := make(map[string]json.RawMessage, len(r.Extra)+5)
	for k, v := range r.Extra {
		m[k] = v
	}
	if r.AgentID != "" {
		b, err := json.Marshal(r.AgentID)
		if err != nil {
			return nil, fmt.Errorf("marshal runtime.agent_id: %w", err)
		}
		m["agent_id"] = b
	}
	if r.AgentType != "" {
		b, err := json.Marshal(r.AgentType)
		if err != nil {
			return nil, fmt.Errorf("marshal runtime.agent_type: %w", err)
		}
		m["agent_type"] = b
	}
	if r.Model != "" {
		b, err := json.Marshal(r.Model)
		if err != nil {
			return nil, fmt.Errorf("marshal runtime.model: %w", err)
		}
		m["model"] = b
	}
	if len(r.Usage) > 0 {
		// Stored verbatim — the runtime's own token-usage object, never
		// recomputed. Canonicalize re-serialises it deterministically at hash
		// time, so the byte form here need not be pre-canonicalised.
		m["usage"] = r.Usage
	}
	if r.CaptureMethod != "" {
		b, err := json.Marshal(r.CaptureMethod)
		if err != nil {
			return nil, fmt.Errorf("marshal runtime.capture_method: %w", err)
		}
		m["capture_method"] = b
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal runtime: %w", err)
	}
	return b, nil
}

// UnmarshalJSON reads the typed members into AgentID / AgentType and keeps any
// remaining keys in Extra.
func (r *Runtime) UnmarshalJSON(data []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("unmarshal runtime: %w", err)
	}
	*r = Runtime{}
	if v, ok := m["agent_id"]; ok {
		if err := json.Unmarshal(v, &r.AgentID); err != nil {
			return fmt.Errorf("runtime.agent_id: %w", err)
		}
		delete(m, "agent_id")
	}
	if v, ok := m["agent_type"]; ok {
		if err := json.Unmarshal(v, &r.AgentType); err != nil {
			return fmt.Errorf("runtime.agent_type: %w", err)
		}
		delete(m, "agent_type")
	}
	if v, ok := m["model"]; ok {
		if err := json.Unmarshal(v, &r.Model); err != nil {
			return fmt.Errorf("runtime.model: %w", err)
		}
		delete(m, "model")
	}
	if v, ok := m["usage"]; ok {
		// Keep the verbatim bytes so the token-usage object round-trips and
		// hashes identically — it is the runtime's report, not ours to reshape.
		r.Usage = v
		delete(m, "usage")
	}
	if v, ok := m["capture_method"]; ok {
		if err := json.Unmarshal(v, &r.CaptureMethod); err != nil {
			return fmt.Errorf("runtime.capture_method: %w", err)
		}
		delete(m, "capture_method")
	}
	if len(m) > 0 {
		r.Extra = m
	}
	return nil
}

// Principal identifies the human or organisation that authorised the action.
type Principal struct {
	ID   string `json:"id"`
	Type string `json:"type,omitempty"`
}

// ActionTarget specifies the system and resource being acted upon.
type ActionTarget struct {
	System   string `json:"system"`
	Resource string `json:"resource,omitempty"`
}

// PeerCredential is OS-attested peer process metadata captured by the daemon
// at the SDK↔daemon boundary (ADR-0010). Present only on receipts emitted
// through a daemon; absent on direct-SDK emissions. The values are daemon-
// attested, not agent-claimed, and are signature-protected by the surrounding
// receipt.
//
// Field widths follow POSIX: PID is int32 (signed pid_t, -1 is a valid
// sentinel); UID/GID are *uint32 (pointer so that uid=0 / gid=0 — the root
// identity — serialise as `"uid":0` rather than absent). A nil pointer means
// the platform has no UID/GID concept (e.g. Windows); ExePath uses omitempty
// for the same reason.
type PeerCredential struct {
	Platform string  `json:"platform"`
	PID      int32   `json:"pid"`
	UID      *uint32 `json:"uid,omitempty"`
	GID      *uint32 `json:"gid,omitempty"`
	ExePath  string  `json:"exe_path,omitempty"`
}

// EmitterMetadata holds daemon-observed emitter-side metadata (ADR-0010).
// Currently records the drop counter on synthetic events_dropped receipts.
// Daemon-attested, not agent-claimed.
type EmitterMetadata struct {
	DropCount int64 `json:"drop_count,omitempty"`
}

// Action describes what the agent did.
type Action struct {
	ID                   string              `json:"id"`
	Type                 string              `json:"type"`
	ToolName             string              `json:"tool_name,omitempty"`
	RiskLevel            RiskLevel           `json:"risk_level"`
	Target               *ActionTarget       `json:"target,omitempty"`
	ParametersHash       string              `json:"parameters_hash,omitempty"`
	ParametersDisclosure *DisclosureEnvelope `json:"parameters_disclosure,omitempty"`
	PeerCredential       *PeerCredential     `json:"peer_credential,omitempty"`
	EmitterMetadata      *EmitterMetadata    `json:"emitter_metadata,omitempty"`
	Timestamp            string              `json:"timestamp"`
	TrustedTimestamp     string              `json:"trusted_timestamp,omitempty"`
	// IdempotencyKey is a stable identifier for the logical operation this
	// action represents (e.g. a request ID). When an agent retries a tool call,
	// the same key is stamped on every receipt for that operation so auditors
	// can distinguish a legitimate retry from a duplicated emission. Omitted
	// (omitempty) when no stable source exists; MUST NOT be empty when present.
	// See spec §7.3.6 and ADR-0019 §S5.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// Intent captures conversation context behind the action.
type Intent struct {
	ConversationHash       string `json:"conversation_hash,omitempty"`
	PromptPreview          string `json:"prompt_preview,omitempty"`
	PromptPreviewTruncated *bool  `json:"prompt_preview_truncated,omitempty"`
	ReasoningHash          string `json:"reasoning_hash,omitempty"`
}

// StateChange captures before/after state hashes.
type StateChange struct {
	BeforeHash string `json:"before_hash"`
	AfterHash  string `json:"after_hash"`
}

// Outcome describes the result of an action.
type Outcome struct {
	Status                OutcomeStatus `json:"status"`
	Error                 string        `json:"error,omitempty"`
	Reversible            *bool         `json:"reversible,omitempty"`
	ReversalMethod        string        `json:"reversal_method,omitempty"`
	ReversalWindowSeconds *int          `json:"reversal_window_seconds,omitempty"`
	ReversalOf            string        `json:"reversal_of,omitempty"`
	StateChange           *StateChange  `json:"state_change,omitempty"`
	ResponseHash          string        `json:"response_hash,omitempty"`
}

// Authorization captures the scope and expiry of an action.
type Authorization struct {
	Scopes    []string `json:"scopes"`
	GrantedAt string   `json:"granted_at"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	GrantRef  string   `json:"grant_ref,omitempty"`
}

// Chain links receipts in a tamper-evident sequence.
type Chain struct {
	Sequence            int     `json:"sequence"`
	PreviousReceiptHash *string `json:"previous_receipt_hash"`
	ChainID             string  `json:"chain_id"`
	// Terminal, when non-nil and true, asserts this is the final receipt in
	// the chain. Spec §4.3.2 restricts the wire form to the constant true or
	// absent — explicit false is schema-invalid. MarshalJSON silently drops
	// Terminal when it is non-nil but false so external callers who set
	// Terminal: &falseVal still produce a valid JSON document.
	Terminal *bool `json:"terminal,omitempty"`
	// Status, when non-empty, asserts the reason the chain ended. MUST be
	// ChainStatusComplete or ChainStatusInterrupted; ChainStatusUnknown is
	// verifier-derived and MUST NOT be set by issuers. Only meaningful
	// alongside Terminal: true. MarshalJSON silently drops Status when
	// Terminal is unset or false, and also drops any value that is not a
	// valid wire value. See spec §7.3.3.
	Status ChainStatus `json:"status,omitempty"`
}

// MarshalJSON serializes Chain, enforcing the wire-form invariants:
//   - Terminal is dropped when it is non-nil but false (spec §4.3.2 forbids
//     terminal: false on the wire).
//   - Status is dropped when Terminal is unset (spec §7.3.3 requires status
//     to coexist with terminal).
//   - Status is dropped when it is not a valid wire value (i.e. anything
//     other than ChainStatusComplete or ChainStatusInterrupted — including
//     ChainStatusUnknown, which is verifier-derived only).
func (c Chain) MarshalJSON() ([]byte, error) {
	type chainAlias Chain
	a := chainAlias(c)
	if a.Terminal != nil && !*a.Terminal {
		a.Terminal = nil
	}
	if a.Terminal == nil {
		a.Status = ""
	}
	if a.Status != "" && !a.Status.IsValidWireValue() {
		a.Status = ""
	}
	return json.Marshal(a)
}

// Delegator identifies the agent whose chain spawned a delegation.
type Delegator struct {
	ID string `json:"id"`
}

// Delegation records the chain linkage when this chain was spawned by
// delegation from another agent. Present only on the first receipt of a
// subagent chain; absent on root chains. See spec §delegation.
type Delegation struct {
	ParentChainID   string    `json:"parent_chain_id"`
	ParentReceiptID string    `json:"parent_receipt_id"`
	Delegator       Delegator `json:"delegator"`
}

// KeyRotation records a key-rotation event (ADR-0015). It is present only on a
// key_rotated receipt and absent on every other receipt. The receipt carrying
// it is signed with the OUTGOING key (SignedWith == "old"); NewPublicKey holds
// the incoming key inline so verifiers chain through the rotation without an
// external key registry. All seven fields are required when the object is
// present. See spec §7.3.7 for verifier traversal.
type KeyRotation struct {
	// EventType is the constant "key_rotated".
	EventType string `json:"event_type"`
	// NewPublicKey is the incoming public key inline: raw key bytes per the
	// algorithm's canonical encoding (Ed25519: 32 bytes, RFC 8032 §5.1.5),
	// multibase-encoded with the "u" base64url prefix.
	NewPublicKey string `json:"new_public_key"`
	// OldKeyFingerprint is sha256:<hex> of the outgoing public key's raw bytes.
	OldKeyFingerprint string `json:"old_key_fingerprint"`
	// NewKeyFingerprint is sha256:<hex> of the incoming public key's raw bytes;
	// it MUST equal the SHA-256 of the bytes decoded from NewPublicKey.
	NewKeyFingerprint string `json:"new_key_fingerprint"`
	// OldAlgorithm is the algorithm tag of the outgoing key (e.g. "ed25519").
	OldAlgorithm string `json:"old_algorithm"`
	// NewAlgorithm is the algorithm tag of the incoming key.
	NewAlgorithm string `json:"new_algorithm"`
	// SignedWith is the constant "old": the rotation event is signed with the
	// outgoing key.
	SignedWith string `json:"signed_with"`
}

// CredentialSubject contains the core receipt payload.
type CredentialSubject struct {
	Principal     Principal      `json:"principal"`
	Action        Action         `json:"action"`
	Intent        *Intent        `json:"intent,omitempty"`
	Outcome       Outcome        `json:"outcome"`
	Authorization *Authorization `json:"authorization,omitempty"`
	Chain         Chain          `json:"chain"`
	// KeyRotation is present only on a key_rotated receipt (ADR-0015); absent on
	// all other receipts.
	KeyRotation *KeyRotation `json:"keyRotation,omitempty"`
	// CorrelationID links related receipts for the same logical tool invocation
	// (e.g. hook pre-check to MCP proxy post-action). Populated from the
	// runtime's tool-use correlation token; absent when not available.
	CorrelationID string `json:"correlation_id,omitempty"`
	// Delegation records the parent chain when this receipt opens a subagent
	// chain. Absent on root chains and all receipts after the first in a chain.
	Delegation *Delegation `json:"delegation,omitempty"`
}

// Proof contains the Ed25519 signature.
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created,omitempty"`
	VerificationMethod string `json:"verificationMethod,omitempty"`
	ProofPurpose       string `json:"proofPurpose,omitempty"`
	ProofValue         string `json:"proofValue"`
}

// AgentReceipt is a signed W3C Verifiable Credential for an agent action.
type AgentReceipt struct {
	Context []string `json:"@context"`
	ID      string   `json:"id"`
	Type    []string `json:"type"`
	Version string   `json:"version"`
	Issuer  Issuer   `json:"issuer"`
	// issuanceDate follows W3C VC v1 naming; the protocol spec uses this
	// instead of VC v2's validFrom.
	IssuanceDate      string            `json:"issuanceDate"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
	Proof             Proof             `json:"proof"`
}

// UnsignedAgentReceipt is an AgentReceipt without a proof, ready to be signed.
type UnsignedAgentReceipt struct {
	Context           []string          `json:"@context"`
	ID                string            `json:"id"`
	Type              []string          `json:"type"`
	Version           string            `json:"version"`
	Issuer            Issuer            `json:"issuer"`
	IssuanceDate      string            `json:"issuanceDate"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
}

// KeyPair holds PEM-encoded Ed25519 keys.
type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

// TruncatePromptPreview truncates s to maxLen runes and sets the truncated flag.
func TruncatePromptPreview(s string, maxLen int) (preview string, truncated bool) {
	if maxLen <= 0 {
		return "", len(s) > 0
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s, false
	}
	return string(runes[:maxLen]), true
}
