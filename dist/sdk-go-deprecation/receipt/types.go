// Package receipt provides types and functions for creating, signing, and
// verifying Action Receipts — W3C Verifiable Credentials for AI agent actions.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the
// canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
package receipt

import "encoding/json"

// Protocol constants (unexported to prevent mutation).
var (
	protocolContext        = []string{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"}
	protocolCredentialType = []string{"VerifiableCredential", "AgentReceipt"}
)

// Context returns a copy of the W3C VC context array.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
func Context() []string { return append([]string{}, protocolContext...) }

// CredentialType returns a copy of the credential type array.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
func CredentialType() []string { return append([]string{}, protocolCredentialType...) }

// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
const Version = "0.4.0"

// RiskLevel classifies the security risk of an action.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type RiskLevel string

const (
	// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
	RiskLow RiskLevel = "low"
	// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
	RiskMedium RiskLevel = "medium"
	// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
	RiskHigh RiskLevel = "high"
	// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
	RiskCritical RiskLevel = "critical"
)

// ChainStatus is the issuer-asserted termination reason carried in
// chain.status (spec §7.3.3). Wire values are ChainStatusComplete and
// ChainStatusInterrupted only — ChainStatusUnknown is verifier-derived
// and MUST NOT be emitted by issuers.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type ChainStatus string

const (
	// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
	ChainStatusComplete ChainStatus = "complete"
	// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
	ChainStatusInterrupted ChainStatus = "interrupted"
	// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
	ChainStatusUnknown ChainStatus = "unknown"
)

// IsValidWireValue reports whether v is one of the two values an issuer may
// write to chain.status. Verifier-only "unknown" returns false.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
func (v ChainStatus) IsValidWireValue() bool {
	return v == ChainStatusComplete || v == ChainStatusInterrupted
}

// OutcomeStatus represents the result of an action.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type OutcomeStatus string

const (
	// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
	StatusSuccess OutcomeStatus = "success"
	// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
	StatusFailure OutcomeStatus = "failure"
	// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
	StatusPending OutcomeStatus = "pending"
)

// Operator identifies the AI model executing actions.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type Operator struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Issuer represents the agent that issued the receipt.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type Issuer struct {
	ID        string    `json:"id"`
	Type      string    `json:"type,omitempty"`
	Name      string    `json:"name,omitempty"`
	Operator  *Operator `json:"operator,omitempty"`
	Model     string    `json:"model,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
}

// Principal identifies the human or organisation that authorised the action.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type Principal struct {
	ID   string `json:"id"`
	Type string `json:"type,omitempty"`
}

// ActionTarget specifies the system and resource being acted upon.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
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
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
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
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type EmitterMetadata struct {
	DropCount int64 `json:"drop_count,omitempty"`
}

// Action describes what the agent did.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
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
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type Intent struct {
	ConversationHash       string `json:"conversation_hash,omitempty"`
	PromptPreview          string `json:"prompt_preview,omitempty"`
	PromptPreviewTruncated *bool  `json:"prompt_preview_truncated,omitempty"`
	ReasoningHash          string `json:"reasoning_hash,omitempty"`
}

// StateChange captures before/after state hashes.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type StateChange struct {
	BeforeHash string `json:"before_hash"`
	AfterHash  string `json:"after_hash"`
}

// Outcome describes the result of an action.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
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
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type Authorization struct {
	Scopes    []string `json:"scopes"`
	GrantedAt string   `json:"granted_at"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	GrantRef  string   `json:"grant_ref,omitempty"`
}

// Chain links receipts in a tamper-evident sequence.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
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
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
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
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type Delegator struct {
	ID string `json:"id"`
}

// Delegation records the chain linkage when this chain was spawned by a parent agent.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type Delegation struct {
	ParentChainID   string    `json:"parent_chain_id"`
	ParentReceiptID string    `json:"parent_receipt_id"`
	Delegator       Delegator `json:"delegator"`
}

// CredentialSubject contains the core receipt payload.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type CredentialSubject struct {
	Principal     Principal      `json:"principal"`
	Action        Action         `json:"action"`
	Intent        *Intent        `json:"intent,omitempty"`
	Outcome       Outcome        `json:"outcome"`
	Authorization *Authorization `json:"authorization,omitempty"`
	Chain         Chain          `json:"chain"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Delegation    *Delegation    `json:"delegation,omitempty"`
}

// Proof contains the Ed25519 signature.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created,omitempty"`
	VerificationMethod string `json:"verificationMethod,omitempty"`
	ProofPurpose       string `json:"proofPurpose,omitempty"`
	ProofValue         string `json:"proofValue"`
}

// AgentReceipt is a signed W3C Verifiable Credential for an agent action.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
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
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
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
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

// TruncatePromptPreview truncates s to maxLen runes and sets the truncated flag.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module github.com/agent-receipts/ar/sdk/go instead (see ADR-0023).
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
