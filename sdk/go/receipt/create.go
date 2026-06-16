package receipt

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
)

var reversalOfPattern = regexp.MustCompile(`^urn:receipt:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// CreateInput holds the inputs for creating an unsigned receipt.
type CreateInput struct {
	Issuer        Issuer
	Principal     Principal
	Action        Action // ID and Timestamp are auto-generated if empty.
	Outcome       Outcome
	Chain         Chain
	Intent        *Intent
	Authorization *Authorization
	// ResponseBody is the pre-redacted response body to hash. When non-empty,
	// the hash is computed (redact → hash → sign ordering) and stored in
	// outcome.ResponseHash. Callers must redact before passing.
	ResponseBody json.RawMessage

	// Terminal marks this as the final receipt in the chain.
	// When true, sets chain.terminal: true. Never emits false.
	Terminal bool

	// TerminationStatus, when valid and Terminal is true, sets chain.status
	// on the receipt. MUST be ChainStatusComplete or ChainStatusInterrupted
	// (spec §7.3.3). Other values — including ChainStatusUnknown, which is
	// verifier-derived — are silently dropped at construction so callers
	// cannot accidentally produce schema-invalid receipts. Setting
	// TerminationStatus without Terminal is also silently dropped; the spec
	// requires status to coexist with terminal.
	TerminationStatus ChainStatus

	// CorrelationID links related receipts for the same logical tool invocation.
	// See CredentialSubject.CorrelationID.
	CorrelationID string

	// Delegation records the parent chain when this receipt opens a subagent
	// chain. Nil on root chains and all receipts after the first in a chain.
	Delegation *Delegation
}

// Create builds an unsigned AgentReceipt from structured inputs.
// It auto-generates the receipt ID, action ID, issuance date, and action
// timestamp (if not already set in Action).
func Create(input CreateInput) UnsignedAgentReceipt {
	now := time.Now().UTC().Format(time.RFC3339)

	action := input.Action
	if action.ID == "" {
		action.ID = fmt.Sprintf("act_%s", uuid.New().String())
	}
	if action.Timestamp == "" {
		action.Timestamp = now
	}

	subject := CredentialSubject{
		Principal:     input.Principal,
		Action:        action,
		Outcome:       input.Outcome,
		Chain:         input.Chain,
		Intent:        input.Intent,
		Authorization: input.Authorization,
		CorrelationID: input.CorrelationID,
		Delegation:    input.Delegation,
	}

	// Panic on malformed reversal_of: a non-empty value that doesn't match the
	// URN format is a programming error (the caller is constructing an
	// invalid receipt). Silent omission would let bad data reach the chain.
	if input.Outcome.ReversalOf != "" && !reversalOfPattern.MatchString(input.Outcome.ReversalOf) {
		panic(fmt.Sprintf("receipt.Create: Outcome.ReversalOf is not a valid receipt URN: %q", input.Outcome.ReversalOf))
	}

	// Compute response_hash when a response body is supplied.
	// Panic on unmarshal/canonicalization failure: passing non-JSON as ResponseBody
	// is a programming error — silently omitting the hash would undermine the
	// security property the caller intended to commit to.
	if len(input.ResponseBody) > 0 {
		var responseAny any
		if err := json.Unmarshal(input.ResponseBody, &responseAny); err != nil {
			panic(fmt.Sprintf("receipt.Create: ResponseBody is not valid JSON: %v", err))
		}
		canonical, err := Canonicalize(responseAny)
		if err != nil {
			panic(fmt.Sprintf("receipt.Create: ResponseBody canonicalization failed: %v", err))
		}
		subject.Outcome.ResponseHash = SHA256Hash(canonical)
	}

	// Set terminal marker when requested (never set false).
	if input.Terminal {
		t := true
		subject.Chain.Terminal = &t
		// Status is only emitted alongside terminal AND only when the value
		// is a valid wire-form ChainStatus (spec §7.3.3). Invalid values
		// (including ChainStatusUnknown) are silently dropped here so this
		// entry point cannot produce a schema-invalid receipt.
		if input.TerminationStatus.IsValidWireValue() {
			subject.Chain.Status = input.TerminationStatus
		}
	}

	return UnsignedAgentReceipt{
		Context:           Context(),
		ID:                fmt.Sprintf("urn:receipt:%s", uuid.New().String()),
		Type:              CredentialType(),
		Version:           Version,
		Issuer:            input.Issuer,
		IssuanceDate:      now,
		CredentialSubject: subject,
	}
}
