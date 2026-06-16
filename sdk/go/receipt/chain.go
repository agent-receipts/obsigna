package receipt

import (
	"encoding/json"
	"strconv"
	"strings"
)

// hashReceipt is overridable in tests so the error-return path of HashReceipt
// (unreachable in production with the current strictly-typed AgentReceipt) can
// be exercised. In production, this variable is left pointing at HashReceipt.
var hashReceipt = HashReceipt

// verifyReceipt is overridable in tests so the error-return path of Verify can
// be exercised without a malformed key. In production this points at Verify.
var verifyReceipt = Verify

// ReceiptVerification holds the verification result for a single receipt in a chain.
type ReceiptVerification struct {
	Index          int    `json:"index"`
	ReceiptID      string `json:"receipt_id"`
	SignatureValid bool   `json:"signature_valid"`
	HashLinkValid  bool   `json:"hash_link_valid"`
	SequenceValid  bool   `json:"sequence_valid"`
}

// ChainVerification holds the verification result for an entire chain.
type ChainVerification struct {
	Valid    bool                  `json:"valid"`
	Length   int                   `json:"length"`
	Status   ChainStatus           `json:"status"` // "complete" | "interrupted" | "unknown" (spec §7.3.3).
	Receipts []ReceiptVerification `json:"receipts"`
	BrokenAt int                   `json:"broken_at"`       // -1 if chain is valid.
	Error    string                `json:"error,omitempty"` // Non-empty if verification failed due to a key/proof error.
	// ResponseHashNote is non-empty when one or more receipts carry response_hash
	// but no response body was supplied for recomputation.
	ResponseHashNote string `json:"response_hash_note,omitempty"`
	// Warnings carries non-fatal advisories about the verified chain. It is
	// populated independently of Valid — a warning never changes the
	// verification result. Currently it surfaces duplicate action.idempotency_key
	// values (spec §7.3.6): retries are legitimate, so duplicates are flagged for
	// auditor review rather than treated as failures.
	Warnings []string `json:"warnings,omitempty"`
	// IncompleteToolRoundtrip is true when the final, non-terminal receipt has
	// outcome.status == pending — a tool call whose result receipt never arrived
	// (ADR-0019 §O3, retained by ADR-0020). Advisory only: it does NOT by itself
	// set Valid=false, since the chain may still verify cryptographically. It is
	// surfaced separately from a generic chain break so callers can report
	// "incomplete tool roundtrip" specifically.
	IncompleteToolRoundtrip bool `json:"incomplete_tool_roundtrip,omitempty"`
	// IncompleteSession is true when PTY session accounting is imbalanced:
	// more opens than closes (session force-terminated without a close receipt)
	// or more closes than opens (orphaned close from a replay or truncated
	// chain). Advisory only: it does NOT by itself set Valid=false. Analogous
	// to IncompleteToolRoundtrip for session-scope pairs (ADR-0027 §/pty).
	IncompleteSession bool `json:"incomplete_session,omitempty"`
}

// classifyTerminationStatus inspects the wire form of the final receipt and
// returns the chain's termination status (spec §7.3.3). Independent of
// verification result — describes what the chain claims, not whether it's valid.
func classifyTerminationStatus(receipts []AgentReceipt) ChainStatus {
	if len(receipts) == 0 {
		return ChainStatusUnknown
	}
	last := receipts[len(receipts)-1]
	ch := last.CredentialSubject.Chain
	if ch.Terminal == nil || !*ch.Terminal {
		return ChainStatusUnknown
	}
	if ch.Status == ChainStatusInterrupted {
		return ChainStatusInterrupted
	}
	return ChainStatusComplete
}

// duplicateIdempotencyWarnings scans the chain for non-empty
// action.idempotency_key values that appear on more than one receipt and
// returns a human-readable advisory for each such key (spec §7.3.6). Retries
// are legitimate, so these are warnings, not failures. Order is deterministic:
// warnings follow the first-seen order of each duplicated key, and the indices
// within each warning are in chain order. Receipts that omit the key never
// contribute. Returns nil when there are no duplicates.
func duplicateIdempotencyWarnings(receipts []AgentReceipt) []string {
	indices := make(map[string][]int)
	var order []string
	for i, r := range receipts {
		key := r.CredentialSubject.Action.IdempotencyKey
		if key == "" {
			continue
		}
		if _, seen := indices[key]; !seen {
			order = append(order, key)
		}
		indices[key] = append(indices[key], i)
	}
	var warnings []string
	for _, key := range order {
		idx := indices[key]
		if len(idx) < 2 {
			continue
		}
		parts := make([]string, len(idx))
		for j, v := range idx {
			parts[j] = strconv.Itoa(v)
		}
		warnings = append(warnings, "duplicate idempotency_key "+strconv.Quote(key)+
			" on receipts at indices "+strings.Join(parts, ", ")+
			" (retries are legitimate; review for double-counting)")
	}
	return warnings
}

// isIncompleteToolRoundtrip reports whether the final receipt is non-terminal
// (Terminal absent or false) AND carries outcome.status == pending — a tool
// call whose result receipt never arrived (ADR-0019 §O3, retained by ADR-0020).
// A terminal receipt closes the chain deliberately, so a pending terminal
// receipt is not flagged. An empty chain is not flagged. Advisory only:
// independent of whether the chain verifies.
func isIncompleteToolRoundtrip(receipts []AgentReceipt) bool {
	if len(receipts) == 0 {
		return false
	}
	last := receipts[len(receipts)-1]
	if last.CredentialSubject.Chain.Terminal != nil && *last.CredentialSubject.Chain.Terminal {
		return false
	}
	return last.CredentialSubject.Outcome.Status == StatusPending
}

// isIncompleteSession reports whether PTY session accounting is imbalanced:
// more opens than closes (session force-terminated without a close receipt) or
// more closes than opens (orphaned close from a replay or truncated chain).
// Count-based; advisory only; independent of chain validity. ADR-0027 §/pty.
func isIncompleteSession(receipts []AgentReceipt) bool {
	var opens, closes int
	for _, r := range receipts {
		switch r.CredentialSubject.Action.Type {
		case ActionTypePTYOpen:
			opens++
		case ActionTypePTYClose:
			closes++
		}
	}
	return opens != closes
}

// ChainVerifyOptions holds optional parameters for VerifyChain.
// Zero value means "use defaults" — behaviour is identical to v0.1 with no options.
type ChainVerifyOptions struct {
	// ExpectedLength, when non-nil, causes verification to fail if the observed
	// chain length does not equal this value. Provides out-of-band truncation
	// detection when the caller knows the expected chain length.
	ExpectedLength *int

	// ExpectedFinalHash, when non-empty, causes verification to fail if the
	// SHA-256 hash of the last observed receipt does not equal this value.
	// Provides out-of-band truncation detection when the caller knows the
	// expected final receipt hash.
	ExpectedFinalHash string

	// RequireTerminal, when true, causes verification to fail if the last
	// observed receipt does not have chain.terminal: true. Use for chains
	// that must close cleanly. When false (the default), absence of a terminal
	// marker is not a failure.
	RequireTerminal bool

	// ResponseBodies maps receipt ID → pre-redacted response body (JSON-encoded).
	// When a receipt carries outcome.response_hash and its ID appears here,
	// VerifyChain recomputes the hash (canonicalize → SHA-256) and fails on
	// mismatch. When an entry is absent the verifier emits an informational note
	// instead (see ChainVerification.ResponseHashNote). An absent body is not a
	// verification failure.
	ResponseBodies map[string]json.RawMessage
}

// VerifyChain verifies a chain of signed receipts. In execution order, it
// checks:
//   - Ed25519 signature validity
//   - Hash linkage (previous_receipt_hash matches SHA-256 of prior receipt)
//   - Sequence numbers strictly incrementing from the first receipt
//   - Chain identifier binding: all receipts MUST share the same
//     chain.chain_id as the first receipt (unconditional, see spec §7.3.4)
//   - Receipt-after-terminal: if any receipt has chain.terminal: true, no
//     subsequent receipt may reference it (unconditional check, see spec §7.3.2)
//
// Chain verification does NOT detect tail truncation by default — dropping the
// last N receipts from a chain still produces Valid: true. To detect truncation:
//   - Supply ExpectedLength and/or ExpectedFinalHash (out-of-band witness)
//   - Supply RequireTerminal for chains that must close with chain.terminal: true
//
// Chains that are open-ended and have no external witness cannot be detected as
// truncated. See spec §7.3.1 for the full treatment.
//
// Supply ResponseBodies to verify outcome.response_hash fields: for each receipt
// whose ID maps to a body, the hash is recomputed and verification fails on
// mismatch. When no body is supplied for a receipt that carries response_hash, an
// informational note is emitted but verification continues.
func VerifyChain(receipts []AgentReceipt, publicKeyPEM string, opts ...ChainVerifyOptions) ChainVerification {
	var opt ChainVerifyOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	// Computed once and stamped onto every returned ChainVerification below;
	// advisory and never affects Valid.
	incompleteToolRoundtrip := isIncompleteToolRoundtrip(receipts)
	incompleteSession := isIncompleteSession(receipts)

	if len(receipts) == 0 {
		// Handle ExpectedLength=0 edge case: empty chain with ExpectedLength=0 is valid.
		if opt.ExpectedLength != nil && *opt.ExpectedLength != 0 {
			return ChainVerification{
				Valid:                   false,
				Length:                  0,
				Status:                  ChainStatusUnknown,
				BrokenAt:                0,
				Error:                   "expected chain length does not match: expected " + strconv.Itoa(*opt.ExpectedLength) + ", got 0",
				IncompleteToolRoundtrip: incompleteToolRoundtrip,
				IncompleteSession:       incompleteSession,
			}
		}
		return ChainVerification{Valid: true, Length: 0, Status: ChainStatusUnknown, BrokenAt: -1, IncompleteToolRoundtrip: incompleteToolRoundtrip, IncompleteSession: incompleteSession}
	}

	status := classifyTerminationStatus(receipts)

	// Idempotency-key duplicate detection is independent of validity (spec
	// §7.3.6) — compute it once up front so every return path can surface it.
	warnings := duplicateIdempotencyWarnings(receipts)

	results := make([]ReceiptVerification, 0, len(receipts))
	brokenAt := -1
	var firstSigErr string
	var firstSigErrAt int = -1
	var firstRotationErr string
	var firstRotationErrAt int = -1
	var firstHashComputeErr string
	var firstHashComputeErrAt int = -1
	var schemaErr string
	var schemaErrAt int = -1

	// activeKeyPEM is the public key that the current receipt must verify
	// against. It starts as the caller-supplied genesis key and is replaced by
	// the incoming key after each verified key_rotated receipt (spec §7.3.7).
	activeKeyPEM := publicKeyPEM

	for i, r := range receipts {
		chain := r.CredentialSubject.Chain

		// Schema-level chain.status invariants (spec §7.3.3).
		// A non-empty chain.status MUST be a valid wire value (complete or
		// interrupted — never the verifier-only "unknown") AND MUST coexist
		// with chain.terminal: true. Receipts deserialised from external JSON
		// can violate either invariant; the verifier rejects them here so an
		// attacker cannot smuggle in schema-invalid receipts that bypass the
		// SDK's construction-time guards.
		if chain.Status != "" {
			terminalSet := chain.Terminal != nil && *chain.Terminal
			switch {
			case !chain.Status.IsValidWireValue():
				if schemaErr == "" {
					schemaErr = "invalid chain.status value at index " + strconv.Itoa(i) + ": " + string(chain.Status) + " is not a valid wire value (spec §7.3.3)"
					schemaErrAt = i
				}
			case !terminalSet:
				if schemaErr == "" {
					schemaErr = "chain.status without chain.terminal: true at index " + strconv.Itoa(i) + " (spec §7.3.3)"
					schemaErrAt = i
				}
			}
		}

		sigValid, sigErr := verifyReceipt(r, activeKeyPEM)
		if sigErr != nil {
			sigValid = false
			if firstSigErr == "" {
				firstSigErr = "signature compute failed at index " + strconv.Itoa(i) + ": " + sigErr.Error()
				firstSigErrAt = i
			}
		}

		hashValid := true
		if i == 0 {
			hashValid = chain.PreviousReceiptHash == nil
		} else {
			prevHash, err := hashReceipt(receipts[i-1])
			if err != nil {
				if firstHashComputeErr == "" {
					firstHashComputeErr = "hash compute failed at index " + strconv.Itoa(i-1) + ": " + err.Error()
					firstHashComputeErrAt = i
				}
				hashValid = false
			} else {
				hashValid = chain.PreviousReceiptHash != nil && *chain.PreviousReceiptHash == prevHash
			}
		}

		seqValid := true
		if i == 0 {
			seqValid = chain.Sequence >= 1
		} else {
			seqValid = chain.Sequence == receipts[i-1].CredentialSubject.Chain.Sequence+1
		}

		results = append(results, ReceiptVerification{
			Index:          i,
			ReceiptID:      r.ID,
			SignatureValid: sigValid,
			HashLinkValid:  hashValid,
			SequenceValid:  seqValid,
		})

		if brokenAt == -1 && (!sigValid || !hashValid || !seqValid) {
			brokenAt = i
		}
		if brokenAt == -1 && schemaErrAt == i {
			brokenAt = i
		}

		// Key-rotation traversal (ADR-0015 / spec §7.3.7). A key_rotated receipt
		// is signed with the OUTGOING (currently active) key; once that signature
		// and the rotation-event fields check out, the incoming key carried inline
		// takes over for every subsequent receipt until the next rotation.
		if kr := r.CredentialSubject.KeyRotation; kr != nil {
			newKeyPEM, rotErr := verifyRotationEvent(activeKeyPEM, kr)
			if rotErr != nil {
				if firstRotationErr == "" {
					firstRotationErr = "key rotation invalid at index " + strconv.Itoa(i) + ": " + rotErr.Error()
					firstRotationErrAt = i
				}
				if brokenAt == -1 {
					brokenAt = i
				}
			} else if sigValid {
				// Only adopt the incoming key when the rotation receipt itself
				// verified under the outgoing key; otherwise the binding of
				// new_public_key to the prior chain segment is not trustworthy.
				activeKeyPEM = newKeyPEM
			}
		}
	}

	// Pick whichever compute / schema error occurred first in the chain.
	// Candidates are checked in priority order — sig > hash > schema —
	// so when two errors occur at the same index, the higher-priority one
	// wins (the strict-less-than below skips equal-index later entries).
	// This precedence reflects that crypto failures are more diagnostic
	// than schema violations when both fire on the same receipt.
	// Compute this before the terminal check so early returns preserve it.
	var loopErr string
	var loopErrAt int = -1
	candidates := []struct {
		msg string
		at  int
	}{
		{firstSigErr, firstSigErrAt},
		{firstRotationErr, firstRotationErrAt},
		{firstHashComputeErr, firstHashComputeErrAt},
		{schemaErr, schemaErrAt},
	}
	for _, c := range candidates {
		if c.msg == "" {
			continue
		}
		if loopErrAt == -1 || c.at < loopErrAt {
			loopErr, loopErrAt = c.msg, c.at
		}
	}

	// Chain identifier binding check (unconditional — spec §7.3.4).
	// All receipts in a verified chain MUST share chain.chain_id. Reject
	// cross-chain splices: an attacker with a valid hash linkage might
	// otherwise mix receipts from two distinct chains under one verification
	// call. Runs independently of hash linkage so a forged link still fails
	// here.
	expectedChainID := receipts[0].CredentialSubject.Chain.ChainID
	for i := 1; i < len(receipts); i++ {
		observed := receipts[i].CredentialSubject.Chain.ChainID
		if observed != expectedChainID {
			// BrokenAt aligns with the error message — set unconditionally to
			// the mismatch index so callers reading BrokenAt and Error see the
			// same offending receipt. (Any earlier per-receipt failure already
			// surfaces in the per-receipt Receipts slice.)
			return ChainVerification{
				Valid:    false,
				Length:   len(receipts),
				Status:   status,
				Receipts: results,
				BrokenAt: i,
				Error: "chain_id mismatch at index " + strconv.Itoa(i) +
					": expected \"" + expectedChainID + "\", got \"" + observed + "\"",
				Warnings:                warnings,
				IncompleteToolRoundtrip: incompleteToolRoundtrip,
				IncompleteSession:       incompleteSession,
			}
		}
	}

	// Receipt-after-terminal integrity check (unconditional — spec §7.3.2).
	// If a receipt has terminal: true and is not the last receipt, that is a
	// protocol violation: a receipt after a terminal predecessor exists.
	for i, r := range receipts {
		ch := r.CredentialSubject.Chain
		if ch.Terminal != nil && *ch.Terminal {
			if i < len(receipts)-1 {
				terminalViolationAt := i + 1
				if brokenAt == -1 || terminalViolationAt < brokenAt {
					brokenAt = terminalViolationAt
				}
				// Use compute error only if it occurred at or before the terminal
				// violation; otherwise the terminal violation message takes precedence.
				errMsg := loopErr
				if loopErrAt == -1 || loopErrAt > terminalViolationAt {
					errMsg = "receipt after terminal: receipt at index " + strconv.Itoa(i+1) + " follows a terminal receipt at index " + strconv.Itoa(i)
				}
				return ChainVerification{
					Valid:                   false,
					Length:                  len(receipts),
					Status:                  status,
					Receipts:                results,
					BrokenAt:                brokenAt,
					Error:                   errMsg,
					Warnings:                warnings,
					IncompleteToolRoundtrip: incompleteToolRoundtrip,
					IncompleteSession:       incompleteSession,
				}
			}
		}
	}

	cv := ChainVerification{
		Valid:                   brokenAt == -1,
		Length:                  len(receipts),
		Status:                  status,
		Receipts:                results,
		BrokenAt:                brokenAt,
		Error:                   loopErr,
		Warnings:                warnings,
		IncompleteToolRoundtrip: incompleteToolRoundtrip,
		IncompleteSession:       incompleteSession,
	}

	// Response-hash verification (spec §4.3.2).
	// When a body is supplied: recompute and fail on mismatch.
	// When the body is absent: emit an informational note only.
	for i, r := range receipts {
		expectedHash := r.CredentialSubject.Outcome.ResponseHash
		if expectedHash == "" {
			continue
		}
		body, hasBody := opt.ResponseBodies[r.ID]
		if !hasBody {
			cv.ResponseHashNote = "response_hash present in one or more receipts; response body not supplied — hash cannot be verified offline"
			continue
		}
		if !cv.Valid {
			// Chain already broken; skip comparison.
			continue
		}
		var bodyAny any
		if err := json.Unmarshal(body, &bodyAny); err != nil {
			cv.Valid = false
			cv.BrokenAt = i
			cv.Error = "response_hash: failed to parse response body at index " + strconv.Itoa(i) + ": " + err.Error()
			return cv
		}
		canonical, err := Canonicalize(bodyAny)
		if err != nil {
			cv.Valid = false
			cv.BrokenAt = i
			cv.Error = "response_hash: failed to canonicalize response body at index " + strconv.Itoa(i) + ": " + err.Error()
			return cv
		}
		computed := SHA256Hash(canonical)
		if computed != expectedHash {
			cv.Valid = false
			cv.BrokenAt = i
			cv.Error = "response_hash mismatch at index " + strconv.Itoa(i) + ": receipt has " + expectedHash + ", body hashes to " + computed
			return cv
		}
	}

	if cv.Valid {
		// Optional out-of-band checks (only applied when basic verification passes).
		if opt.ExpectedLength != nil && len(receipts) != *opt.ExpectedLength {
			cv.Valid = false
			cv.BrokenAt = len(receipts) - 1
			cv.Error = "expected chain length does not match: expected " + strconv.Itoa(*opt.ExpectedLength) + ", got " + strconv.Itoa(len(receipts))
		} else if opt.ExpectedFinalHash != "" {
			last := len(receipts) - 1
			lastHash, err := hashReceipt(receipts[last])
			if err != nil {
				cv.Valid = false
				cv.BrokenAt = last
				cv.Error = "hash compute failed at index " + strconv.Itoa(last) + ": " + err.Error()
			} else if lastHash != opt.ExpectedFinalHash {
				cv.Valid = false
				cv.BrokenAt = last
				cv.Error = "final receipt hash mismatch at index " + strconv.Itoa(last) + ": expected " + opt.ExpectedFinalHash + ", got " + lastHash
			}
		}

		if cv.Valid && opt.RequireTerminal {
			last := receipts[len(receipts)-1]
			if last.CredentialSubject.Chain.Terminal == nil || !*last.CredentialSubject.Chain.Terminal {
				cv.Valid = false
				cv.BrokenAt = len(receipts) - 1
				cv.Error = "require_terminal: last receipt does not have chain.terminal: true"
			}
		}
	}

	return cv
}
