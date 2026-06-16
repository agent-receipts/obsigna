package receipt

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func buildChain(t *testing.T, kp KeyPair, count int) []AgentReceipt {
	t.Helper()
	chain := make([]AgentReceipt, 0, count)
	var prevHash *string

	for i := 1; i <= count; i++ {
		unsigned := Create(CreateInput{
			Issuer:    Issuer{ID: "did:agent:test"},
			Principal: Principal{ID: "did:user:test"},
			Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
			Outcome:   Outcome{Status: StatusSuccess},
			Chain:     Chain{Sequence: i, PreviousReceiptHash: prevHash, ChainID: "chain-1"},
		})
		signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, signed)

		h, err := HashReceipt(signed)
		if err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}
	return chain
}

func TestVerifyChainValid(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 5)

	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Errorf("expected valid chain, broken at %d", result.BrokenAt)
		for _, r := range result.Receipts {
			t.Logf("  [%d] sig=%v hash=%v seq=%v", r.Index, r.SignatureValid, r.HashLinkValid, r.SequenceValid)
		}
	}
	if result.Length != 5 {
		t.Errorf("expected length 5, got %d", result.Length)
	}
}

func TestVerifyChainEmpty(t *testing.T) {
	result := VerifyChain(nil, "")
	if !result.Valid {
		t.Error("empty chain should be valid")
	}
	if result.Length != 0 {
		t.Errorf("expected length 0, got %d", result.Length)
	}
}

func TestVerifyChainSingleReceipt(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 1)

	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Errorf("expected single-receipt chain to be valid, broken at %d", result.BrokenAt)
	}
	if result.Length != 1 {
		t.Errorf("expected length 1, got %d", result.Length)
	}
	if len(result.Receipts) != 1 {
		t.Errorf("expected 1 receipt result, got %d", len(result.Receipts))
	}
}

func TestVerifyChainDetectsTamper(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 3)

	// Tamper with second receipt.
	chain[1].CredentialSubject.Action.Type = "hacked"

	result := VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Error("expected tampered chain to be invalid")
	}
	if result.BrokenAt != 1 {
		t.Errorf("expected broken at 1, got %d", result.BrokenAt)
	}
}

func TestVerifyChainDetectsBrokenHashLink(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 3)

	// Break hash link on third receipt.
	bad := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	chain[2].CredentialSubject.Chain.PreviousReceiptHash = &bad

	result := VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Error("expected broken hash link to be invalid")
	}
	// Broken at 2 (hash link) but also signature will fail because we modified the receipt.
	if result.BrokenAt != 2 {
		t.Errorf("expected broken at 2, got %d", result.BrokenAt)
	}
}

// Spec §7.3.5 / #479 — a gap in chain.sequence within a session is a hard
// verification failure. Parity with the TS "detects a broken sequence" and
// Python "test_broken_sequence" tests.
func TestVerifyChainDetectsSequenceGap(t *testing.T) {
	kp, _ := GenerateKeyPair()

	// Build a 2-receipt chain manually with sequences 1 and 3 (gap at 2),
	// preserving valid hash linkage between them so the only invariant
	// violated is sequence contiguity.
	first := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, PreviousReceiptHash: nil, ChainID: "chain-gap"},
	})
	firstSigned, err := Sign(first, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	firstHash, err := HashReceipt(firstSigned)
	if err != nil {
		t.Fatal(err)
	}
	third := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 3, PreviousReceiptHash: &firstHash, ChainID: "chain-gap"},
	})
	thirdSigned, err := Sign(third, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}

	result := VerifyChain([]AgentReceipt{firstSigned, thirdSigned}, kp.PublicKey)
	if result.Valid {
		t.Fatal("sequence gap (1 → 3) must be rejected")
	}
	if result.BrokenAt != 1 {
		t.Errorf("expected BrokenAt=1, got %d", result.BrokenAt)
	}
	if len(result.Receipts) < 2 || result.Receipts[1].SequenceValid {
		t.Errorf("expected receipts[1].SequenceValid=false, got %+v", result.Receipts)
	}
}

func TestVerifyChainSurfacesHashError(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 3)

	targetID := chain[0].ID
	orig := hashReceipt
	hashReceipt = func(r AgentReceipt) (string, error) {
		if r.ID == targetID {
			return "", errors.New("synthetic canonicalize failure")
		}
		return orig(r)
	}
	t.Cleanup(func() { hashReceipt = orig })

	result := VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Error("expected Valid: false when HashReceipt errors")
	}
	if result.BrokenAt != 1 {
		t.Errorf("expected BrokenAt=1, got %d", result.BrokenAt)
	}
	if len(result.Receipts) != 3 {
		t.Errorf("expected all 3 receipt entries, got %d", len(result.Receipts))
	}
	if !strings.Contains(result.Error, "hash compute failed at index 0") {
		t.Errorf("expected error to contain 'hash compute failed at index 0', got: %s", result.Error)
	}
	if !strings.Contains(result.Error, "synthetic canonicalize failure") {
		t.Errorf("expected error to contain 'synthetic canonicalize failure', got: %s", result.Error)
	}
}

// TestHashComputeErrorAllReceiptsPresent verifies the length/brokenAt invariants
// when hashReceipt fails mid-chain: all receipts must be in the result, and
// brokenAt must point to the first broken index, not the early-exit point.
func TestHashComputeErrorAllReceiptsPresent(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 5)

	targetID := chain[0].ID
	orig := hashReceipt
	hashReceipt = func(r AgentReceipt) (string, error) {
		if r.ID == targetID {
			return "", errors.New("synthetic failure")
		}
		return orig(r)
	}
	t.Cleanup(func() { hashReceipt = orig })

	result := VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Error("expected Valid: false")
	}
	if result.BrokenAt != 1 {
		t.Errorf("expected BrokenAt=1 (first broken index), got %d", result.BrokenAt)
	}
	if result.Length != 5 {
		t.Errorf("expected Length=5, got %d", result.Length)
	}
	if len(result.Receipts) != 5 {
		t.Errorf("expected 5 per-receipt entries (invariant), got %d", len(result.Receipts))
	}
	// Only receipt[1]'s hash link is broken; later ones resolve normally.
	if result.Receipts[1].HashLinkValid {
		t.Error("expected Receipts[1].HashLinkValid=false")
	}
	if !result.Receipts[2].HashLinkValid {
		t.Error("expected Receipts[2].HashLinkValid=true (hash of receipt[1] computes fine)")
	}
}

// TestSigComputeErrorContinuesIteration verifies that a signature-compute error
// (Verify returns a non-nil error) does not early-exit the loop: all receipts
// must be present, brokenAt is the first index that failed, and the error message
// names the failure site.
func TestSigComputeErrorContinuesIteration(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 5)

	targetID := chain[1].ID
	orig := verifyReceipt
	verifyReceipt = func(r AgentReceipt, key string) (bool, error) {
		if r.ID == targetID {
			return false, errors.New("synthetic verify failure")
		}
		return orig(r, key)
	}
	t.Cleanup(func() { verifyReceipt = orig })

	result := VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Error("expected Valid: false")
	}
	if result.BrokenAt != 1 {
		t.Errorf("expected BrokenAt=1, got %d", result.BrokenAt)
	}
	if result.Length != 5 {
		t.Errorf("expected Length=5, got %d", result.Length)
	}
	if len(result.Receipts) != 5 {
		t.Errorf("expected 5 per-receipt entries, got %d", len(result.Receipts))
	}
	if !strings.Contains(result.Error, "signature compute failed at index 1") {
		t.Errorf("expected error to name failure site, got: %s", result.Error)
	}
	if !strings.Contains(result.Error, "synthetic verify failure") {
		t.Errorf("expected error to include cause, got: %s", result.Error)
	}
	// Non-target receipts must have their SignatureValid computed correctly.
	if !result.Receipts[0].SignatureValid {
		t.Error("expected Receipts[0].SignatureValid=true")
	}
	if result.Receipts[1].SignatureValid {
		t.Error("expected Receipts[1].SignatureValid=false (injected error)")
	}
	for i := 2; i < 5; i++ {
		if !result.Receipts[i].SignatureValid {
			t.Errorf("expected Receipts[%d].SignatureValid=true", i)
		}
	}
}

// TestDualErrorSigTakesPrecedenceOverHashCompute verifies that when both a
// signature-compute error and a hash-compute error occur in the same chain,
// the signature error wins in ChainVerification.Error.
func TestDualErrorSigTakesPrecedenceOverHashCompute(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 3)

	targetID := chain[0].ID

	origVerify := verifyReceipt
	verifyReceipt = func(r AgentReceipt, key string) (bool, error) {
		if r.ID == targetID {
			return false, errors.New("synthetic sig failure")
		}
		return origVerify(r, key)
	}
	t.Cleanup(func() { verifyReceipt = origVerify })

	origHash := hashReceipt
	hashReceipt = func(r AgentReceipt) (string, error) {
		if r.ID == targetID {
			return "", errors.New("synthetic hash failure")
		}
		return origHash(r)
	}
	t.Cleanup(func() { hashReceipt = origHash })

	result := VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Error("expected Valid: false")
	}
	if !strings.Contains(result.Error, "signature compute failed at index 0") {
		t.Errorf("expected sig error to win, got: %s", result.Error)
	}
	if strings.Contains(result.Error, "hash compute") {
		t.Errorf("hash-compute error must be suppressed when sig error present, got: %s", result.Error)
	}
}

// TestExpectedFinalHashMismatchError verifies the enriched error message includes
// both the expected and computed hashes.
func TestExpectedFinalHashMismatchError(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 3)
	realFinalHash, _ := HashReceipt(chain[2])

	// Supply a deliberately wrong expected hash.
	wrongHash := "sha256:" + strings.Repeat("0", 64)
	result := VerifyChain(chain, kp.PublicKey, ChainVerifyOptions{ExpectedFinalHash: wrongHash})
	if result.Valid {
		t.Error("expected Valid: false")
	}
	if !strings.Contains(result.Error, "final receipt hash mismatch at index 2") {
		t.Errorf("expected index in error, got: %s", result.Error)
	}
	if !strings.Contains(result.Error, wrongHash) {
		t.Errorf("expected expected-hash in error, got: %s", result.Error)
	}
	if !strings.Contains(result.Error, realFinalHash) {
		t.Errorf("expected computed-hash in error, got: %s", result.Error)
	}
}

// TestComputeErrorPreservedThroughTerminalCheck verifies that a sig-compute error
// is still surfaced in ChainVerification.Error when the chain also has a
// receipt-after-terminal violation (which previously returned early before the error
// was applied).
func TestComputeErrorPreservedThroughTerminalCheck(t *testing.T) {
	kp, _ := GenerateKeyPair()
	terminalChain := buildChainWithTerminal(t, kp, 2)

	terminalHash, err := HashReceipt(terminalChain[1])
	if err != nil {
		t.Fatal(err)
	}
	extra := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 3, PreviousReceiptHash: &terminalHash, ChainID: "chain-1"},
	})
	extraSigned, _ := Sign(extra, kp.PrivateKey, "did:agent:test#key-1")
	chain := append(terminalChain, extraSigned)

	targetID := chain[0].ID
	orig := verifyReceipt
	verifyReceipt = func(r AgentReceipt, key string) (bool, error) {
		if r.ID == targetID {
			return false, errors.New("synthetic sig failure")
		}
		return orig(r, key)
	}
	t.Cleanup(func() { verifyReceipt = orig })

	result := VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Error("expected Valid: false")
	}
	if !strings.Contains(result.Error, "signature compute failed at index 0") {
		t.Errorf("compute error must surface through terminal check, got: %s", result.Error)
	}
}

// --- ADR-0008 tests below ---

// buildChainWithTerminal builds a chain of `count` receipts where the last
// receipt has chain.terminal: true.
func buildChainWithTerminal(t *testing.T, kp KeyPair, count int) []AgentReceipt {
	t.Helper()
	chain := buildChain(t, kp, count-1)

	// Build terminal receipt.
	var prevHash *string
	if len(chain) > 0 {
		h, err := HashReceipt(chain[len(chain)-1])
		if err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: count, PreviousReceiptHash: prevHash, ChainID: "chain-1"},
		Terminal:  true,
	})
	signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	return append(chain, signed)
}

func TestChainTruncationPins(t *testing.T) {
	// Dropping tail receipts must not break verification (pins current behaviour).
	// This is a deliberate design floor documented in spec §7.3.1.
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 5)
	truncated := chain[:3] // drop last 2

	result := VerifyChain(truncated, kp.PublicKey)
	if !result.Valid {
		t.Errorf("truncated chain (no expected length/hash) must be Valid: true; broken at %d: %s", result.BrokenAt, result.Error)
	}
	if result.Length != 3 {
		t.Errorf("expected length 3, got %d", result.Length)
	}
}

func TestExpectedLength(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 5)
	truncated := chain[:3]

	five := 5
	result := VerifyChain(truncated, kp.PublicKey, ChainVerifyOptions{ExpectedLength: &five})
	if result.Valid {
		t.Error("expected Valid: false when ExpectedLength=5 but chain has 3")
	}
	if result.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestExpectedLengthMatch(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 5)

	five := 5
	result := VerifyChain(chain, kp.PublicKey, ChainVerifyOptions{ExpectedLength: &five})
	if !result.Valid {
		t.Errorf("expected Valid: true when ExpectedLength matches, got error: %s", result.Error)
	}
}

func TestExpectedFinalHash(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 5)
	truncated := chain[:3]

	// Use the hash of the real final receipt as the expected value.
	realFinalHash, _ := HashReceipt(chain[4])
	result := VerifyChain(truncated, kp.PublicKey, ChainVerifyOptions{ExpectedFinalHash: realFinalHash})
	if result.Valid {
		t.Error("expected Valid: false when ExpectedFinalHash doesn't match truncated chain")
	}
}

func TestExpectedFinalHashMatch(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 5)

	finalHash, err := HashReceipt(chain[4])
	if err != nil {
		t.Fatal(err)
	}
	result := VerifyChain(chain, kp.PublicKey, ChainVerifyOptions{ExpectedFinalHash: finalHash})
	if !result.Valid {
		t.Errorf("expected Valid: true when ExpectedFinalHash matches, got: %s", result.Error)
	}
}

func TestTerminalRoundTrip(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChainWithTerminal(t, kp, 3)

	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Errorf("chain ending in terminal must be valid: broken at %d: %s", result.BrokenAt, result.Error)
	}

	// Confirm last receipt has terminal: true.
	last := chain[len(chain)-1]
	if last.CredentialSubject.Chain.Terminal == nil || !*last.CredentialSubject.Chain.Terminal {
		t.Error("last receipt must have chain.terminal: true")
	}
}

func TestReceiptAfterTerminal(t *testing.T) {
	// Build a chain where a receipt appears after a terminal receipt.
	// This must always fail regardless of any caller options.
	kp, _ := GenerateKeyPair()
	terminalChain := buildChainWithTerminal(t, kp, 3) // 3 receipts, last is terminal

	// Append a receipt after the terminal one — this is a protocol violation.
	terminalHash, err := HashReceipt(terminalChain[2])
	if err != nil {
		t.Fatal(err)
	}
	extra := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 4, PreviousReceiptHash: &terminalHash, ChainID: "chain-1"},
	})
	extraSigned, err := Sign(extra, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	bad := append(terminalChain, extraSigned)

	result := VerifyChain(bad, kp.PublicKey)
	if result.Valid {
		t.Error("chain with receipt after terminal must be Valid: false")
	}
	if result.Error == "" {
		t.Error("expected a clear error message for receipt-after-terminal")
	}
	// Should contain "terminal" in the error message.
	if !containsStr(result.Error, "terminal") {
		t.Errorf("error message should mention 'terminal', got: %s", result.Error)
	}
}

func TestReceiptAfterTerminalIgnoresCallerOptions(t *testing.T) {
	// receipt-after-terminal must fire even with no caller options.
	kp, _ := GenerateKeyPair()
	terminalChain := buildChainWithTerminal(t, kp, 2)

	terminalHash, err := HashReceipt(terminalChain[1])
	if err != nil {
		t.Fatal(err)
	}
	extra := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 3, PreviousReceiptHash: &terminalHash, ChainID: "chain-1"},
	})
	extraSigned, _ := Sign(extra, kp.PrivateKey, "did:agent:test#key-1")
	bad := append(terminalChain, extraSigned)

	// Even with no options, must fail.
	result := VerifyChain(bad, kp.PublicKey)
	if result.Valid {
		t.Error("receipt-after-terminal must be caught unconditionally")
	}
}

func TestRequireTerminalWithTerminal(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChainWithTerminal(t, kp, 3)

	result := VerifyChain(chain, kp.PublicKey, ChainVerifyOptions{RequireTerminal: true})
	if !result.Valid {
		t.Errorf("RequireTerminal with terminal chain must be valid: %s", result.Error)
	}
}

func TestRequireTerminalTruncated(t *testing.T) {
	// RequireTerminal: true on a chain where the terminal receipt was dropped → invalid.
	kp, _ := GenerateKeyPair()
	chain := buildChainWithTerminal(t, kp, 3)
	// Drop the terminal receipt (last one).
	truncated := chain[:2]

	result := VerifyChain(truncated, kp.PublicKey, ChainVerifyOptions{RequireTerminal: true})
	if result.Valid {
		t.Error("RequireTerminal with missing terminal receipt must be Valid: false")
	}
}

func TestRequireTerminalWithoutTerminal(t *testing.T) {
	// RequireTerminal: false (default) with non-terminal chain → valid.
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 3)

	result := VerifyChain(chain, kp.PublicKey) // no options
	if !result.Valid {
		t.Errorf("non-terminal chain without RequireTerminal must be valid: %s", result.Error)
	}
}

func TestResponseHashHappyPath(t *testing.T) {
	responseBody := []byte(`{"result":"ok","status":200}`)
	unsigned := Create(CreateInput{
		Issuer:       Issuer{ID: "did:agent:test"},
		Principal:    Principal{ID: "did:user:test"},
		Action:       Action{Type: "data.api.read", RiskLevel: RiskLow},
		Outcome:      Outcome{Status: StatusSuccess},
		Chain:        Chain{Sequence: 1, ChainID: "chain-resp"},
		ResponseBody: responseBody,
	})

	if unsigned.CredentialSubject.Outcome.ResponseHash == "" {
		t.Fatal("expected response_hash to be populated")
	}

	// Recompute the hash manually and compare.
	var responseAny any
	if err := json.Unmarshal(responseBody, &responseAny); err != nil {
		t.Fatal(err)
	}
	canonical, err := Canonicalize(responseAny)
	if err != nil {
		t.Fatal(err)
	}
	expected := SHA256Hash(canonical)
	if unsigned.CredentialSubject.Outcome.ResponseHash != expected {
		t.Errorf("hash mismatch: got %s, want %s", unsigned.CredentialSubject.Outcome.ResponseHash, expected)
	}
}

func TestResponseHashMissingBody(t *testing.T) {
	// A receipt with response_hash but no body supplied → continues with note.
	kp, _ := GenerateKeyPair()
	unsigned := Create(CreateInput{
		Issuer:       Issuer{ID: "did:agent:test"},
		Principal:    Principal{ID: "did:user:test"},
		Action:       Action{Type: "data.api.read", RiskLevel: RiskLow},
		Outcome:      Outcome{Status: StatusSuccess},
		Chain:        Chain{Sequence: 1, ChainID: "chain-note"},
		ResponseBody: []byte(`{"result":"ok"}`),
	})
	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	result := VerifyChain([]AgentReceipt{signed}, kp.PublicKey)
	if !result.Valid {
		t.Errorf("missing response body must not fail verification: %s", result.Error)
	}
	if result.ResponseHashNote == "" {
		t.Error("expected ResponseHashNote to be non-empty when response_hash present but body absent")
	}
}

func TestResponseHashAbsent(t *testing.T) {
	// No response_hash → no note, no failure.
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 1)

	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Errorf("expected valid, got error: %s", result.Error)
	}
	if result.ResponseHashNote != "" {
		t.Errorf("expected empty ResponseHashNote, got: %s", result.ResponseHashNote)
	}
}

func TestRedactThenHash(t *testing.T) {
	// The ordering test: redact → hash, not hash → redact.
	// A known "secret" in the raw response must NOT appear in the hash computation.
	rawResponse := map[string]any{
		"result":   "ok",
		"password": "super-secret-value",
	}

	// Simulate redaction: replace sensitive value with [REDACTED].
	redacted := map[string]any{
		"result":   "ok",
		"password": "[REDACTED]",
	}

	// Hash of redacted form.
	rawRedacted := `{"password":"[REDACTED]","result":"ok"}` // RFC 8785 sorted
	hashOfRedacted := SHA256Hash(rawRedacted)

	// Hash of raw form (should differ).
	rawRaw := `{"password":"super-secret-value","result":"ok"}`
	hashOfRaw := SHA256Hash(rawRaw)

	if hashOfRedacted == hashOfRaw {
		t.Fatal("test setup error: hashes of raw and redacted should differ")
	}

	// Create receipt using pre-redacted body.
	redactedJSON, _ := json.Marshal(redacted)
	unsigned := Create(CreateInput{
		Issuer:       Issuer{ID: "did:agent:test"},
		Principal:    Principal{ID: "did:user:test"},
		Action:       Action{Type: "data.api.read", RiskLevel: RiskLow},
		Outcome:      Outcome{Status: StatusSuccess},
		Chain:        Chain{Sequence: 1, ChainID: "chain-redact"},
		ResponseBody: redactedJSON,
	})

	// Verify the stored hash equals hash(redacted), not hash(raw response).
	got := unsigned.CredentialSubject.Outcome.ResponseHash
	if got != hashOfRedacted {
		t.Errorf("response_hash should equal hash(redacted): got %s, want %s", got, hashOfRedacted)
	}
	if got == hashOfRaw {
		t.Error("response_hash must not equal hash(raw response)")
	}
	_ = rawResponse // suppress unused warning
}

func TestTerminalFieldNeverFalse(t *testing.T) {
	// Creating a receipt with Terminal: false should NOT emit terminal field.
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-t"},
		Terminal:  false, // explicitly false — must produce no terminal field
	})
	if unsigned.CredentialSubject.Chain.Terminal != nil {
		t.Error("Terminal: false must not emit chain.terminal field (Terminal pointer must be nil)")
	}
}

func TestTerminalTrueEmits(t *testing.T) {
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-t"},
		Terminal:  true,
	})
	if unsigned.CredentialSubject.Chain.Terminal == nil {
		t.Fatal("Terminal: true must set chain.terminal field")
	}
	if !*unsigned.CredentialSubject.Chain.Terminal {
		t.Error("chain.terminal must be true")
	}
}

// TestChainMarshalDropsFalseTerminal verifies the structural safeguard on
// Chain: even when an external caller explicitly sets Terminal to &false
// (bypassing Create()), the wire form must omit the terminal field entirely,
// per spec §4.3.2 which forbids `terminal: false`.
func TestChainMarshalDropsFalseTerminal(t *testing.T) {
	f := false
	prevHash := "sha256:abc"
	c := Chain{
		Sequence:            2,
		PreviousReceiptHash: &prevHash,
		ChainID:             "chain-escape",
		Terminal:            &f, // the escape hatch
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if containsStr(string(data), "terminal") {
		t.Errorf("Terminal: &false must be omitted from JSON; got %s", data)
	}
}

func TestResponseHashVerificationMatch(t *testing.T) {
	// When a matching body is supplied, VerifyChain recomputes and passes.
	kp, _ := GenerateKeyPair()
	body := json.RawMessage(`{"result":"ok","status":200}`)
	unsigned := Create(CreateInput{
		Issuer:       Issuer{ID: "did:agent:test"},
		Principal:    Principal{ID: "did:user:test"},
		Action:       Action{Type: "data.api.read", RiskLevel: RiskLow},
		Outcome:      Outcome{Status: StatusSuccess},
		Chain:        Chain{Sequence: 1, ChainID: "chain-verify"},
		ResponseBody: body,
	})
	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	result := VerifyChain([]AgentReceipt{signed}, kp.PublicKey, ChainVerifyOptions{
		ResponseBodies: map[string]json.RawMessage{signed.ID: body},
	})
	if !result.Valid {
		t.Errorf("expected valid when response body matches hash: %s", result.Error)
	}
	if result.ResponseHashNote != "" {
		t.Errorf("expected no note when body is supplied: %s", result.ResponseHashNote)
	}
}

func TestResponseHashVerificationMismatch(t *testing.T) {
	// When the supplied body does not match the stored hash, verification fails.
	kp, _ := GenerateKeyPair()
	goodBody := json.RawMessage(`{"result":"ok"}`)
	badBody := json.RawMessage(`{"result":"tampered"}`)
	unsigned := Create(CreateInput{
		Issuer:       Issuer{ID: "did:agent:test"},
		Principal:    Principal{ID: "did:user:test"},
		Action:       Action{Type: "data.api.read", RiskLevel: RiskLow},
		Outcome:      Outcome{Status: StatusSuccess},
		Chain:        Chain{Sequence: 1, ChainID: "chain-mismatch"},
		ResponseBody: goodBody,
	})
	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	result := VerifyChain([]AgentReceipt{signed}, kp.PublicKey, ChainVerifyOptions{
		ResponseBodies: map[string]json.RawMessage{signed.ID: badBody},
	})
	if result.Valid {
		t.Error("expected invalid when supplied body does not match stored hash")
	}
	if !containsStr(result.Error, "response_hash mismatch") {
		t.Errorf("expected mismatch error, got: %s", result.Error)
	}
}

func TestResponseHashNoBodyInMap(t *testing.T) {
	// response_hash present but receipt ID not in ResponseBodies → note, not failure.
	kp, _ := GenerateKeyPair()
	unsigned := Create(CreateInput{
		Issuer:       Issuer{ID: "did:agent:test"},
		Principal:    Principal{ID: "did:user:test"},
		Action:       Action{Type: "data.api.read", RiskLevel: RiskLow},
		Outcome:      Outcome{Status: StatusSuccess},
		Chain:        Chain{Sequence: 1, ChainID: "chain-note2"},
		ResponseBody: []byte(`{"result":"ok"}`),
	})
	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	// Supply an empty ResponseBodies map (no entry for this receipt).
	result := VerifyChain([]AgentReceipt{signed}, kp.PublicKey, ChainVerifyOptions{
		ResponseBodies: map[string]json.RawMessage{},
	})
	if !result.Valid {
		t.Errorf("absent body entry must not fail verification: %s", result.Error)
	}
	if result.ResponseHashNote == "" {
		t.Error("expected informational note when body is absent from map")
	}
}

// TestTerminalViolationBeforeComputeError verifies that when a terminal violation
// occurs at an earlier index than a hash-compute error, brokenAt reflects the
// terminal violation index and the error message names the terminal violation.
func TestTerminalViolationBeforeComputeError(t *testing.T) {
	kp, _ := GenerateKeyPair()
	// Build: receipt[0] is terminal, receipt[1..3] are normal — terminal violation
	// at terminalViolationAt=1 (receipt[1] follows the terminal receipt[0]).
	terminalChain := buildChainWithTerminal(t, kp, 1)

	// Append three more receipts after the terminal one.
	var prevHash *string
	h, err := HashReceipt(terminalChain[0])
	if err != nil {
		t.Fatal(err)
	}
	prevHash = &h
	extra := make([]AgentReceipt, 3)
	for j := 0; j < 3; j++ {
		seq := 2 + j
		unsigned := Create(CreateInput{
			Issuer:    Issuer{ID: "did:agent:test"},
			Principal: Principal{ID: "did:user:test"},
			Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
			Outcome:   Outcome{Status: StatusSuccess},
			Chain:     Chain{Sequence: seq, PreviousReceiptHash: prevHash, ChainID: "chain-1"},
		})
		signed, signErr := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
		if signErr != nil {
			t.Fatal(signErr)
		}
		extra[j] = signed
		hh, hashErr := HashReceipt(signed)
		if hashErr != nil {
			t.Fatal(hashErr)
		}
		prevHash = &hh
	}
	chain := append(terminalChain, extra...)

	// Inject a hash-compute error on receipt[2] — this fires when processing
	// receipt[3] (i=3, computing hash of receipts[2]), so loopErrAt=3.
	// Terminal violation is at terminalViolationAt=1 (receipt[0] is terminal).
	// The bug: before the fix, brokenAt was left at loopErrAt=3 and the error
	// message was the hash-compute error even though terminal violation came first.
	targetID := chain[2].ID
	orig := hashReceipt
	hashReceipt = func(r AgentReceipt) (string, error) {
		if r.ID == targetID {
			return "", errors.New("synthetic hash failure")
		}
		return orig(r)
	}
	t.Cleanup(func() { hashReceipt = orig })

	result := VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Error("expected Valid: false")
	}
	if result.BrokenAt != 1 {
		t.Errorf("expected BrokenAt=1 (terminal violation index), got %d", result.BrokenAt)
	}
	if !strings.Contains(result.Error, "receipt after terminal") {
		t.Errorf("expected terminal violation error to win, got: %s", result.Error)
	}
	if strings.Contains(result.Error, "hash compute") {
		t.Errorf("hash-compute error must not appear when terminal violation comes first, got: %s", result.Error)
	}
}

// --- Chain termination status (spec §7.3.3, #475) ---

// buildChainWithStatus is like buildChainWithTerminal but also sets
// chain.status on the terminal receipt.
func buildChainWithStatus(t *testing.T, kp KeyPair, count int, status ChainStatus) []AgentReceipt {
	t.Helper()
	chain := buildChain(t, kp, count-1)

	var prevHash *string
	if len(chain) > 0 {
		h, err := HashReceipt(chain[len(chain)-1])
		if err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}
	unsigned := Create(CreateInput{
		Issuer:            Issuer{ID: "did:agent:test"},
		Principal:         Principal{ID: "did:user:test"},
		Action:            Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:           Outcome{Status: StatusSuccess},
		Chain:             Chain{Sequence: count, PreviousReceiptHash: prevHash, ChainID: "chain-1"},
		Terminal:          true,
		TerminationStatus: status,
	})
	signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	return append(chain, signed)
}

func TestChainStatusCompleteByDefault(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChainWithTerminal(t, kp, 3)
	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Fatalf("chain should be valid: %s", result.Error)
	}
	if result.Status != ChainStatusComplete {
		t.Errorf("expected Status=%q, got %q", ChainStatusComplete, result.Status)
	}
	// Wire form: no status field emitted when not explicitly set.
	if chain[len(chain)-1].CredentialSubject.Chain.Status != "" {
		t.Errorf("terminal receipt without TerminationStatus must have empty Chain.Status on the wire, got %q", chain[len(chain)-1].CredentialSubject.Chain.Status)
	}
}

func TestChainStatusComplete(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChainWithStatus(t, kp, 3, ChainStatusComplete)
	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Fatalf("chain should be valid: %s", result.Error)
	}
	if result.Status != ChainStatusComplete {
		t.Errorf("expected Status=%q, got %q", ChainStatusComplete, result.Status)
	}
	if chain[len(chain)-1].CredentialSubject.Chain.Status != ChainStatusComplete {
		t.Errorf("wire form: expected Chain.Status=%q, got %q", ChainStatusComplete, chain[len(chain)-1].CredentialSubject.Chain.Status)
	}
}

func TestChainStatusInterrupted(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChainWithStatus(t, kp, 3, ChainStatusInterrupted)
	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Fatalf("chain should be valid: %s", result.Error)
	}
	if result.Status != ChainStatusInterrupted {
		t.Errorf("expected Status=%q, got %q", ChainStatusInterrupted, result.Status)
	}
	if chain[len(chain)-1].CredentialSubject.Chain.Status != ChainStatusInterrupted {
		t.Errorf("wire form: expected Chain.Status=%q, got %q", ChainStatusInterrupted, chain[len(chain)-1].CredentialSubject.Chain.Status)
	}
}

func TestChainStatusUnknownNoTerminal(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 3)
	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Fatalf("chain should be valid: %s", result.Error)
	}
	if result.Status != ChainStatusUnknown {
		t.Errorf("expected Status=%q, got %q", ChainStatusUnknown, result.Status)
	}
}

func TestChainStatusUnknownEmpty(t *testing.T) {
	kp, _ := GenerateKeyPair()
	result := VerifyChain([]AgentReceipt{}, kp.PublicKey)
	if !result.Valid {
		t.Fatalf("empty chain should be valid: %s", result.Error)
	}
	if result.Status != ChainStatusUnknown {
		t.Errorf("expected Status=%q, got %q", ChainStatusUnknown, result.Status)
	}
}

// Status reflects what the chain claims on the wire, not its validity.
func TestChainStatusIndependentOfValidity(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChainWithStatus(t, kp, 3, ChainStatusInterrupted)
	// Tamper with the middle receipt.
	chain[1].CredentialSubject.Action.RiskLevel = RiskCritical

	result := VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Fatal("tampered chain should be invalid")
	}
	if result.Status != ChainStatusInterrupted {
		t.Errorf("expected Status=%q even on invalid chain, got %q", ChainStatusInterrupted, result.Status)
	}
}

// MarshalJSON silently drops chain.status when terminal is unset (spec §7.3.3).
func TestChainStatusDroppedWithoutTerminal(t *testing.T) {
	c := Chain{
		Sequence:            1,
		PreviousReceiptHash: nil,
		ChainID:             "chain-1",
		Status:              ChainStatusInterrupted, // Set without Terminal — should be dropped on marshal.
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "status") {
		t.Errorf("status must be dropped from JSON when terminal is unset, got: %s", data)
	}
}

// MarshalJSON also drops chain.status when the value is not a valid wire
// vocabulary entry — including ChainStatusUnknown, which is verifier-only.
func TestChainStatusDroppedForInvalidWireValue(t *testing.T) {
	terminal := true
	cases := []ChainStatus{ChainStatusUnknown, ChainStatus("garbage"), ChainStatus("")}
	for _, status := range cases {
		c := Chain{
			Sequence:            1,
			PreviousReceiptHash: nil,
			ChainID:             "chain-1",
			Terminal:            &terminal,
			Status:              status,
		}
		data, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("Status=%q: %v", status, err)
		}
		if strings.Contains(string(data), `"status"`) {
			t.Errorf("Status=%q must be dropped from wire form, got: %s", status, data)
		}
	}
}

// Create() drops TerminationStatus when it is not a valid wire vocabulary entry.
func TestCreateDropsInvalidTerminationStatus(t *testing.T) {
	cases := []ChainStatus{ChainStatusUnknown, ChainStatus("garbage")}
	for _, status := range cases {
		unsigned := Create(CreateInput{
			Issuer:            Issuer{ID: "did:agent:test"},
			Principal:         Principal{ID: "did:user:test"},
			Action:            Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
			Outcome:           Outcome{Status: StatusSuccess},
			Chain:             Chain{Sequence: 1, PreviousReceiptHash: nil, ChainID: "chain-1"},
			Terminal:          true,
			TerminationStatus: status,
		})
		if unsigned.CredentialSubject.Chain.Status != "" {
			t.Errorf("invalid TerminationStatus=%q must be silently dropped, got Chain.Status=%q",
				status, unsigned.CredentialSubject.Chain.Status)
		}
	}
}

// VerifyChain rejects schema-invalid chain.status values smuggled in via direct
// struct mutation (or external JSON deserialisation). Mirrors the Python model
// validator: the SDK enforces spec §7.3.3 symmetrically on both issuer and
// verifier sides.
func TestVerifyRejectsInvalidChainStatusValue(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChainWithStatus(t, kp, 3, ChainStatusInterrupted)
	// Mutate the terminal receipt's chain.status to a non-wire value after signing.
	// We re-sign to ensure the signature itself is still valid; only the status
	// field is schema-invalid.
	chain[len(chain)-1].CredentialSubject.Chain.Status = "garbage"
	unsigned := UnsignedAgentReceipt{
		Context:           chain[len(chain)-1].Context,
		ID:                chain[len(chain)-1].ID,
		Type:              chain[len(chain)-1].Type,
		Version:           chain[len(chain)-1].Version,
		Issuer:            chain[len(chain)-1].Issuer,
		IssuanceDate:      chain[len(chain)-1].IssuanceDate,
		CredentialSubject: chain[len(chain)-1].CredentialSubject,
	}
	resigned, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	chain[len(chain)-1] = resigned

	result := VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Fatal("verifier must reject schema-invalid chain.status")
	}
	if !strings.Contains(result.Error, "invalid chain.status value") {
		t.Errorf("expected schema-invalid error message, got: %s", result.Error)
	}
}

// VerifyChain rejects chain.status set without chain.terminal: true.
func TestVerifyRejectsStatusWithoutTerminal(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 3)
	// Mutate the last receipt: set status without terminal, then re-sign.
	chain[len(chain)-1].CredentialSubject.Chain.Status = ChainStatusInterrupted
	unsigned := UnsignedAgentReceipt{
		Context:           chain[len(chain)-1].Context,
		ID:                chain[len(chain)-1].ID,
		Type:              chain[len(chain)-1].Type,
		Version:           chain[len(chain)-1].Version,
		Issuer:            chain[len(chain)-1].Issuer,
		IssuanceDate:      chain[len(chain)-1].IssuanceDate,
		CredentialSubject: chain[len(chain)-1].CredentialSubject,
	}
	resigned, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	chain[len(chain)-1] = resigned

	result := VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Fatal("verifier must reject chain.status without chain.terminal: true")
	}
	if !strings.Contains(result.Error, "chain.status without chain.terminal") {
		t.Errorf("expected status-without-terminal error message, got: %s", result.Error)
	}
}

// --- Chain identifier binding (spec §7.3.4, #477) ---

// buildChainWithID is like buildChain but lets the test choose chain_id and
// the starting sequence/previous hash. Used to construct cross-chain splices.
func buildChainWithID(t *testing.T, kp KeyPair, count int, chainID string, startSeq int, startPrevHash *string) []AgentReceipt {
	t.Helper()
	chain := make([]AgentReceipt, 0, count)
	prevHash := startPrevHash
	for i := 0; i < count; i++ {
		seq := startSeq + i
		unsigned := Create(CreateInput{
			Issuer:    Issuer{ID: "did:agent:test"},
			Principal: Principal{ID: "did:user:test"},
			Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
			Outcome:   Outcome{Status: StatusSuccess},
			Chain:     Chain{Sequence: seq, PreviousReceiptHash: prevHash, ChainID: chainID},
		})
		signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, signed)
		h, err := HashReceipt(signed)
		if err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}
	return chain
}

func TestChainIDBindingSingleChainPasses(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChainWithID(t, kp, 3, "chain-A", 1, nil)
	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Fatalf("single-chain input should be valid: %s", result.Error)
	}
	if result.BrokenAt != -1 {
		t.Errorf("expected BrokenAt=-1, got %d", result.BrokenAt)
	}
}

// Even when an attacker forges a valid-looking hash link between two chains,
// the verifier MUST reject because chain_id differs (spec §7.3.4).
func TestChainIDBindingRejectsCrossChainSplice(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chainA := buildChainWithID(t, kp, 2, "chain-A", 1, nil)
	lastA := chainA[len(chainA)-1]
	spliceHash, err := HashReceipt(lastA)
	if err != nil {
		t.Fatal(err)
	}
	chainB := buildChainWithID(t, kp, 2, "chain-B", 3, &spliceHash)
	input := append([]AgentReceipt{}, chainA...)
	input = append(input, chainB...)

	result := VerifyChain(input, kp.PublicKey)
	if result.Valid {
		t.Fatal("cross-chain splice must be rejected")
	}
	if result.BrokenAt != 2 {
		t.Errorf("expected BrokenAt=2 (first mismatched index), got %d", result.BrokenAt)
	}
	if !strings.Contains(result.Error, "chain_id mismatch at index 2") {
		t.Errorf("expected error to identify mismatch index, got: %s", result.Error)
	}
	if !strings.Contains(result.Error, `"chain-A"`) || !strings.Contains(result.Error, `"chain-B"`) {
		t.Errorf("expected error to include both chain_ids, got: %s", result.Error)
	}
}

// A single off-chain receipt spliced into the middle (with signatures still
// valid for its own chain_id) must be rejected solely on chain_id.
//
// Isolation note: this test confirms the chain would otherwise verify
// cleanly; the only failure mode is the chain_id binding check. We re-sign
// the middle receipt with a different chain_id AND re-link and re-sign the
// trailing receipt so its previous_receipt_hash points at the middle's new
// hash — keeping hash linkage valid so the sole invariant violated is
// chain_id binding (not collateral hash breakage).
func TestChainIDBindingRejectsSingleMismatchedReceipt(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChainWithID(t, kp, 3, "chain-A", 1, nil)
	// Re-sign the middle receipt with chain_id="chain-other" so its signature
	// is still valid against kp.PublicKey but the chain_id differs.
	middle := chain[1]
	middle.CredentialSubject.Chain.ChainID = "chain-other"
	resigned, err := Sign(UnsignedAgentReceipt{
		Context:           middle.Context,
		ID:                middle.ID,
		Type:              middle.Type,
		Version:           middle.Version,
		Issuer:            middle.Issuer,
		IssuanceDate:      middle.IssuanceDate,
		CredentialSubject: middle.CredentialSubject,
	}, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	chain[1] = resigned

	// Re-link the trailing receipt to the re-signed middle so hash linkage
	// stays valid; its chain_id remains "chain-A".
	middleHash, err := HashReceipt(resigned)
	if err != nil {
		t.Fatal(err)
	}
	tail := chain[2]
	tail.CredentialSubject.Chain.PreviousReceiptHash = &middleHash
	resignedTail, err := Sign(UnsignedAgentReceipt{
		Context:           tail.Context,
		ID:                tail.ID,
		Type:              tail.Type,
		Version:           tail.Version,
		Issuer:            tail.Issuer,
		IssuanceDate:      tail.IssuanceDate,
		CredentialSubject: tail.CredentialSubject,
	}, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	chain[2] = resignedTail

	result := VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Fatal("mismatched chain_id must be rejected")
	}
	if !strings.Contains(result.Error, "chain_id mismatch at index 1") {
		t.Errorf("expected error to identify mismatch index, got: %s", result.Error)
	}
	if !strings.Contains(result.Error, `"chain-A"`) || !strings.Contains(result.Error, `"chain-other"`) {
		t.Errorf("expected error to include both chain_ids, got: %s", result.Error)
	}
}

// --- Incomplete tool roundtrip (ADR-0019 §O3, retained by ADR-0020) ---

// buildPendingTail builds a valid `count`-receipt chain whose final,
// non-terminal receipt carries outcome.status == pending — modelling a tool
// call whose result receipt never arrived.
func buildPendingTail(t *testing.T, kp KeyPair, count int) []AgentReceipt {
	t.Helper()
	chain := make([]AgentReceipt, 0, count)
	var prevHash *string
	for i := 1; i <= count; i++ {
		status := StatusSuccess
		if i == count {
			status = StatusPending
		}
		unsigned := Create(CreateInput{
			Issuer:    Issuer{ID: "did:agent:test"},
			Principal: Principal{ID: "did:user:test"},
			Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
			Outcome:   Outcome{Status: status},
			Chain:     Chain{Sequence: i, PreviousReceiptHash: prevHash, ChainID: "chain-1"},
		})
		signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, signed)
		h, err := HashReceipt(signed)
		if err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}
	return chain
}

func TestIncompleteToolRoundtripFlagsPendingTail(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildPendingTail(t, kp, 3)

	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Errorf("pending tail must not break verification; broken at %d: %s", result.BrokenAt, result.Error)
	}
	if !result.IncompleteToolRoundtrip {
		t.Error("expected IncompleteToolRoundtrip=true for a pending non-terminal tail")
	}
}

func TestIncompleteToolRoundtripIgnoresCompletedTail(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 3) // all StatusSuccess

	result := VerifyChain(chain, kp.PublicKey)
	if result.IncompleteToolRoundtrip {
		t.Error("expected IncompleteToolRoundtrip=false for a completed tail")
	}
}

func TestIncompleteToolRoundtripIgnoresNonFinalPending(t *testing.T) {
	kp, _ := GenerateKeyPair()
	// Build a 3-receipt chain whose MIDDLE receipt is pending but the final one
	// is success — only the final receipt's status is consulted.
	chain := make([]AgentReceipt, 0, 3)
	var prevHash *string
	for i := 1; i <= 3; i++ {
		status := StatusSuccess
		if i == 2 {
			status = StatusPending
		}
		unsigned := Create(CreateInput{
			Issuer:    Issuer{ID: "did:agent:test"},
			Principal: Principal{ID: "did:user:test"},
			Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
			Outcome:   Outcome{Status: status},
			Chain:     Chain{Sequence: i, PreviousReceiptHash: prevHash, ChainID: "chain-1"},
		})
		signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, signed)
		h, err := HashReceipt(signed)
		if err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	result := VerifyChain(chain, kp.PublicKey)
	if result.IncompleteToolRoundtrip {
		t.Error("expected IncompleteToolRoundtrip=false when only a non-final receipt is pending")
	}
}

func TestIncompleteToolRoundtripIgnoresTerminalPending(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 2)
	terminalHash, err := HashReceipt(chain[len(chain)-1])
	if err != nil {
		t.Fatal(err)
	}
	// Final receipt is terminal AND pending — a deliberate close, not flagged.
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusPending},
		Chain:     Chain{Sequence: 3, PreviousReceiptHash: &terminalHash, ChainID: "chain-1"},
		Terminal:  true,
	})
	signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	chain = append(chain, signed)

	result := VerifyChain(chain, kp.PublicKey)
	if result.IncompleteToolRoundtrip {
		t.Error("expected IncompleteToolRoundtrip=false for a terminal pending receipt")
	}
}

func TestIncompleteToolRoundtripEmptyChain(t *testing.T) {
	kp, _ := GenerateKeyPair()
	result := VerifyChain(nil, kp.PublicKey)
	if result.IncompleteToolRoundtrip {
		t.Error("expected IncompleteToolRoundtrip=false for an empty chain")
	}
}

// buildPTYChain builds a chain with a pty.open receipt followed optionally by
// a pty.close receipt. Used for IncompleteSession tests.
func buildPTYChain(t *testing.T, kp KeyPair, withClose bool) []AgentReceipt {
	t.Helper()
	chain := buildChain(t, kp, 2) // two ordinary receipts first
	prevHash, err := HashReceipt(chain[len(chain)-1])
	if err != nil {
		t.Fatal(err)
	}

	openUnsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: ActionTypePTYOpen, RiskLevel: RiskCritical},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 3, PreviousReceiptHash: &prevHash, ChainID: "chain-1"},
	})
	openSigned, err := Sign(openUnsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	chain = append(chain, openSigned)

	if withClose {
		openHash, err := HashReceipt(openSigned)
		if err != nil {
			t.Fatal(err)
		}
		closeUnsigned := Create(CreateInput{
			Issuer:    Issuer{ID: "did:agent:test"},
			Principal: Principal{ID: "did:user:test"},
			Action:    Action{Type: ActionTypePTYClose, RiskLevel: RiskHigh},
			Outcome:   Outcome{Status: StatusSuccess},
			Chain:     Chain{Sequence: 4, PreviousReceiptHash: &openHash, ChainID: "chain-1"},
		})
		closeSigned, err := Sign(closeUnsigned, kp.PrivateKey, "did:agent:test#key-1")
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, closeSigned)
	}
	return chain
}

func TestIncompleteSessionFlagsMissingClose(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildPTYChain(t, kp, false)

	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Errorf("missing pty.close must not break verification; broken at %d: %s", result.BrokenAt, result.Error)
	}
	if !result.IncompleteSession {
		t.Error("expected IncompleteSession=true when pty.open has no pty.close")
	}
}

func TestIncompleteSessionClearedByClose(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildPTYChain(t, kp, true)

	result := VerifyChain(chain, kp.PublicKey)
	if result.IncompleteSession {
		t.Error("expected IncompleteSession=false when pty.open is matched by pty.close")
	}
}

func TestIncompleteSessionNoPTYReceipts(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 4)

	result := VerifyChain(chain, kp.PublicKey)
	if result.IncompleteSession {
		t.Error("expected IncompleteSession=false when chain has no PTY receipts")
	}
}

func TestIncompleteSessionEmptyChain(t *testing.T) {
	result := VerifyChain(nil, "")
	if result.IncompleteSession {
		t.Error("expected IncompleteSession=false for empty chain")
	}
}

func TestIncompleteSessionIsAdvisory(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildPTYChain(t, kp, false)

	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Errorf("IncompleteSession must not affect Valid; got Valid=false: %s", result.Error)
	}
	if !result.IncompleteSession {
		t.Error("expected IncompleteSession=true")
	}
}

func TestIncompleteSessionOrphanedClose(t *testing.T) {
	// A chain with a pty.close but no prior pty.open (e.g. a replayed close
	// receipt or a chain viewed after its open was truncated) must also be
	// flagged — closes > opens is equally anomalous to opens > closes.
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 2)
	prevHash, err := HashReceipt(chain[len(chain)-1])
	if err != nil {
		t.Fatal(err)
	}
	closeUnsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: ActionTypePTYClose, RiskLevel: RiskHigh},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 3, PreviousReceiptHash: &prevHash, ChainID: "chain-1"},
	})
	closeSigned, err := Sign(closeUnsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	chain = append(chain, closeSigned)

	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Errorf("orphaned close must not break verification; broken at %d: %s", result.BrokenAt, result.Error)
	}
	if !result.IncompleteSession {
		t.Error("expected IncompleteSession=true for closes > opens (orphaned close)")
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || findStr(s, sub))
}

func findStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
