package receipt

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// stubResolver is a GrantResolver used in tests. It maps grant_ref to a
// pre-built GrantInfo (or an error if the key maps to an error sentinel).
type stubResolver struct {
	grants map[string]GrantInfo
	// errorRefs maps grant_ref strings that should return an error.
	errorRefs map[string]struct{}
}

func (s *stubResolver) ResolveGrant(grantRef, _ string) (GrantInfo, error) {
	if _, bad := s.errorRefs[grantRef]; bad {
		return GrantInfo{}, errors.New("resolver: grant not found")
	}
	if g, ok := s.grants[grantRef]; ok {
		return g, nil
	}
	return GrantInfo{}, errors.New("resolver: unknown grant ref")
}

// validGrant is a well-formed grant for subject, in force around now.
func validGrant(subject string) GrantInfo {
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	return GrantInfo{
		Subject:    subject,
		Scopes:     []string{"files:write"},
		ValidFrom:  now.Add(-time.Hour),
		ExpiresAt:  &exp,
		Revocation: RevocationNotRevoked,
		Issuer:     "https://auth.example.com",
	}
}

// failures returns the results that are not grounded.
func failures(results []GroundedResult) []GroundedResult {
	var out []GroundedResult
	for _, r := range results {
		if !r.Grounded() {
			out = append(out, r)
		}
	}
	return out
}

// verify runs the tier with default options and fails the test on error.
func verify(t *testing.T, receipts []AgentReceipt, resolver GrantResolver) []GroundedResult {
	t.Helper()
	results, err := VerifyGroundedPrincipalTier(receipts, resolver, GroundedOptions{})
	if err != nil {
		t.Fatalf("VerifyGroundedPrincipalTier: %v", err)
	}
	return results
}

func makeGroundedReceipt(t *testing.T, kp KeyPair, principalID string, riskLevel RiskLevel, grantRef string) AgentReceipt {
	t.Helper()

	var auth *Authorization
	if grantRef != "" {
		auth = &Authorization{
			Scopes:    []string{"files:write"},
			GrantedAt: time.Now().UTC().Format(time.RFC3339),
			GrantRef:  grantRef,
		}
	}

	unsigned := Create(CreateInput{
		Issuer:        Issuer{ID: "did:key:z6Mk1"},
		Principal:     Principal{ID: principalID},
		Action:        Action{Type: "filesystem.file.write", RiskLevel: riskLevel},
		Outcome:       Outcome{Status: StatusSuccess},
		Authorization: auth,
		Chain:         Chain{Sequence: 1, PreviousReceiptHash: nil, ChainID: "chain-grounded-1"},
	})
	signed, err := Sign(unsigned, kp.PrivateKey, "did:key:z6Mk1#key-1")
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// TestGrantInfoFields verifies the GrantInfo struct carries the expected fields.
func TestGrantInfoFields(t *testing.T) {
	g := validGrant("did:user:alice")
	if g.Subject != "did:user:alice" {
		t.Errorf("unexpected Subject: %s", g.Subject)
	}
	if len(g.Scopes) != 1 || g.Scopes[0] != "files:write" {
		t.Errorf("unexpected Scopes: %v", g.Scopes)
	}
}

// TestVerifyGroundedPrincipalTier_NoResolver returns no violations when no
// resolver is configured (base-tier verifier).
func TestVerifyGroundedPrincipalTier_NoResolver(t *testing.T) {
	kp, _ := GenerateKeyPair()
	r := makeGroundedReceipt(t, kp, "did:user:alice", RiskHigh, "")
	violations := verify(t, []AgentReceipt{r}, nil)
	if len(violations) != 0 {
		t.Errorf("expected no violations without resolver, got %d", len(violations))
	}
}

// TestVerifyGroundedPrincipalTier_LowMediumSkipped confirms low/medium receipts
// are not checked even when a resolver is configured.
func TestVerifyGroundedPrincipalTier_LowMediumSkipped(t *testing.T) {
	kp, _ := GenerateKeyPair()
	resolver := &stubResolver{grants: map[string]GrantInfo{}}
	lowR := makeGroundedReceipt(t, kp, "did:user:alice", RiskLow, "")
	medR := makeGroundedReceipt(t, kp, "did:user:alice", RiskMedium, "")
	violations := verify(t, []AgentReceipt{lowR, medR}, resolver)
	if len(violations) != 0 {
		t.Errorf("expected no violations for low/medium receipts, got %d", len(violations))
	}
}

// TestVerifyGroundedPrincipalTier_MissingGrantRef produces UNGROUNDED_PRINCIPAL
// for a high receipt with no grant_ref.
func TestVerifyGroundedPrincipalTier_MissingGrantRef(t *testing.T) {
	kp, _ := GenerateKeyPair()
	resolver := &stubResolver{grants: map[string]GrantInfo{}}
	r := makeGroundedReceipt(t, kp, "did:user:alice", RiskHigh, "")
	violations := failures(verify(t, []AgentReceipt{r}, resolver))
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Outcome != GroundedOutcomeUngrounded {
		t.Errorf("expected UNGROUNDED_PRINCIPAL, got %s", violations[0].Outcome)
	}
}

// TestVerifyGroundedPrincipalTier_ResolutionFailure produces UNGROUNDED_PRINCIPAL
// when the resolver cannot resolve the grant_ref.
func TestVerifyGroundedPrincipalTier_ResolutionFailure(t *testing.T) {
	kp, _ := GenerateKeyPair()
	resolver := &stubResolver{
		grants:    map[string]GrantInfo{},
		errorRefs: map[string]struct{}{"bad-ref": {}},
	}
	r := makeGroundedReceipt(t, kp, "did:user:alice", RiskHigh, "bad-ref")
	violations := failures(verify(t, []AgentReceipt{r}, resolver))
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Outcome != GroundedOutcomeUngrounded {
		t.Errorf("expected UNGROUNDED_PRINCIPAL, got %s", violations[0].Outcome)
	}
}

// TestVerifyGroundedPrincipalTier_PrincipalMismatch produces PRINCIPAL_GRANT_MISMATCH
// when the resolved grant subject does not equal principal.id.
func TestVerifyGroundedPrincipalTier_PrincipalMismatch(t *testing.T) {
	kp, _ := GenerateKeyPair()
	resolver := &stubResolver{
		grants: map[string]GrantInfo{
			"grant-abc": validGrant("did:user:bob"), // mismatch: receipt says alice
		},
	}
	r := makeGroundedReceipt(t, kp, "did:user:alice", RiskHigh, "grant-abc")
	violations := failures(verify(t, []AgentReceipt{r}, resolver))
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Outcome != GroundedOutcomeMismatch {
		t.Errorf("expected PRINCIPAL_GRANT_MISMATCH, got %s", violations[0].Outcome)
	}
}

// TestVerifyGroundedPrincipalTier_ValidGrounding produces no violation when
// grant resolves and subject equals principal.id.
func TestVerifyGroundedPrincipalTier_ValidGrounding(t *testing.T) {
	kp, _ := GenerateKeyPair()
	resolver := &stubResolver{
		grants: map[string]GrantInfo{
			"grant-xyz": validGrant("did:user:alice"),
		},
	}
	r := makeGroundedReceipt(t, kp, "did:user:alice", RiskHigh, "grant-xyz")
	violations := failures(verify(t, []AgentReceipt{r}, resolver))
	if len(violations) != 0 {
		t.Errorf("expected no violations for grounded receipt, got %d", len(violations))
	}
}

// TestVerifyGroundedPrincipalTier_CriticalAlsoChecked verifies critical receipts
// are included in the tier checks alongside high receipts.
func TestVerifyGroundedPrincipalTier_CriticalAlsoChecked(t *testing.T) {
	kp, _ := GenerateKeyPair()
	resolver := &stubResolver{grants: map[string]GrantInfo{}}
	r := makeGroundedReceipt(t, kp, "did:user:alice", RiskCritical, "")
	violations := failures(verify(t, []AgentReceipt{r}, resolver))
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation for critical receipt without grant_ref, got %d", len(violations))
	}
	if violations[0].Outcome != GroundedOutcomeUngrounded {
		t.Errorf("expected UNGROUNDED_PRINCIPAL, got %s", violations[0].Outcome)
	}
}

// TestVerifyGroundedPrincipalTier_MultipleViolations surfaces all violations,
// not just the first.
func TestVerifyGroundedPrincipalTier_MultipleViolations(t *testing.T) {
	kp, _ := GenerateKeyPair()
	resolver := &stubResolver{
		grants: map[string]GrantInfo{
			"grant-good": validGrant("did:user:alice"),
		},
		errorRefs: map[string]struct{}{"grant-bad": {}},
	}
	r1 := makeGroundedReceipt(t, kp, "did:user:alice", RiskHigh, "")              // UNGROUNDED
	r2 := makeGroundedReceipt(t, kp, "did:user:alice", RiskHigh, "grant-good")    // OK
	r3 := makeGroundedReceipt(t, kp, "did:user:alice", RiskCritical, "grant-bad") // UNGROUNDED (resolution fails)
	results := verify(t, []AgentReceipt{r1, r2, r3}, resolver)
	if len(results) != 3 {
		t.Errorf("expected a result for each of 3 checked receipts, got %d", len(results))
	}
	violations := failures(results)
	if len(violations) != 2 {
		t.Errorf("expected 2 violations, got %d", len(violations))
	}
}

// TestVerifyGroundedPrincipalTier_ReceiptIndexReported confirms the violation
// records the correct receipt index.
func TestVerifyGroundedPrincipalTier_ReceiptIndexReported(t *testing.T) {
	kp, _ := GenerateKeyPair()
	resolver := &stubResolver{grants: map[string]GrantInfo{}}
	low := makeGroundedReceipt(t, kp, "did:user:alice", RiskLow, "")   // index 0, skipped
	high := makeGroundedReceipt(t, kp, "did:user:alice", RiskHigh, "") // index 1, violation
	violations := failures(verify(t, []AgentReceipt{low, high}, resolver))
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Index != 1 {
		t.Errorf("expected violation at index 1, got %d", violations[0].Index)
	}
}

// TestVerifyGroundedPrincipalTier_EmptyChain produces no violations for an
// empty receipt slice.
func TestVerifyGroundedPrincipalTier_EmptyChain(t *testing.T) {
	resolver := &stubResolver{grants: map[string]GrantInfo{}}
	violations := verify(t, nil, resolver)
	if len(violations) != 0 {
		t.Errorf("expected no violations for empty chain, got %d", len(violations))
	}
}

// TestVerifyGroundedPrincipalTier_TypedNilResolver confirms that a typed-nil
// resolver (a non-nil interface value whose concrete pointer is nil) is treated
// the same as a nil interface — no violations, no panic.
func TestVerifyGroundedPrincipalTier_TypedNilResolver(t *testing.T) {
	kp, _ := GenerateKeyPair()
	r := makeGroundedReceipt(t, kp, "did:user:alice", RiskHigh, "")

	var typed *stubResolver // typed nil: concrete type known, pointer is nil
	violations := verify(t, []AgentReceipt{r}, typed)
	if len(violations) != 0 {
		t.Errorf("expected no violations for typed-nil resolver, got %d", len(violations))
	}
}

// TestVerifyGroundedPrincipalTier_GroundedDetailNamesTimeSource checks that a
// grounded result says its validity rests on the issuer-asserted action time
// (spec §7.9.3).
func TestVerifyGroundedPrincipalTier_GroundedDetailNamesTimeSource(t *testing.T) {
	kp, _ := GenerateKeyPair()
	resolver := &stubResolver{grants: map[string]GrantInfo{"grant-xyz": validGrant("did:user:alice")}}
	r := makeGroundedReceipt(t, kp, "did:user:alice", RiskHigh, "grant-xyz")
	results := verify(t, []AgentReceipt{r}, resolver)
	if len(results) != 1 || !results[0].Grounded() {
		t.Fatalf("expected one grounded result, got %+v", results)
	}
	if !strings.Contains(results[0].Detail, "issuer-asserted action time") {
		t.Errorf("grounded detail %q does not name the time source", results[0].Detail)
	}
}

// TestVerifyGroundedPrincipalTier_NegativeSkewWithoutResolver confirms the
// option is validated even in the base tier.
func TestVerifyGroundedPrincipalTier_NegativeSkewWithoutResolver(t *testing.T) {
	_, err := VerifyGroundedPrincipalTier(nil, nil, GroundedOptions{ClockSkew: -time.Millisecond})
	if !errors.Is(err, ErrNegativeClockSkew) {
		t.Errorf("err = %v, want ErrNegativeClockSkew", err)
	}
}
