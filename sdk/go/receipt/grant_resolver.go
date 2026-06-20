package receipt

import (
	"reflect"
	"time"
)

// GrantInfo is the resolved representation of an externally-minted
// authorization grant (e.g. an RFC 8693 OBO token or a Grantex grant token).
// GrantResolver implementations MUST populate at minimum Subject; the
// remaining fields are advisory and MAY be zero when the resolver's backend
// does not expose them.
type GrantInfo struct {
	// Subject is the principal on whose behalf the grant was issued.
	// MUST equal credentialSubject.principal.id for the grounded-principal
	// tier check to pass.
	Subject string
	// Scopes are the authorization scopes active under the grant.
	Scopes []string
	// IssuedAt is when the authorization server minted the grant.
	IssuedAt time.Time
	// ExpiresAt is when the grant expires. Zero value means no expiry recorded.
	ExpiresAt time.Time
	// Issuer identifies the authorization server that minted the grant.
	Issuer string
}

// GrantResolver resolves an authorization grant reference to its minted
// grant, confirming the named principal delegated authority to the agent.
//
// Input:
//   - grantRef is the authorization.grant_ref value from the receipt.
//   - principalID is the credentialSubject.principal.id from the receipt
//     (supplied as a hint; resolvers MAY use it to select a cached entry).
//
// Output: the resolved GrantInfo, or a non-nil error on resolution failure
// (network error, token not found, token revoked, etc.).
//
// Implementations MAY perform network I/O (token introspection, OIDC
// userinfo). Caching is an implementation concern. Side-effect freedom is
// NOT required: a resolver MAY log, meter, or cache resolutions.
//
// The SDK ships this interface only. Integrators supply a resolver for their
// authorization server (RFC 8693 token introspection, OIDC, Grantex). The
// project does not endorse a single authorization server, mirroring the
// ADR-0007 stance on DID methods.
type GrantResolver interface {
	ResolveGrant(grantRef, principalID string) (GrantInfo, error)
}

// GroundedOutcome is the result of a grounded-principal tier check on a
// single receipt (spec §7.9, ADR-0038).
type GroundedOutcome string

const (
	// GroundedOutcomeUngrounded is returned when a high/critical receipt lacks
	// a resolvable grant_ref. Corresponds to UNGROUNDED_PRINCIPAL in spec §7.9.
	GroundedOutcomeUngrounded GroundedOutcome = "UNGROUNDED_PRINCIPAL"
	// GroundedOutcomeMismatch is returned when the resolved grant's subject
	// does not equal the receipt's principal.id. Corresponds to
	// PRINCIPAL_GRANT_MISMATCH in spec §7.9.
	GroundedOutcomeMismatch GroundedOutcome = "PRINCIPAL_GRANT_MISMATCH"
)

// GroundedPrincipalViolation records a grounded-principal tier failure for a
// single receipt.
type GroundedPrincipalViolation struct {
	// Index is the position of the offending receipt in the input slice.
	Index int
	// ReceiptID is the receipt's id field.
	ReceiptID string
	// PrincipalID is the receipt's credentialSubject.principal.id.
	PrincipalID string
	// GrantRef is the authorization.grant_ref value (may be empty for
	// UNGROUNDED_PRINCIPAL violations where no grant_ref is present).
	GrantRef string
	// Outcome is the specific failure: UNGROUNDED_PRINCIPAL or
	// PRINCIPAL_GRANT_MISMATCH.
	Outcome GroundedOutcome
	// Detail carries a human-readable description of the failure, including
	// resolver error messages for UNGROUNDED_PRINCIPAL resolution failures.
	Detail string
}

// VerifyGroundedPrincipalTier applies the grounded-principal conformance tier
// checks (spec §7.9, ADR-0038 D1–D3) to a set of receipts.
//
// For each receipt whose action.risk_level is "high" or "critical":
//  1. If authorization.grant_ref is absent or empty → UNGROUNDED_PRINCIPAL.
//  2. If the resolver returns an error → UNGROUNDED_PRINCIPAL.
//  3. If the resolved grant's Subject ≠ principal.id → PRINCIPAL_GRANT_MISMATCH.
//
// Receipts at risk_level "low" or "medium" are not checked.
//
// When resolver is nil, no checks are performed and an empty slice is
// returned — this is the correct behaviour for base-tier verifiers that
// have not configured a resolver (ADR-0038 D3: "absence of a resolver in
// the base tier is not a verification failure").
//
// All violations are collected and returned; the function does not stop at
// the first failure so callers get a complete picture of the tier's state.
// isNilResolver reports whether r is nil, handling both untyped nils and
// typed nils (e.g. (*MyResolver)(nil) wrapped in a GrantResolver interface).
// Calling IsNil on a non-nilable kind panics, so the kind is checked first.
func isNilResolver(r GrantResolver) bool {
	if r == nil {
		return true
	}
	v := reflect.ValueOf(r)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Chan, reflect.Func, reflect.Map, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func VerifyGroundedPrincipalTier(receipts []AgentReceipt, resolver GrantResolver) []GroundedPrincipalViolation {
	if isNilResolver(resolver) {
		return nil
	}

	var violations []GroundedPrincipalViolation

	for i, r := range receipts {
		rl := r.CredentialSubject.Action.RiskLevel
		if rl != RiskHigh && rl != RiskCritical {
			continue
		}

		principalID := r.CredentialSubject.Principal.ID
		auth := r.CredentialSubject.Authorization

		// Step 1: grant_ref must be present and non-empty.
		if auth == nil || auth.GrantRef == "" {
			violations = append(violations, GroundedPrincipalViolation{
				Index:       i,
				ReceiptID:   r.ID,
				PrincipalID: principalID,
				Outcome:     GroundedOutcomeUngrounded,
				Detail:      "authorization.grant_ref is absent on a " + string(rl) + " receipt",
			})
			continue
		}

		grantRef := auth.GrantRef

		// Step 2: resolve the grant.
		grant, err := resolver.ResolveGrant(grantRef, principalID)
		if err != nil {
			violations = append(violations, GroundedPrincipalViolation{
				Index:       i,
				ReceiptID:   r.ID,
				PrincipalID: principalID,
				GrantRef:    grantRef,
				Outcome:     GroundedOutcomeUngrounded,
				Detail:      "grant resolution failed: " + err.Error(),
			})
			continue
		}

		// Step 3: subject must equal principal.id.
		if grant.Subject != principalID {
			violations = append(violations, GroundedPrincipalViolation{
				Index:       i,
				ReceiptID:   r.ID,
				PrincipalID: principalID,
				GrantRef:    grantRef,
				Outcome:     GroundedOutcomeMismatch,
				Detail: "grant subject " + grant.Subject +
					" does not match principal.id " + principalID,
			})
		}
	}

	return violations
}
