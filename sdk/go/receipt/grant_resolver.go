package receipt

import (
	"errors"
	"reflect"
	"slices"
	"time"
)

// Revocation is a resolved grant's revocation status (spec §7.9.1).
type Revocation string

const (
	// RevocationNotRevoked means the grant was not revoked as of resolution,
	// which covers any earlier action.
	RevocationNotRevoked Revocation = "not_revoked"
	// RevocationRevoked means the grant has been revoked. RevokedAt carries
	// the time when the resolver knows it.
	RevocationRevoked Revocation = "revoked"
	// RevocationUnknown means the resolver cannot see revocation, for example
	// because it only verifies a JWT access token.
	RevocationUnknown Revocation = "unknown"
)

// GrantInfo is the resolved representation of an externally-minted
// authorization grant, such as an RFC 8693 token-exchange token or a Grantex
// grant token (spec §7.9.1, ADR-0041 D2).
//
// Subject, Scopes, ValidFrom, Revocation and Issuer are required. A grant
// that is missing one of them, has empty Scopes, has ExpiresAt not after
// ValidFrom, or has RevokedAt without RevocationRevoked is malformed, and the
// verifier treats it as a resolution failure.
type GrantInfo struct {
	// Subject is the principal the grant was issued for. It must equal
	// credentialSubject.principal.id.
	Subject string
	// Scopes are the scopes the grant conferred. Non-empty.
	Scopes []string
	// ValidFrom is when the grant took effect. For a JWT access token this is
	// nbf when present, otherwise iat.
	ValidFrom time.Time
	// ExpiresAt is when the grant expires. Nil means no expiry.
	ExpiresAt *time.Time
	// Revocation is the grant's revocation status. A resolver that cannot see
	// revocation must report RevocationUnknown, never leave it empty.
	Revocation Revocation
	// RevokedAt is when the grant was revoked, if known. Only allowed with
	// RevocationRevoked.
	RevokedAt *time.Time
	// Issuer identifies the authorization server that minted the grant.
	Issuer string
}

// GrantResolver resolves an authorization grant reference to the grant's
// terms (spec §7.9.1).
//
// Input:
//   - grantRef is the authorization.grant_ref value from the receipt.
//   - principalID is the credentialSubject.principal.id from the receipt
//     (supplied as a hint; resolvers MAY use it to select a cached entry).
//
// A grant that has expired or been revoked is still a resolved grant: when the
// resolver can establish its terms it must return them, not an error. Return
// a non-nil error only when the grant cannot be found, the backend cannot be
// reached, or its response cannot be interpreted. A resolver that learns only
// that a grant is inactive, without its terms (as with plain RFC 7662 token
// introspection), must return an error. Document whether your resolver returns
// the terms of lapsed grants and whether it can see revocation.
//
// Implementations MAY perform network I/O (token introspection, OIDC).
// Caching is an implementation concern. The SDK ships this interface only;
// integrators supply a resolver for their authorization server, mirroring the
// ADR-0007 stance on DID methods.
type GrantResolver interface {
	ResolveGrant(grantRef, principalID string) (GrantInfo, error)
}

// GroundedOutcome is the failure outcome of a grounded-principal tier check on
// a single receipt (spec §7.9.6). The empty value means the receipt is
// grounded.
type GroundedOutcome string

const (
	// GroundedOutcomeUngrounded: the receipt has no grant_ref, or its grant
	// cannot be resolved or is malformed.
	GroundedOutcomeUngrounded GroundedOutcome = "UNGROUNDED_PRINCIPAL"
	// GroundedOutcomeMismatch: the grant's subject does not equal principal.id.
	GroundedOutcomeMismatch GroundedOutcome = "PRINCIPAL_GRANT_MISMATCH"
	// GroundedOutcomeNotValidAtActionTime: the grant was not in force at the
	// action time.
	GroundedOutcomeNotValidAtActionTime GroundedOutcome = "GRANT_NOT_VALID_AT_ACTION_TIME"
	// GroundedOutcomeValidityUnresolved: the verifier cannot tell whether the
	// grant was in force at the action time.
	GroundedOutcomeValidityUnresolved GroundedOutcome = "GRANT_VALIDITY_UNRESOLVED"
	// GroundedOutcomeScopeExceeded: authorization.scopes contains a scope the
	// grant does not confer.
	GroundedOutcomeScopeExceeded GroundedOutcome = "GRANT_SCOPE_EXCEEDED"
)

// GroundedWarningCode identifies a warning raised alongside a grounded-tier
// result (spec §7.9.4). Warnings never change the outcome.
type GroundedWarningCode string

const (
	// WarningGrantedAtDisagrees: authorization.granted_at differs from the
	// grant's ValidFrom.
	WarningGrantedAtDisagrees GroundedWarningCode = "GRANTED_AT_DISAGREES"
	// WarningExpiresAtDisagrees: authorization.expires_at differs from the
	// grant's ExpiresAt, including when the grant has no expiry.
	WarningExpiresAtDisagrees GroundedWarningCode = "EXPIRES_AT_DISAGREES"
)

// GroundedWarning is a warning raised alongside a grounded-tier result.
type GroundedWarning struct {
	Code   GroundedWarningCode
	Detail string
}

// GroundedResult is the grounded-principal tier result for one checked
// receipt.
type GroundedResult struct {
	// Index is the receipt's position in the input slice.
	Index int
	// ReceiptID is the receipt's id.
	ReceiptID string
	// PrincipalID is the receipt's credentialSubject.principal.id.
	PrincipalID string
	// GrantRef is authorization.grant_ref; empty when absent.
	GrantRef string
	// Outcome is empty when the receipt is grounded.
	Outcome GroundedOutcome
	// Detail explains the outcome. For a grounded receipt it states that
	// validity was established at the issuer-asserted action time (§7.9.3).
	Detail string
	// Warnings are raised once the grant has resolved, whatever the outcome.
	Warnings []GroundedWarning
}

// Grounded reports whether the receipt passed every grounded-tier check.
func (r GroundedResult) Grounded() bool { return r.Outcome == "" }

// GroundedOptions configures [VerifyGroundedPrincipalTier].
type GroundedOptions struct {
	// ClockSkew is the tolerance δ applied around the action time (§7.9.3).
	// It is used at millisecond precision. Zero means exact comparison;
	// a negative value is a configuration error.
	ClockSkew time.Duration
}

// ErrNegativeClockSkew is returned when GroundedOptions.ClockSkew is negative.
var ErrNegativeClockSkew = errors.New("receipt: grounded-tier clock skew must not be negative")

// isNilResolver reports whether r is nil, including a typed nil: a non-nil
// interface value whose concrete pointer (or other nillable kind) is nil.
// Calling IsNil on a non-nillable kind panics, so the kind is checked first.
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

// VerifyGroundedPrincipalTier applies the grounded-principal tier checks
// (spec v0.7.0 §7.9, ADR-0038 and ADR-0041) and returns one result for every
// receipt it checks: those at risk level high or critical. Low and medium
// receipts are not checked and produce no result.
//
// For each checked receipt the steps run in order, and the first failure is
// the outcome: grant presence, grant resolution (including the malformed-
// grant rules), subject match, validity at the action time, and scope
// containment.
//
// A nil resolver, including a typed nil, means the verifier is in the base
// tier: no checks run and the result is empty. The only error is an invalid
// option.
func VerifyGroundedPrincipalTier(receipts []AgentReceipt, resolver GrantResolver, opts GroundedOptions) ([]GroundedResult, error) {
	if opts.ClockSkew < 0 {
		return nil, ErrNegativeClockSkew
	}
	if isNilResolver(resolver) {
		return []GroundedResult{}, nil
	}
	skewMs := opts.ClockSkew.Milliseconds()

	results := []GroundedResult{}
	for i, r := range receipts {
		rl := r.CredentialSubject.Action.RiskLevel
		if rl != RiskHigh && rl != RiskCritical {
			continue
		}
		res := GroundedResult{
			Index:       i,
			ReceiptID:   r.ID,
			PrincipalID: r.CredentialSubject.Principal.ID,
		}
		checkGrounded(r, resolver, skewMs, &res)
		results = append(results, res)
	}
	return results, nil
}

func checkGrounded(r AgentReceipt, resolver GrantResolver, skewMs int64, res *GroundedResult) {
	auth := r.CredentialSubject.Authorization
	if auth == nil || auth.GrantRef == "" {
		res.Outcome = GroundedOutcomeUngrounded
		res.Detail = "authorization.grant_ref is absent on a " + string(r.CredentialSubject.Action.RiskLevel) + " receipt"
		return
	}
	res.GrantRef = auth.GrantRef

	grant, err := resolver.ResolveGrant(auth.GrantRef, res.PrincipalID)
	if err != nil {
		res.Outcome = GroundedOutcomeUngrounded
		res.Detail = "grant resolution failed: " + err.Error()
		return
	}
	if reason := malformedGrant(grant); reason != "" {
		res.Outcome = GroundedOutcomeUngrounded
		res.Detail = "resolved grant is malformed: " + reason
		return
	}
	res.Warnings = grantFieldWarnings(*auth, grant)

	if grant.Subject != res.PrincipalID {
		res.Outcome = GroundedOutcomeMismatch
		res.Detail = "grant subject " + grant.Subject + " does not match principal.id " + res.PrincipalID
		return
	}

	t, ok := parseReceiptTimeMs(r.CredentialSubject.Action.Timestamp)
	if !ok {
		res.Outcome = GroundedOutcomeValidityUnresolved
		res.Detail = "action.timestamp is not a readable RFC 3339 date-time"
		return
	}
	if outcome, detail := checkValidityWindow(grant, t, skewMs); outcome != "" {
		res.Outcome, res.Detail = outcome, detail
		return
	}

	for _, s := range auth.Scopes {
		if !slices.Contains(grant.Scopes, s) {
			res.Outcome = GroundedOutcomeScopeExceeded
			res.Detail = "authorization.scopes contains " + s + ", which the grant does not confer"
			return
		}
	}
	res.Detail = "grounded at the issuer-asserted action time"
}

// malformedGrant returns why a resolved grant is malformed (§7.9.1), or "".
func malformedGrant(g GrantInfo) string {
	switch {
	case g.Subject == "":
		return "subject is missing"
	case len(g.Scopes) == 0:
		return "scopes is missing or empty"
	case g.ValidFrom.IsZero():
		return "valid_from is missing"
	case g.Issuer == "":
		return "issuer is missing"
	}
	switch g.Revocation {
	case RevocationNotRevoked, RevocationRevoked, RevocationUnknown:
	case "":
		return "revocation is missing"
	default:
		return "revocation " + string(g.Revocation) + " is not one of not_revoked, revoked, unknown"
	}
	if g.ExpiresAt != nil && g.ExpiresAt.UnixMilli() <= g.ValidFrom.UnixMilli() {
		return "expires_at is not after valid_from"
	}
	if g.RevokedAt != nil && g.Revocation != RevocationRevoked {
		return "revoked_at is set but revocation is " + string(g.Revocation)
	}
	return ""
}

// checkValidityWindow applies §7.9.3 to action time t (milliseconds since the
// Unix epoch) with tolerance skewMs. It returns an empty outcome when the
// grant was in force.
func checkValidityWindow(g GrantInfo, t, skewMs int64) (GroundedOutcome, string) {
	start := g.ValidFrom.UnixMilli()
	var end *int64
	bound := func(v *time.Time) {
		if v == nil {
			return
		}
		ms := v.UnixMilli()
		if end == nil || ms < *end {
			end = &ms
		}
	}
	bound(g.ExpiresAt)
	if g.Revocation == RevocationRevoked {
		bound(g.RevokedAt)
	}

	lo, hi := t-skewMs, t+skewMs
	emptyWindow := end != nil && *end <= start
	overlaps := !emptyWindow && hi >= start && (end == nil || lo < *end)
	if !overlaps {
		return GroundedOutcomeNotValidAtActionTime, "the grant was not in force at the issuer-asserted action time"
	}
	inside := lo >= start && (end == nil || hi < *end)
	if !inside {
		return GroundedOutcomeValidityUnresolved, "the action time is within the clock-skew tolerance of a grant boundary"
	}
	switch {
	case g.Revocation == RevocationUnknown:
		return GroundedOutcomeValidityUnresolved, "the resolver cannot see whether the grant was revoked"
	case g.Revocation == RevocationRevoked && g.RevokedAt == nil:
		return GroundedOutcomeValidityUnresolved, "the grant was revoked at an unknown time"
	}
	return "", ""
}

// grantFieldWarnings compares the receipt's stated grant fields with the
// resolved grant at millisecond precision (§7.9.4). A stated value that is not
// a readable RFC 3339 date-time raises no warning.
func grantFieldWarnings(auth Authorization, g GrantInfo) []GroundedWarning {
	var warnings []GroundedWarning
	if v, ok := parseReceiptTimeMs(auth.GrantedAt); ok && v != g.ValidFrom.UnixMilli() {
		warnings = append(warnings, GroundedWarning{
			Code:   WarningGrantedAtDisagrees,
			Detail: "authorization.granted_at differs from the grant's valid_from",
		})
	}
	if v, ok := parseReceiptTimeMs(auth.ExpiresAt); ok && (g.ExpiresAt == nil || v != g.ExpiresAt.UnixMilli()) {
		warnings = append(warnings, GroundedWarning{
			Code:   WarningExpiresAtDisagrees,
			Detail: "authorization.expires_at differs from the grant's expiry",
		})
	}
	return warnings
}
