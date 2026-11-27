# ADR-0041: Grant Validity and Scope Checks in the Grounded-Principal Tier

## Status

Proposed

## Context

ADR-0038 defined the grounded-principal conformance tier. For `high` and
`critical` receipts, a verifier in that tier checks that
`authorization.grant_ref` is present, resolves it through a pluggable grant
resolver (D3), and checks that the grant's subject equals `principal.id` (D2).
Spec §7.9 specifies those three steps.

That proves a real grant exists for the named principal. It does not check that
the action fell within the grant. Spec §7.9 and ADR-0038 D3 say the resolver
returns at minimum `{ subject, scopes, issued_at, expires_at, issuer }`. The
three SDKs relax that: only `subject` is required, and the other fields are
documented as advisory and may be omitted (or zero, in Go). Their
`VerifyGroundedPrincipalTier`
implementations use only `subject`. As a result, a grounded-tier receipt passes
when:

- it claims scopes the grant never conferred (`authorization.scopes` is not a
  subset of the grant's scopes);
- its action happened before the grant was issued, or after it expired or was
  revoked;
- its `authorization.granted_at` / `expires_at` contradict the grant.

ADR-0038 D2 describes the tier's purpose as turning "the agent claims it acted
for X" into "an external authority confirms X delegated this scope". Nothing
compares the scope. ADR-0038 recorded the time question as an open question
("Grant freshness vs `action.timestamp`"), along with partial scope coverage and
long-lived verifiability.

The maintainer found this gap while answering an external interop review,
[#1204](https://github.com/agent-receipts/obsigna/issues/1204), in which an
outside verifier asked whether a receipt establishes that an action stayed
within the authority granted. The honest answer was no, not even in the
grounded tier. The issue tracking the gap is
[#1207](https://github.com/agent-receipts/obsigna/issues/1207).

### Verification time versus action time

Grant resolution happens when a receipt is verified. Authority is a question
about when the action happened. The two diverge for any receipt verified after
its grant expired or was revoked, which is common for audits carried out after
the fact. Spec §7.9 step 2 currently lists "token revoked" as a resolution
failure, and the SDK resolver docs say the same. So a receipt for an action that
was properly authorized at the time becomes `UNGROUNDED_PRINCIPAL` once its
grant is revoked, and usually once it expires. That is wrong in one direction. A
naive fix that only checks the grant is "active now" is wrong in the other: it
judges a past action by present state.

### What authorization servers can actually tell us

The resolver is the only source of grant state, so the design has to fit what
real authorization servers expose:

- **OAuth 2.0 Token Introspection (RFC 7662)** returns `active: false` for a
  token that is expired, revoked or unknown, and says the server SHOULD NOT
  include any further information about an inactive token. An
  introspection-backed resolver therefore cannot report the historical state of
  a lapsed grant. For an active token, `scope`, `iat`, `nbf` and `exp` are all
  optional members of the response, so such a resolver may lack a grant's
  scopes or start time too. What an active response does establish is that the
  token is not revoked now, which settles revocation for any earlier action.
- **JWT access tokens (RFC 9068)** carry signed `iat` and `exp` claims, and may
  carry `nbf`. A resolver that holds the token can verify it and read those
  times after expiry, but the token says nothing about revocation.
- **Token revocation (RFC 7009)** has no standard way to ask *when* a token was
  revoked.
- An authorization server's own grant records or audit log can answer all of
  these, if the deployment exposes them.

So some resolvers can establish a grant's full history, some its validity window
but not its revocation status, some its revocation status but not its terms, and
some neither.
The verifier has to be able to say "cannot tell" without guessing in either
direction.

### Prior art

AMEP ([stafordtituss/amep](https://github.com/stafordtituss/amep)), whose
conformance profile was run over our test vectors in #1204, settled the same
question. Its author summarised the approach on
[#1207](https://github.com/agent-receipts/obsigna/issues/1207#issuecomment-7204973282):
validity is judged at each action's time; revocation carries its own time and is
compared against the action; "never valid" and "expired since" are different
outcomes; and a revocation that cannot be ordered against the action within the
declared clock skew is unresolved rather than guessed. This ADR adopts those
time semantics. It does not adopt AMEP's carrier: AMEP carries the grant inside
the signed record, which ADR-0038 rejected in favour of `grant_ref` plus a
resolver (see *Alternatives considered*). Citing AMEP here records prior art; it
is not an endorsement.

## Decision

These checks extend the grounded-principal tier. They apply only where the tier
applies: a verifier with a grant resolver configured, and receipts at
`risk_level` `high` or `critical`. The base tier is unchanged. As with every
grounded-tier step, they assume the receipt has already passed schema validation
(spec §7.8 step 1).

### D1. Authority is judged at the action time

The grant must have been valid when the action happened. Validity at
verification time is irrelevant.

The action time `t` is `action.timestamp`. It is the issuer's own statement, so
the window check (D4) shows that the issuer's *claimed* time falls inside the
grant, not that the action did: an issuer that can forge receipts can also
backdate them. Verifiers MUST say so when reporting a grounded result, for
example "valid at the issuer-asserted action time".

`action.trusted_timestamp` does not supply the action time. Under spec §7.7 the
TSA stamps the receipt, so its time (`TSTInfo.genTime`) is an independent upper
bound on when the action happened, not the action time itself. A verified
`genTime` could later strengthen the check at the end of the window: if
`genTime` is before the grant's expiry or revocation, the action happened before
the grant ended, subject to skew between the TSA's and the authorization
server's clocks. That needs an RFC 3161 verifier,
which no SDK has, and a fix to §7.7's canonical-form definition first (see
*Open questions*). This ADR does not depend on it.

### D2. The resolver returns the grant's terms, including after it lapses

The resolved grant exposes:

| Field | Required | Meaning |
|---|---|---|
| `subject` | Yes | The principal the grant was issued for. |
| `scopes` | Yes | The scopes the grant conferred. Non-empty. |
| `valid_from` | Yes | When the grant became valid. For a JWT this is `nbf` when present, otherwise `iat`. |
| `expires_at` | No | When the grant expires. Absent means no expiry. |
| `revocation` | Yes | One of `not_revoked` (not revoked as of resolution, which covers any earlier action), `revoked` or `unknown`. |
| `revoked_at` | No | When the grant was revoked. Allowed only with `revocation: revoked`. |
| `issuer` | Yes | The authorization server that minted the grant. |

Compared with today, this changes the contract in four ways:

- **A lapsed grant is a resolved grant.** When the resolver can establish an
  expired or revoked grant's terms, it MUST return them, not a resolution
  failure. Resolution failure is reserved for a grant that cannot be found, a
  resolver that cannot be reached, or a response it cannot interpret. This
  reverses spec §7.9 step 2's "token revoked" case.
- **Revocation status is explicit and three-valued.** A resolver that cannot
  see revocation, such as one that only verifies a JWT, MUST return `unknown`.
  It MUST NOT omit the field, so "cannot tell" is never mistaken for "not
  revoked".
- **`scopes`, `valid_from` and `issuer` are required in the SDKs**, matching
  the minimum spec §7.9 already lists. `issued_at` is renamed `valid_from`,
  because what matters is when the grant took effect. `expires_at` becomes
  explicitly optional, since grants without an expiry exist.
- **Malformed grants fail resolution.** The verifier treats the following as a
  resolution failure (`UNGROUNDED_PRINCIPAL`): a missing required field, empty
  `scopes`, `expires_at` not after `valid_from`, or `revoked_at` with
  `revocation` other than `revoked`. A `revoked_at` before `valid_from` is not
  malformed: a grant can be revoked before it takes effect. Its window (D4) is
  then empty, so it grounds no action.

A resolver that, like plain RFC 7662 introspection, learns only that a grant is
inactive cannot meet the first requirement. It reports a resolution failure, and
the receipt is `UNGROUNDED_PRINCIPAL`. That is the conservative result: the
verifier could not establish the grant, so it does not claim the action was
grounded. Resolver documentation SHOULD state whether a resolver returns
historical state and whether it can see revocation.

`issuer` is required so a reader can see which authorization server vouched for
the grant. ADR-0038 D1 requires that server to be distinct from the receipt
issuer, but the two use different identifier spaces, so this ADR does not add a
check comparing them (see *Open questions*).

### D3. Scope containment

Every entry in `authorization.scopes` MUST appear in the grant's `scopes`, by
exact string comparison. Otherwise the receipt is `GRANT_SCOPE_EXCEEDED`.

The spec defines no scope hierarchy, so `files:*` does not cover `files:read`
unless the grant lists `files:read` itself. A deployment that wants hierarchical
scopes can express that in its resolver, by returning the expanded set.

This check compares the receipt's *claimed* scopes with the grant. It does not
show that the action needed only those scopes, because the spec defines no
mapping from `action.type` to scopes. An issuer that claims a narrow scope for a
broad action passes. The ADR-0038 caveat that a grant proves "a scope, not this
exact action" still holds.

### D4. Validity window

The grant's **validity window** is the half-open interval
`W = [valid_from, end)`, where `end` is the earliest of `expires_at` and
`revoked_at` that the grant has. If it has neither, `end` is unbounded.

Let `δ ≥ 0` be the verifier's clock-skew tolerance (D6), and
`I = [t − δ, t + δ]` the span of times the action may have happened in once
skew is allowed for. Then:

1. If `I` lies entirely outside `W`, the receipt is
   `GRANT_NOT_VALID_AT_ACTION_TIME`.
2. If `I` lies partly inside and partly outside `W`, the receipt is
   `GRANT_VALIDITY_UNRESOLVED`: under the allowed skew the action could have
   fallen on either side of a boundary.
3. If `I` lies entirely inside `W`:
   - with `revocation: not_revoked`, or `revoked` with a `revoked_at`, the
     check passes;
   - with `revocation: unknown`, or `revoked` without a `revoked_at`, the
     receipt is `GRANT_VALIDITY_UNRESOLVED`: the grant may have been revoked
     before the action, and the verifier cannot tell.

With `δ = 0`, `I` is the single point `t`, and the rule reduces to "is `t` in
`[valid_from, end)`". Expiry or revocation after the action does not affect it:
a grant that expired last year still grounds an action taken while it was valid.
Step 1 takes precedence over unknown revocation: when `I` lies entirely outside
`W`, the receipt is not valid whatever its revocation status. Because `I` is
closed and `W` is half-open, the two ends of the window behave differently when
`δ > 0`: `t − δ` equal to `end` is outside `W` (step 1), while `t + δ` equal to
`valid_from` overlaps it (step 2).

### D5. Receipt-stated grant fields are informational

`authorization.granted_at` and `authorization.expires_at` are the issuer's
statement about the grant. The resolved grant is authoritative: D4 uses the
grant's times, never the receipt's.

The verifier SHOULD surface a warning alongside the result when the receipt
states a value and the grant's corresponding value differs at millisecond
precision: `granted_at` against `valid_from`, `expires_at` against `expires_at`.
A field the receipt leaves out is not a disagreement. The warning is not a
failure in its own right, because the outcome is already decided by the grant,
following the precedent of spec §7.3.6 for duplicate idempotency keys. Warnings are
attached to the receipt's result whatever its outcome, once the grant has
resolved. A disagreement can be legitimate: a token refresh or exchange can mint a grant
later than the user's original consent. It is still worth an auditor's
attention.

### D6. Time comparison and clock-skew tolerance

Every time comparison in this ADR (D2's malformed-grant rules, D4 and D5) is
made in UTC at millisecond precision. Values with finer precision are truncated
(floored) to the millisecond first, so the three SDKs, whose native time types
differ in precision, reach the same result.

`δ` is supplied by the verifier, in milliseconds, default zero. A negative value
is a configuration error. The spec does not fix a value, because the right
tolerance depends on the deployment's clocks. The SDKs expose it as an option
next to the grant resolver.

### D7. Outcome order

The grounded-tier checks run in this order. The first failure is the receipt's
outcome:

1. grant presence: `UNGROUNDED_PRINCIPAL` (ADR-0038)
2. grant resolution, including D2's required fields and malformed-grant rules:
   `UNGROUNDED_PRINCIPAL`
3. subject match: `PRINCIPAL_GRANT_MISMATCH` (ADR-0038)
4. validity window (D4): `GRANT_NOT_VALID_AT_ACTION_TIME` or
   `GRANT_VALIDITY_UNRESOLVED`
5. scope containment (D3): `GRANT_SCOPE_EXCEEDED`

Validity comes before scope because a grant that was not in force says nothing
about the scopes it conferred.

`GRANT_VALIDITY_UNRESOLVED` is a failure in the tier, like the others: the
verifier could not establish that the action was grounded. Severity within the
tier stays the open question ADR-0038 recorded for all of its outcomes.

### D8. Spec, SDKs, vectors and gate

- **Spec.** In the draft 0.7.0 (`spec/v0.7.0/spec.md`), §7.9 replaces its
  resolver contract with D2's, rewrites step 2 so a lapsed grant is no longer a
  resolution failure, and adds steps 4–5, the three outcomes, the action-time
  rule and D5's warning. This is a verifier-side change: no receipt field,
  schema or JSON-LD context changes.
- **SDKs.** This is a **breaking change** to the grant-resolver API in all three
  SDKs, and the CHANGELOGs MUST say so with migration notes:
  - The grant types change to D2's fields (`valid_from` replacing `issued_at`,
    `revocation`, `revoked_at`), with `scopes`, `valid_from`, `revocation` and
    `issuer` required. In TypeScript this is a compile-time break.
  - A resolver that returns only `subject`, which is conforming today, will
    turn every receipt into `UNGROUNDED_PRINCIPAL` until it supplies the
    required fields.
  - Resolver docstrings stop describing revocation as a resolution failure.
  - `VerifyGroundedPrincipalTier` and its equivalents return a result for every
    receipt they check, not only violations: the outcome, a detail, the
    statement that the action time is issuer-asserted, and any D5 warnings.
  - The tolerance `δ` becomes an option.
- **Vectors.** `cross-sdk-tests/` gains a grounded-tier corpus: receipts, a
  fixed resolver table, and the expected result for each case. It covers every
  branch of D4 (including each revocation status, windows shorter than `2δ`, both window
  ends with `δ > 0`, a grant revoked before it took effect, sub-millisecond
  boundaries and timezone offsets), scope containment, each
  malformed-grant rule, and D5's warnings. All three SDKs must agree on it. The
  corpus is generated from this contract, not imported from another project.
  Once published, outside verifiers (as in #1204) can be invited to run it.
- **Gate.** ADR-0038 D5 requires a CI gate that checks a deployment profile's
  emitted high/critical receipts against that profile's resolver. It was never
  delivered: #915 shipped the tier and closed #900 without it, no workflow runs
  such a check, and ADR-0024's catalogue has no entry for it. The corpus
  above supports a different gate, one that checks the three verifier
  implementations agree. Implementing this ADR ships that verifier-agreement
  gate. The deployment-profile gate is still owed under ADR-0038 D5; this ADR
  does not replace it.

## Consequences

### Positive

- **The tier checks what it claims to.** A grounded receipt now means the named
  principal held a grant, in force at the issuer-asserted action time, that
  conferred the scopes the receipt claims.
- **Historical receipts stay verifiable.** A receipt for an action taken under a
  since-expired or since-revoked grant no longer fails just because the grant
  lapsed, provided the resolver can report the grant's terms.
- **"Cannot tell" is an explicit result.** Unknown revocation status, revocations
  without a time, and boundary cases under clock skew produce
  `GRANT_VALIDITY_UNRESOLVED` instead of a guess in either direction.
- **No wire change.** Everything is verifier-side, so existing receipts and
  emitters are unaffected.

### Negative

- **Breaking change for resolver authors.** Resolvers have to supply more than
  `subject`, and one that cannot see revocation gets `GRANT_VALIDITY_UNRESOLVED`
  for every receipt it would otherwise ground.
- **Resolvers carry more of the load.** Returning historical state needs more
  than standard introspection offers. Deployments whose authorization server
  only answers "active or not" will see lapsed grants as
  `UNGROUNDED_PRINCIPAL`, as today. The tier is only as strong as the resolver
  behind it.
- **The action time is self-asserted.** The window check proves consistency with
  the issuer's claimed time, not the actual time. D1 makes the verifier say so,
  but the gap remains until trusted timestamps can be verified (see *Open
  questions*).
- **Scope containment is only as good as the claimed scopes.** Without an
  `action.type`-to-scope mapping, D3 cannot catch an issuer that under-declares
  the scope an action needed.
- **Three new outcomes and a richer result type** to document, surface in
  tooling and keep identical across three SDKs.

## Alternatives considered

- **Judge validity at verification time.** Rejected. It turns every properly
  authorized historical receipt into a failure once its grant lapses, which is
  the normal state of an audit after the fact.
- **Use the trusted timestamp as the action time.** Rejected. The TSA stamps the
  receipt, not the action, so its time is an upper bound. Used as `t` it fails
  actions taken just before expiry and stamped just after, and overstates what
  it shows at the start of the window. D1 keeps it for a later upper-bound
  check.
- **Carry the grant inside the receipt (AMEP's approach).** A signed snapshot of
  the grant in the receipt would make verification independent of a live
  resolver and would answer ADR-0038's long-lived-verifiability question. Not
  adopted here: ADR-0038 rejected inlining to keep receipts small and keep token
  material out of long-lived signed records, and this ADR's checks do not need
  it. Revisit together with long-lived verifiability.
- **Leave the checks to resolvers.** A resolver could refuse out-of-window
  grants itself. Rejected: it never sees the receipt's scopes or action time in
  a form it can compare, and leaving core verification semantics to pluggable
  code means three SDKs and every resolver get them differently.
- **Document the limitation only.** Cheaper, but it leaves the tier's main
  promise unchecked. The limitation is not yet documented in the spec or on the
  Trust Model page; implementing D8 replaces it with the checks themselves.
- **Hierarchical or pattern scopes.** Out of scope. The spec defines scopes as
  opaque strings. A resolver can expand them if a deployment needs it.

## Open questions

- **Trusted-timestamp upper bound.** Using a verified `genTime` to confirm the
  end of the window (D1) needs an RFC 3161 verifier in all three SDKs, which is
  a dependency and trust-anchor decision of its own. It also needs a fix to spec
  §7.7, whose stamped canonical form removes only `proof` and so still contains
  `trusted_timestamp` itself.
- **Default tolerance.** Zero is safe but may produce `GRANT_VALIDITY_UNRESOLVED`
  for honest receipts near a boundary. Whether the spec should recommend a value
  is left open.
- **Authorization-server distinctness.** ADR-0038 D1 requires the grant to come
  from a party distinct from the receipt issuer. Checking that needs a way to
  relate an authorization server's identifier to the issuer's DID, which the
  spec does not have.
- **Long-lived verifiability.** Unchanged from ADR-0038: a receipt may need
  verifying after the authorization server is gone. A signed grant snapshot,
  carried or archived, is the likely answer.
- **Action-to-scope mapping.** Real containment needs to know which scopes an
  action required. That needs a mapping from `action.type` to scopes, which the
  spec does not have.
- **Multiple grants.** D3 checks one grant. An action whose scopes span several
  grants is still unspecified, as in ADR-0038.

## Related ADRs

- [ADR-0038](0038-grounded-principal-conformance-tier.md): the grounded-principal
  tier this ADR extends; resolves its open question on grant freshness.
- [ADR-0007](0007-did-method-strategy.md): the pluggable-resolver pattern D2
  extends.
- [ADR-0024](0024-project-verification-contract.md): the gate requirement
  behind ADR-0038 D5, which D8 records as still owed.
