# ADR-0038: Grounded-Principal Conformance Tier

## Status

Proposed

## Context

The protocol authenticates *who signed a receipt* and *what they claimed*. It
does not authenticate *that the human named as principal actually authorized
the action*. That gap is the subject of this ADR.

### The principal is self-asserted

Spec §3.4 defines the principal as "the entity who authorized the action." The
schema does not hold the issuer to that definition. In §4.3.2:

- `principal.id` is required, but it is a value the issuer writes into the
  credential body. Nothing external corroborates it.
- `authorization` is **optional**. A valid receipt may omit it entirely.
- `authorization.grant_ref` — described in §4.3.2 as "Reference to the
  authorization grant (e.g. a Grantex grant token)" — is **optional even when
  `authorization` is present**. The full schema example (§4.1) ships with
  `"grant_ref": null`.

The consequence: a receipt can assert `principal.id: did:user:X` for a
`risk_level: high` action with no evidence that X authorized anything. The
Ed25519 signature (ADR-0001) makes that assertion non-repudiable *for the
issuer* — it proves the agent said "I acted for X." It says nothing about
whether X granted the authority. An auditor reading the chain sees a signed
claim of delegated human authority and an empty `grant_ref` beside it.

This is a different gap from the two adjacent ones already on record, and this
ADR is careful not to reopen either:

- **Not P2 (agent legitimacy).** ADR-0019 P2 (#481) is the *agent* side: an
  attacker who can write to the store can fabricate an `agent_start` with a
  fresh keypair, and nothing proves the DID is a legitimate agent. P2 is
  deferred to v2 and is **out of scope here.** This ADR grounds the *human
  principal*, not the agent.
- **Not O2 (store completeness).** ADR-0019 O2 (#484) is about the store that
  holds receipts being un-witnessed. It is sequenced for v1.5 and is
  **referenced, not redefined** below — this ADR notes one way the
  grounded-principal mechanism strengthens an O2 witness, and stops there.

Two prior decisions bound the design space and are **not** relitigated:

- **Custody / out-of-process signing** is settled by ADR-0018 (`Signer`,
  `KMSSigner`, `TPMSigner`). This ADR does not touch where keys live or how
  signing happens.
- **DID method strategy** is settled by ADR-0007 (`did:key` default, `did:web`
  for production, pluggable resolver interface). This ADR reuses ADR-0007's
  resolver *pattern* for a new purpose; it does not change the DID method
  decision.

### Why now: dated mandates and the verifying party

The demand for grounding the principal is concrete and dated. Reasonable-
oversight liability regimes and transparency mandates require an auditable link
between an automated action and the human who authorized it:

- **Colorado AI Act** — effective 2026-06-30.
- **EU AI Act** transparency obligations — applicable 2026-08-02.

The verifying party under these regimes is an auditor or insurer. What they need
is evidence of the *human's authorization*, not the *agent's claim about it*. A
self-asserted `principal.id` with `grant_ref: null` is exactly the artifact that
does not satisfy a reasonable-oversight standard: it is the agent vouching for
itself.

### The standards-aligned grant source already fits

The spec already accommodates the right shape. §8 records that Grantex is
complementary — "Grantex handles authorization (should this agent be allowed to
act?)" — and that "An Agent Receipt may reference a Grantex grant token in
`authorization.grant_ref`." The standards-aligned sources of such a grant are
**RFC 8693 OAuth 2.0 Token Exchange** (the On-Behalf-Of / delegation flow) and
OIDC. In all of these, an external **authorization server** mints a grant whose
subject is the human principal and whose scopes bound what the agent may do on
their behalf. `grant_ref` is the field that already exists to point at it. What
is missing is any requirement that it be present, resolvable, and bound to the
principal.

### Why grounding cannot be a blanket requirement

A naïve fix — "make `authorization.grant_ref` required" — breaks the largest
deployment class the project has. The hook-channel emitters observe **local
agents acting for the local user**, where no delegated authorization grant
exists to point at:

- **ADR-0013 (`claude_code_hook`)** and **ADR-0014 (`codex_hook`)** observe a
  coding agent running on a developer's machine. The principal is the local
  user; the daemon derives it from the kernel-attested peer credentials of the
  emitter process (`SO_PEERCRED` / `LOCAL_PEERCRED`), not from any token.
- **ADR-0027 (`opensandbox_execd`)** observes agent actions inside a sandbox;
  the binding is `OPENSANDBOX_ID`, again with no delegated human grant in the
  loop.
- **ADR-0032 (mcp-proxy transport)** already makes the *injected* principal
  fail closed (one principal per stdio process; on an absent principal the proxy
  refuses to emit a receipt rather than fall back to `did:user:unknown` or a
  guessed default). That is the right behaviour, but an injected principal is
  still not a *grant*: the launch argument / env / config that supplies it is
  operator-asserted, not minted by an authorization server.

For all of these, the principal genuinely *is* the local user and there is no
external grant to require. Demanding one would force these deployments to either
fabricate a grant (worse than honesty) or fall out of conformance entirely.

Grounding must therefore be a **conformance tier** that deployments with a real
delegated-authorization story can claim, leaving the base tier — and the local
hook deployments that live in it — unchanged and honestly documented.

## Decision

Define a **grounded-principal** conformance tier, layered above the existing
base tier. A deployment that claims the grounded-principal tier accepts the
additional obligations D1–D3 below; the base tier (D4) is unchanged.

### D1. High/critical actions MUST carry a resolvable external grant

In the grounded-principal tier, for any action with
`action.risk_level` of `high` or `critical`:

- `credentialSubject.authorization` MUST be present.
- `authorization.grant_ref` MUST be present and MUST resolve to a grant minted
  by an **external authorization server**. An RFC 8693 OAuth 2.0 Token Exchange
  (On-Behalf-Of) grant satisfies this; a Grantex grant token satisfies this.
  The common requirement is that the grant is issued by a party distinct from
  the receipt issuer — the agent cannot mint its own grounding.

Actions at `risk_level` `low` or `medium` are unaffected by this tier (see Open
Questions on whether `medium` should later be included). The tier deliberately
targets the action classes where reasonable-oversight regimes apply.

### D2. The principal MUST match the grant subject

`credentialSubject.principal.id` MUST equal the subject of the resolved grant.
This is the step that converts "the agent claims it acted for X" into "an
external authority confirms X delegated this scope."

Add a **principal-to-grant match** step to the end-to-end verification
algorithm (spec §7.8), conditional on the verifier operating in the
grounded-principal tier:

> *7.8 (grounded-principal tier).* After signature verification, for any
> receipt whose `action.risk_level` is `high` or `critical`: resolve
> `authorization.grant_ref` via the configured grant resolver (D3). If
> resolution fails, the receipt is `UNGROUNDED_PRINCIPAL`. If the resolved
> grant's subject does not equal `credentialSubject.principal.id`, the receipt
> is `PRINCIPAL_GRANT_MISMATCH`.

This check is **verifier-imposed, not receipt-declared.** The verifier opts into
the grounded-principal tier (by configuring a resolver, D3) and the requirement
is then applied to every high/critical receipt it sees — exactly as ADR-0008's
`RequireTerminal` makes chain-closure a *verifier-supplied demand* rather than an
in-receipt claim. Under the base schema the receipt carries no tier marker, so a
base-tier verifier sees nothing to enforce and a grounded-tier verifier enforces
on all high/critical receipts regardless of what the receipt says about itself.
Whether the *receipt* should additionally self-declare the tier — so a third
party holding one receipt can tell it was meant to be grounded — is a separable
carrier question deferred below (see *Per-receipt tier declaration*).

This sits alongside the existing delegation check in §7.6 step 4, which already
requires the principal to be stable *across* a delegation hop; D2 additionally
ties that principal to an external grant at the point of a high/critical action.
The two checks compose — see *Multi-hop delegation* under Deferred decisions for
why D2 does **not** extend into per-hop scope attenuation.

### D3. Grant resolution is pluggable, mirroring ADR-0007

`grant_ref` resolution is an interface, not a hardcoded backend, exactly as DID
resolution is in ADR-0007. The contract:

- **Input:** the `grant_ref` string and the receipt's `principal.id`.
- **Output:** either a resolved grant exposing at minimum `{ subject, scopes,
  issued_at, expires_at, issuer }`, or a resolution failure.
- **Side-effect freedom at the contract level:** like ADR-0007's `did:web`
  resolver, a grant resolver MAY perform network I/O (an introspection call to
  the authorization server, a token-validation endpoint). Caching and offline
  resolution are resolver-implementation concerns, parallel to ADR-0007 Phase C.
- **Pluggability:** the SDK ships the interface; integrators supply a resolver
  for their authorization server (RFC 8693 token introspection, an OIDC
  userinfo/introspection endpoint, a Grantex resolver). The project does not
  endorse a single authorization server, the same stance ADR-0007 takes on DID
  methods beyond `did:key` / `did:web`.

**Absence of a resolver in the base tier is not a verification failure.** A
base-tier verifier that has no grant resolver configured does not fail receipts
for lacking one; it simply does not perform D1/D2. The grounded-principal checks
only run when a verifier opts into the tier *and* has a resolver, the same
opt-in shape ADR-0008 §3 uses for `ExpectedLength` / `ExpectedFinalHash` and
ADR-0008 §4 uses for `RequireTerminal`.

### D4. The base tier is unchanged and documented as such

In the base tier, `authorization` remains optional, `grant_ref` remains
optional, and `principal.id` remains self-asserted. This is **not** a defect to
be apologised for — it is the correct behaviour for local hook deployments
(ADR-0013/0014/0027) where the principal is the local user and no delegated
grant exists. The spec and SDK docs MUST state plainly that:

- A base-tier receipt's `principal.id` is an issuer assertion, corroborated only
  by whatever the channel's peer attestation provides (e.g. kernel peer
  credentials for the hook channels), and is **not** backed by an external
  authorization grant.
- Absence of `authorization` / `grant_ref` in the base tier carries no negative
  signal; it is the expected shape for local-agent deployments.

This documentation requirement is itself an asserted property and is covered by
the D5 gate (per ADR-0024: a property the project states must have a check).

### D5. Ship the enforcing gate in the same change (ADR-0024)

ADR-0024 makes this non-negotiable: a property the project asserts must ship
with the CI gate that fails when the property is false, in the same change. The
grounded-principal tier asserts a checkable property, so the change that
introduces it MUST include:

> A CI gate that, for a deployment/conformance profile claiming the
> grounded-principal tier, fails the build if any emitted receipt with
> `action.risk_level` of `high` or `critical` either (a) lacks a `grant_ref`
> that resolves via the profile's configured resolver, or (b) resolves to a
> grant whose subject does not equal the receipt's `principal.id`.

This extends ADR-0024's gate catalogue (D4) with a new `verification-gate`
entry, tracked by an implementation issue filed alongside this ADR. The gate
runs against the conformance suite's high/critical receipts using the profile's
resolver; base-tier profiles fall outside the gate by construction because they
do not claim the tier. This is structural, not a D5 exemption: a base-tier
deployment does not assert the grounded-principal property, so there is nothing
to exempt, and ADR-0024 D5's bar on "too hard to write" exemptions is not
engaged.

This ADR scopes the tier claim at the *deployment / conformance-profile* level —
a deployment declares the tier it conforms to, and the gate checks that
deployment's high/critical output. That keeps enforcement (D2, verifier-imposed)
and the gate (D5) working with **no spec change**. Whether the receipt should
*also* carry a per-receipt tier marker is a separable carrier decision,
deferred with a clear path and flip condition below (see *Per-receipt tier
declaration*) — not an open-ended unknown.

## Consequences

### Positive — what this enables or makes easier

- **The principal becomes auditable, not just asserted.** For high/critical
  actions in the tier, an auditor or insurer can confirm — against a party
  distinct from the agent — that the named human delegated the scope under which
  the action was taken. This is the artifact the Colorado / EU regimes call for.
- **No new crypto, no new DID method, no schema change at the base.** D1–D3 are
  expressed entirely over fields the spec already defines (`authorization`,
  `grant_ref`, `principal.id`) and a resolver interface modelled on one that
  already exists (ADR-0007). Custody is untouched (ADR-0018).
- **Enables an external completeness witness for O2 (#484) — cross-reference,
  not a redefinition.** Once `grant_ref` is required and resolvable for
  high/critical actions in this tier, the authorization server's
  grant-issuance / token-exchange log becomes reconcilable against the emitted
  receipts: a grant the IdP records as *exercised* (a token issued or exchanged
  for an action) with **no matching receipt** is a visible hole in the store.
  This witness is sourced from a party distinct from the receipt store — the
  authorization server — which is a **stronger** completeness signal than O2's
  current recommendation of self-published chain-head anchoring (ADR-0019 O2;
  the chain-head approach is published *by the same operator that holds the
  store*). This ADR records the consequence only; the O2 mechanism itself stays
  in ADR-0019 and issue #484. It does not satisfy O2 — a grant log witnesses
  only the high/critical, grant-bearing subset, not the whole store.
- **Cleaner story for the mcp-proxy fail-closed principal (ADR-0032).** A
  deployment that already injects a per-process principal can move from
  "structurally one principal, operator-asserted" to "principal backed by an
  external grant" by adopting this tier, without changing the transport
  decision.

### Negative — what becomes harder or carries cost

- **Operational dependency on an authorization server.** The tier only works
  where an RFC 8693 / OIDC / Grantex authorization server exists and issues
  grants the resolver can resolve. Deployments without one cannot reach the
  tier; that is by design (D4) but is a real adoption cost.
- **Verification gains a network dependency for high/critical actions.** Grant
  resolution may require an introspection call. This mirrors the `did:web`
  availability concern in ADR-0007 (a receipt may need to be verifiable years
  later, after the authorization server changes or disappears) and inherits the
  same unanswered caching / archival questions — see Open Questions.
- **A new failure mode for verifiers.** `UNGROUNDED_PRINCIPAL` and
  `PRINCIPAL_GRANT_MISMATCH` are new verification outcomes the tooling and docs
  must define and surface. Their exact severity within the tier (hard failure
  vs degraded "ungrounded but otherwise valid") is an open question.
- **Two-tier conformance to communicate.** The project now has a base tier and a
  grounded-principal tier; consumers must understand which a given deployment
  claims and what each guarantees. Mis-stating the tier is itself a drift risk
  that the D5 gate is meant to catch.
- **Issuer-downgrade is not detectable from a single receipt.** Because
  enforcement is verifier-imposed and the base schema carries no tier marker
  (D2), a third party holding *one* high/critical receipt, verifying in base
  mode, cannot tell it was *meant* to be grounded — a grounded issuer that
  silently emitted an un-grounded receipt looks like a legitimate base-tier
  receipt. This is caught at the issuer's own release by the D5 gate, and at
  verify time by any auditor running in grounded mode; the residual gap is the
  single-receipt, base-mode auditor. Closing it for that party is exactly what a
  per-receipt tier marker would buy — deferred (see *Per-receipt tier
  declaration* under Deferred decisions).

## Honest caveats

These are limitations of the mechanism, recorded so they are not overstated:

- **A grant proves authorization of a *scope*, not of *this exact action*.** An
  RFC 8693 / OIDC / Grantex grant attests that the principal delegated some
  bounded authority; it does not, by itself, attest that the agent used that
  authority for the specific action in this receipt. The binding between the
  grant and the action holds **only because `grant_ref` and the action are
  signed together in one `credentialSubject`** — the issuer commits, in one
  signature, to "this action, under this grant, for this principal." The
  strength of that binding degrades with the breadth and lifetime of the grant:
  grants SHOULD be narrow (scoped to the action class) and short-lived. A broad,
  long-lived standing grant degrades the guarantee back toward "trust me" — the
  agent can wave the same wide grant at any action and the principal-grant match
  still passes. The tier does not, and cannot, fix an over-broad grant; it can
  only require that *some* externally-minted grant exists and names the
  principal.
- **The grounded-principal tier does not apply to local-agent hook
  deployments.** Deployments observing a local agent acting for the local user
  with no delegated grant (ADR-0013/0014/0027, and ADR-0032 deployments that
  inject but do not ground the principal) remain in the base tier. Their
  `principal.id` is self-asserted (corroborated only by channel peer
  attestation) and that is the correct, documented behaviour for them — not a
  conformance failure.

## Deferred decisions and non-decisions

Recorded with rationale so they are not silently assumed resolved.

- **Issuer / agent legitimacy (P2) — deferred to v2, out of scope.** This ADR
  grounds the *human principal* only. Proving that the issuing DID is a
  legitimate agent (vs a fabricated `agent_start` with a fresh keypair) is
  ADR-0019 P2 (#481), deferred to v2. A grounded principal does not imply a
  legitimate agent, and this ADR makes no claim about the agent side.
- **Multi-hop delegation attenuation — explicitly not adopted.** Spec §7.6 links
  parent and child chains and (step 4) requires the principal to be stable
  across a delegation hop. Nothing enforces that each hop only *narrows* scope.
  Adopting an attenuation scheme is **out of scope** because the standards are
  unsettled: the WIMSE work leaves its authorization section as "TODO
  Security"; bearer tokens permit full-scope reuse downstream; and AAuth, AIP,
  and Agentic-JWT compete with no clear winner. This ADR keeps the existing
  §7.6 delegation linkage and adds the D2 principal-grant match at high/critical
  actions; it does **not** introduce any per-hop scope-narrowing requirement.
  Revisit if and when a standard stabilises.
- **Per-receipt tier declaration — deferred, carrier separable from semantics.**
  The tier *semantics* (D1–D3) and the *gate* (D5) are decided here; the
  *wire carrier* for a per-receipt "I claim grounded-principal" marker is
  deferred. This mirrors ADR-0015, which decided key-rotation semantics and
  explicitly deferred where the fields live in the receipt envelope, on the
  rationale that "the integrity properties… are independent of placement and
  survive whichever carrier shape is later chosen." The same holds here: the
  integrity property (`principal.id` equals an externally-minted grant subject)
  is identical whether the claim is verifier-imposed (D2, shipped) or
  receipt-declared. When a carrier is wanted, the cheap path is a strictly
  additive `credentialSubject.conformance` sub-object — `credentialSubject`
  permits extension fields (ADR-0003 §"Subset compliance"), and ADR-0015's
  `keyRotation` is the precedent for adding a sibling without flipping
  `additionalProperties`. Like ADR-0027's `coverage` block it would be
  emitter-asserted but signed, hence a *claim that gets checked*, not new trust.
  Cost: still a spec change (ADR-0021 versioning, three SDKs, a likely version
  bump), so out of scope for this ADR and gated by explicit spec approval.
  **Flip condition:** adopt the carrier once there is (a) a real grounded
  deployment and (b) a verifying party that needs to detect, from a *single*
  receipt without the issuer's profile, that the receipt was meant to be
  grounded (issuer-downgrade detection — the one gap the verifier-imposed model
  does not close; see Consequences → Negative).

## Alternatives considered

- **Make `grant_ref` unconditionally required (no tiers).** Rejected. It breaks
  every local hook deployment (ADR-0013/0014/0027), which has no delegated grant
  to point at, and would push them to fabricate grants or leave conformance. The
  tier exists precisely to avoid this.
- **Embed the grant inline in the receipt instead of referencing it.** Rejected,
  consistent with the project's standing preference for references over inlined
  payloads (ADR-0008 stores hashes not bodies; ADR-0012 keeps parameters out of
  the receipt by default; ADR-0015 / ADR-0008 keep anchoring out-of-band).
  Inlining a grant would bloat receipts and risk leaking token material into a
  long-lived signed record. `grant_ref` + a resolver keeps the receipt small and
  the grant where its issuer controls it.
- **Per-action grants instead of scope grants.** A grant minted for one specific
  action would close the "scope, not this action" caveat. Not adopted as a
  requirement: no widely-deployed authorization server issues per-action grants
  today, and the UX cost (a token round-trip per high/critical action) is
  significant. Flagged as the ideal end state and an open question, not mandated.
- **A trust registry / new DID method for principals.** Rejected as out of scope
  and overlapping ADR-0007's settled DID strategy and ADR-0019 P2's deferred
  agent-legitimacy work. The resolver interface (D3) reuses ADR-0007's pattern
  rather than introducing a new identity mechanism.
- **Enforce authorization only at emit time (issuer-side policy), not at verify
  time.** Rejected as insufficient for the demand. Issuer-side policy is the
  agent checking its own homework; the value under reasonable-oversight regimes
  is *verifier-side* (auditor / insurer) reconstruction of the human's
  authorization after the fact. The mechanism must be checkable by the verifying
  party, which is why D2 lands in the verification algorithm.

## Open questions

Where a decision is genuinely underspecified, it is flagged here rather than
invented:

- **Severity of `UNGROUNDED_PRINCIPAL` within the tier.** Is a high/critical
  receipt with an unresolvable `grant_ref` a hard verification failure, or a
  valid-but-flagged "ungrounded" outcome that downstream policy decides on?
- **Does `medium` risk ever enter the tier?** D1 targets `high`/`critical`. Some
  regimes may reach `medium`-class actions; whether and how to extend is left
  open.
- **Grant freshness vs `action.timestamp`.** Should verification require the
  grant to have been valid (issued, not expired) at `action.timestamp`, and with
  what tolerance? This parallels the §7.7 trusted-timestamp window question and
  is not resolved here.
- **Multiple grants / partial scope coverage.** If an action's required scope
  spans more than one grant, or a single `grant_ref` only partially covers it,
  how is the match evaluated? D2 specifies subject equality, not scope-coverage
  semantics.
- **Long-lived verifiability of grants.** A receipt may need verification years
  after the authorization server has rotated, changed, or disappeared. Grant
  caching / archival is unspecified, inheriting ADR-0007's open `did:web`
  availability questions.
- **Relationship to ADR-0032's injected principal.** ADR-0032 fails closed on an
  absent principal. The exact upgrade path from "injected, operator-asserted
  principal" to "grounded principal" (e.g. whether the injected principal must
  equal the grant subject) is left for the implementation.

## Related ADRs

- [ADR-0007 (DID Method Strategy)](./0007-did-method-strategy.md) — the
  pluggable-resolver pattern D3 mirrors; the settled DID method decision this
  ADR does not reopen.
- [ADR-0008 (Response Hashing and Chain Completeness)](./0008-response-hashing-and-chain-completeness.md)
  — the opt-in verifier-parameter shape (`ExpectedLength`, `RequireTerminal`)
  that D3's "absent resolver is not a failure" follows; reference-over-inline
  precedent.
- [ADR-0018 (Signer Abstraction)](./0018-signer-abstraction-and-cloud-agnostic-keyprovider-design.md)
  — settles custody / out-of-process signing; not reopened here.
- [ADR-0019 (Protocol Integrity Gaps)](./0019-protocol-integrity-gaps-and-mitigations.md)
  — P2 (#481, agent legitimacy, v2, out of scope) and O2 (#484, store
  completeness, v1.5, cross-referenced as a consequence).
- [ADR-0024 (Project Verification Contract)](./0024-project-verification-contract.md)
  — the gate-discipline source for D5; this ADR's gate extends its catalogue.
- [ADR-0013 (`claude_code_hook`)](./0013-claude-code-hook-channel.md),
  [ADR-0014 (`codex_hook`)](./0014-codex-hook-channel.md),
  [ADR-0027 (`opensandbox_execd`)](./0027-opensandbox-execd-channel.md) — local
  hook/sandbox channels where no delegated grant exists; the base-tier
  deployments D4 keeps unchanged.
- [ADR-0032 (mcp-proxy Transport)](./0032-mcp-proxy-transport.md) — the
  fail-closed injected-principal model this tier can sit above.
