# ADR-0024: Project Verification Contract — Every Asserted Property Has a Gate

## Status

Accepted

## Context

Every property the project asserts in spec text, README text, published documentation, or release notes MUST have a corresponding mechanical check that fails the build when the assertion is false. Properties without enforcement are aspirations, not properties. This ADR records this as project policy and lists the initial set of gates that follow from it.

Agent Receipts' value proposition is "verifiable property of the system, independently checkable, not requiring trust in the system's claims." A project that makes that claim about AI agent actions while its own published claims drift from reality is in an untenable position. Auditing the project on 2026-05-24 surfaced ~40 findings across three SDKs and the site. Most collapse to a small number of root causes — *all of them are the same shape*: the project asserted a property (README quick-start works, spec URLs resolve, emit contract is X, module path is Y) and didn't mechanically check the assertion.

The volume of findings is itself signal. AI-paced development produces changes faster than humans can review for documentation drift. The discipline that catches drift in human-paced projects ("did I update the docs?") does not scale to the rate at which changes ship through this project today and will ship through it in future. The only thing that scales with the production rate is mechanized verification.

This ADR commits the project to the position that **gates are the architecture, not an afterthought**.

## Decision

### D1. Verification contract

For every property P the project asserts in any of: spec text, README, published documentation, or release notes — there MUST exist a CI gate G such that G fails when P is false. Properties without gates are aspirations; the project does not assert aspirations as facts.

This rule is non-negotiable for properties that affect external consumers (anyone validating a receipt, anyone reading the spec, anyone running the quick-start). It is recommended for internal properties (developer workflow, build hygiene).

### D2. New properties ship with their gates

A PR that introduces a new asserted property MUST include the gate that enforces it, in the same PR. A PR that asserts a property without enforcement is incomplete and SHOULD NOT merge.

If a property's gate is non-trivial to author, the PR may land with the gate marked TODO and an issue filed for the gate, *only if* the asserted property is clearly marked in the documentation as unverified pending the gate. Asserting properties as established facts without enforcement is not acceptable; asserting them as work-in-progress with an open enforcement issue is.

### D3. Existing properties without gates are tracked, not grandfathered

Properties already asserted by the project that don't yet have gates are catalogued and each gets a follow-up issue. The catalogue is publicly visible (in this ADR's issue or its successor). Properties without gates and without a follow-up issue are removed from the assertion source until a gate exists.

This is uncomfortable but necessary. The alternative is the current state: documented claims that don't hold.

### D4. Initial gate catalogue

The following gates are committed to as the initial set, each tracked by its own implementation issue. The catalogue is not exhaustive and expected to grow.

| # | Gate | Asserts | Tracked by |
|---|---|---|---|
| 1 | **Documented code snippets execute** | Every code block in README and site docs runs against the published artifact in a clean tmpdir and exits 0 | #650 |
| 2 | **Release round-trip verification** | After publishing to PyPI/npm/Go proxy, the published version is fetched and asserted to be the version released; documented snippets run against the fetched artifact | #651 |
| 3 | **Spec URLs resolve** | Every `/spec/v<X.Y.Z>/` and `/context/v<N>` URL referenced by any released artifact resolves with valid content | #597 (D4 + D6) |
| 4 | **E2E receipt validation against live spec** | Every receipt produced by the conformance suite validates as a W3C VC against a strict JSON-LD processor that resolves `@context` URLs from the live site | #597 (D6) |
| 5 | **Site documented-snippet gate** | Same as #1 but for `.mdx` code blocks in the site source | #652 |
| 6 | **SDK output schema-conformance at release time** | Each SDK release produces a receipt and validates it against the published JSON Schema before the release goes out | #653 |
| 7 | **Cross-SDK byte-identity at release time** | Each SDK release runs the canonicalization vectors and asserts byte-identical output before the release goes out | #654 |
| 8 | **Daemon ↔ SDK protocol compatibility** | An SDK release declares a daemon-protocol version range and the gate verifies the released daemon at the same time speaks a compatible range | #655 |
| 9 | **Spec source-of-truth integrity** | At most one canonical spec source file exists at a time; every spec version's `@context` URL exists in the repo at `spec/context/v<N>/context.jsonld` | #597 follow-through |
| 10 | **Documented dependencies match installed dependencies** | The dependencies the README claims match an SBOM produced at release time; unexplained eager dependencies fail the build | #656 |
| 11 | **No tail truncation (checkpoint anchor)** | A chain with an out-of-band checkpoint anchor cannot have its receipt-store tail truncated undetected: `verify --against-anchor` fails when the anchored HEAD is ahead of the store HEAD | #600 |

### D5. Gate exemptions are explicit

A property may be exempt from D2 if and only if:

- The exemption is documented in this ADR (or its successor)
- The exemption has a stated reason and a stated expiry
- Properties exempted because the gate is "too hard to write" do not qualify; the answer there is to either not assert the property or write a simpler one

Current exempt properties: none.

### D6. The verification contract is itself verified

This ADR's gate catalogue (D4) is the assertion. A meta-gate (#657) asserts that every gate in the catalogue exists as an active CI job and has been observed to fail on a deliberately-broken input within the last 90 days. Gates that don't fail when they should are gates in name only.

## Consequences

What this changes about how the project operates:

- **PR review checklist changes.** Reviewers ask: "what property does this PR assert, and where is the gate?" before approving.
- **AI-assisted contribution becomes safer, not less safe.** Agents producing PRs are expected to also produce the gates. The project's policy is that this is the bar; agents that can't meet the bar produce PRs that don't merge. This is a stronger defense against AI-paced documentation drift than human review can be.
- **The project's claims become honest by construction.** Anything the project says it does, it can be observed doing — by anyone, mechanically.

## Out of scope for this ADR

- The implementation of any specific gate. Each gate gets its own issue and its own PR.
- Choosing the CI platform / runner / orchestration shape for gates. Implementation detail.
- Policies for runtime telemetry (vs release-time gates). Different category.

## Implementation issues spawned by this ADR

Filed as separate issues, each labeled `verification-gate` and linked back to this ADR. Implementation lands in these issues, not in this PR.

- Gate #1 — Documented code snippets execute against the published artifact. (#650)
- Gate #2 — Release round-trip verification of published version + snippets. (#651)
- Gate #5 — Site documented-snippet gate (`.mdx` code blocks). (#652)
- Gate #6 — SDK output schema-conformance at release time. (#653)
- Gate #7 — Cross-SDK byte-identity at release time. (#654)
- Gate #8 — Daemon ↔ SDK protocol compatibility. (#655)
- Gate #10 — Documented dependencies match installed dependencies (SBOM). (#656)
- Meta-gate (D6) — Every catalogued gate exists and fails on broken input. (#657)

Gates #3, #4, and #9 are tracked under ADR-0021 (#597) and its follow-through.

## Inputs

- The 2026-05-24 quick-start and site audit, whose ~40 findings across the three SDKs and the site motivated this ADR
- ADR-0021 (#597), spec versioning — first instance of an ADR shipped with its enforcement gate (D4 + D6)
- Closure 1 (#598), Closure 2 (#599) — first closures of pre-existing drift; their existence is what this ADR is committing to make unnecessary in future

---

*Closes #600 when merged.*
