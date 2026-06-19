# ADR-0019: Protocol Integrity Gaps and Mitigations

## Status

Accepted (2026-06-19). All Post 3 / v1 gaps are implemented; the remaining
gaps are documented limitations sequenced for v1.5 / v2 per `ROADMAP.md`
(the authoritative sequencing source).

## Context

A structured stress test of the Agent Receipts protocol and SDK design
identified thirteen gaps across three categories: protocol design, SDK
implementation, and operational concerns. This ADR documents each gap,
the decision taken (or deferred), and the rationale.

Each gap has a corresponding GitHub issue for implementation tracking.
This ADR records the design decisions; the issues track the work.

## Gaps and decisions

### Protocol gaps

---

#### P1: Silent chain termination on SDK or process failure

**Gap.** If the SDK throws mid-session the chain stops with no terminal
receipt. Auditors cannot distinguish a completed session from a crashed one.

**Decision.** Add a `status` field to `agent_end`:
`complete | interrupted | unknown`. The MCP proxy attempts a best-effort
`agent_end { status: interrupted }` on SIGTERM/SIGINT. Verifier tooling
must flag chains without a terminal receipt as `status: unknown` rather
than treating them as valid complete chains.

**Issue.** #475

---

#### P2: Unauthenticated chain origin

**Gap.** An attacker who can write to the receipt store can inject a
fabricated `agent_start` receipt with `previousReceiptHash: null` and a
freshly generated keypair. The chain verifies internally but is entirely
fabricated.

**Decision.** Deferred to v2. For v1, document explicitly that chain
integrity proofs are internal only — the protocol does not assert that a
given DID is a legitimate agent. Evaluate trust registry and witnessed
`agent_start` options for v2.

**Issue.** #481

---

#### P3: No trusted timestamp binding

**Gap.** `issuanceDate` is self-reported. An agent or attacker with the
signing key can backdate or forward-date receipts.

**Decision.** Deferred from v1; sequenced for v1.5 (regulated-industries
milestone — RFC 3161 TSA is a compliance requirement in financial services
and healthcare). Documented as a known limitation in v1. See ROADMAP.md
for authoritative milestone placement.

**Issue.** #482

---

#### P4: Session ID not explicitly bound in signing input

**Gap.** Nothing prevents replaying a valid receipt from session A into
session B. The signature verifies and the hash chains if constructed
carefully. `sessionId` is in the credential body covered by the proof,
but verifiers should enforce it explicitly.

**Decision.** Verifiers must reject receipts whose `sessionId` does not
match the session being verified. Add explicit sessionId binding check to
the verification algorithm in the spec and all three SDK verifiers.

**Issue.** #477

---

#### P5: Sequence gap attack

**Gap.** `sequenceNumber` is monotonically increasing but does not enforce
contiguity. Receipts can be deleted from the store without breaking the
hash chain by re-signing every downstream receipt with an updated
`previousReceiptHash` (requires the agent's signing key). Auditors cannot
detect deletion without external evidence.

**Decision.** Verifiers must enforce strict contiguity — any gap in
`sequenceNumber` within a session is a verification failure, not a warning.
Document that the store is a trusted component; store-level integrity
(checksums, append-only backend) is out of scope for the protocol but
recommended operationally. See also O2 (store completeness).

**Issue.** #479

---

### SDK / implementation gaps

---

#### S1: Cross-SDK canonicalisation conformance vectors missing

**Gap.** RFC 8785 / JCS implementations (per ADR-0002 and ADR-0009)
may diverge subtly across language SDKs on edge cases: UTF-16 code unit
ordering of non-ASCII keys, ES6 `Number.toString()` semantics, Unicode
normalisation of string values. ADR-0002 § Unicode edge cases catalogues
two latent bugs of this class (Python's UTF-16-LE byte sort #86, Go's
`sort.Strings()` #82). The Python SDK previously diverged on
canonical-vocabulary naming (a pre-rename `eventType: "attest"` symbol);
that specific symbol is fixed, but the divergence class it illustrated
remains live. Mixed-language chains may silently fail to verify.

**Decision.** Mandatory before v1 release. Produce a cross-SDK conformance
test suite: fixed receipt JSON-LD documents (W3C VC envelope per ADR-0003)
with known canonical RFC 8785 byte forms and known SHA-256 hash values.
All three SDKs must produce and verify identically. Round-trip matrix:
TypeScript → Python, TypeScript → Go, Python → Go, and all reverse
directions.

**Issue.** #474

---

#### S2: `GeneratingKeyProvider` reachable in production

**Gap.** `GeneratingKeyProvider` is documented as dev-only but nothing
enforces this. A misconfigured production deployment silently generates
a new DID on every cold start with no error surfaced.

**Decision.** `GeneratingKeyProvider` throws `ProductionKeyProviderError`
if instantiated when `AGENTRECEIPTS_PRODUCTION=true`. Emits a loud stderr
warning in all other non-production cases. Documented explicitly in the
deployment guide. Applies to all three SDKs.

**Issue.** #476

---

#### S3: Unbounded `input`/`output` payload size

**Gap.** `input` and `output` are serialised JSON strings with no size
limit. Large LLM responses or tool payloads produce oversized receipts,
degrading canonicalisation performance, blowing storage budgets, and making
audit trails unreadable.

**Decision.** Two options to evaluate:
1. Configurable size cap with truncation — lossy but simple. Truncation
   must be documented in the receipt (`truncated: true` flag).
2. Content-addressed off-chain storage — store the SHA-256 hash of the
   payload in the receipt, the payload in a separate store. Similar to
   JWT detached payload.

Default recommendation: option 2 for production, option 1 for dev
convenience. SDK to provide both via a `PayloadStrategy` interface.
Decision to be finalised in a follow-up ADR.

**Issue.** #478

---

#### S4: `InMemoryKeyProvider` memory safety

**Gap.** Private key bytes are held as plain `Uint8Array` on the heap,
visible in heap dumps, `--inspect` sessions, and V8 snapshots.

**Decision.** Document the limitation explicitly. Recommend against
`InMemoryKeyProvider` in production. Production adapters should zero
key bytes from the source buffer after copying into the provider.
Platform-level memory protection (mlock, secure enclave) is out of scope
for v1 but noted as a v2 improvement.

**Issue.** #485

---

#### S5: No receipt deduplication / idempotency key

**Gap.** If the MCP proxy wraps a tool call that the agent retries on
timeout, two `tool_call` receipts are emitted for the same logical
operation. Auditors cannot distinguish a legitimate retry from a
duplicated emission.

**Decision.** Add an optional `idempotencyKey` field to the event payload.
Callers may set this to a stable identifier for the logical operation
(e.g. a request ID). Verifier tooling should surface duplicate
`idempotencyKey` values as a warning, not a failure — retries are
legitimate. SDK and MCP proxy to populate automatically where possible.

**Issue.** #480

---

### Operational gaps

---

#### O1: No key revocation path for `did:key`

**Gap.** `did:key` has no DID Document and no revocation mechanism. If
an agent's private key is compromised, all historical receipts are suspect
and there is no way to publish a revocation.

**Decision.** Document the limitation in v1. Sequenced for v1.5
(regulated-industries milestone — revocation is a compliance gate):
publish a signed revocation list format (a JSON-LD document listing
compromised DIDs with compromise timestamps, signed by a well-known Agent
Receipts registry key). Evaluate migration path to `did:web` for
deployments requiring rotation. See ROADMAP.md for authoritative milestone
placement.

**Issue.** #483

---

#### O2: Receipt store completeness guarantee

**Gap.** Receipts are tamper-evident but the store that holds them is not.
Deleting entire sessions from the store is undetectable by the protocol.

**Decision.** Recommend periodic publication of chain-head hashes to an
external append-only log as an operational control. This is out of scope
for the core protocol but should be documented as a recommended deployment
practice. An optional `CheckpointPublisher` interface in the SDK can
facilitate this without mandating a specific backend. Sequenced for v1.5
(regulated-industries milestone — store-completeness evidence is a
compliance gate). See ROADMAP.md for authoritative milestone placement.

**Issue.** #484

---

#### O3: MCP proxy at-least-once receipt emission

> **Superseded by ADR-0020.** The WAL has moved from the MCP proxy to the SDK
> emitter layer, making it available regardless of whether the MCP proxy is
> in use. The verifier-side requirement (treat `tool_call` without
> `tool_result` as `incomplete_tool_roundtrip` rather than a generic chain
> break) remains in force. See ADR-0020 § "At-least-once delivery and the WAL"
> for the current design.

**Gap (historical).** If the proxy crashes after a tool executes but before
emitting the `tool_result` receipt, the tool ran but left no trace. This is
indistinguishable from a tool that was called and never responded.

**Decision (historical).** The MCP proxy must implement a write-ahead log
(WAL) of pending receipts. A receipt is considered emitted only after it has
been durably written to the WAL and acknowledged by the receipt store. On
restart, the proxy replays any unacknowledged WAL entries. Verifier tooling
must handle `tool_call` without `tool_result` as a distinct error case
(`incomplete_tool_roundtrip`), not a generic chain break.

**Current decision.** See ADR-0020. The verifier-side `incomplete_tool_roundtrip`
classification is retained.

---

## Priority order

> The table below is the priority ordering at the time this ADR was written.
> For the current authoritative sequencing across all ADRs, see `ROADMAP.md`.

| Priority | Gap | Effort | Target |
|---|---|---|---|
| 1 | S1 — Cross-SDK conformance vectors | Medium | Before v1 / Post 3 |
| 2 | P1 — Silent chain termination | Low | Before v1 / Post 3 |
| 3 | S2 — GeneratingKeyProvider in prod | Low | Before v1 / Post 3 |
| 4 | P4 — Session ID binding in verifier | Low | Before v1 |
| 5 | O3 — MCP proxy at-least-once ¹ | Medium | Before v1 |
| 6 | S3 — Unbounded payload size | Low–Medium | Before v1 |
| 7 | P5 — Sequence gap enforcement | Low | Before v1 |
| 8 | S5 — Idempotency key | Low | Before v1 |
| 9 | P2 — Unauthenticated chain origin | High | v2 |
| 10 | P3 — Trusted timestamp binding | Medium | v1.5 |
| 11 | O1 — Key revocation | High | v1.5 |
| 12 | O2 — Store completeness | Medium | v1.5 |
| 13 | S4 — InMemoryKeyProvider memory safety | Medium | v2 |

¹ Superseded by ADR-0020. The WAL has moved to the SDK emitter layer; see
ADR-0020 for the current v1-blocker tracking. The verifier-side
`incomplete_tool_roundtrip` classification remains in force.

## Consequences

- Items 1–3 are blockers for Post 3 / HN submission.
- Items 4–8 are blockers for v1 release.
- Items 10–12 (P3 timestamps, O1 revocation, O2 store completeness) are
  documented known limitations in v1, sequenced for v1.5 (regulated-
  industries milestone).
- Items 9 (P2) and 13 (S4) are documented known limitations in v1,
  deferred to v2.
- Each gap has a corresponding GitHub issue. This ADR is the authoritative
  record of the decision; issues track implementation progress.
