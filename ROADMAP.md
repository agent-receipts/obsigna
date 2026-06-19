# Agent Receipts — Roadmap

This document is the single source of truth for what's planned, what's
in-flight, and what's deferred. ADRs record decisions; this roadmap records
sequencing.

When this roadmap and an ADR disagree on sequencing, this roadmap wins
(ADRs record decisions and may be amended via dated amendments — see
ADR-0010, ADR-0012, ADR-0015; this roadmap is the sequencing source of
truth). When they disagree on a design decision, the ADR wins.

Most items link to a GitHub issue. A few rows intentionally don't — they
are folded into a parent issue, tracked across per-SDK issues opened lazily
as each SDK starts the work, or explicitly not filed yet. Those rows say so
inline. Status values: `planned`, `in-progress`, `done`, `deferred`.

---

## Milestones at a glance

| Milestone | Description | Target |
|---|---|---|
| **Post 3** | OpenClaw / Claude Code demo published to HN. Subset of v1 blockers required to avoid embarrassing failure modes in the demo. | Next |
| **v1** | Public protocol release. All known integrity gaps either fixed or explicitly documented as limitations. | After Post 3 |
| **v1.5** | Regulated-industries readiness. Items required to clear a financial services or healthcare compliance review. | After v1 |
| **v2** | Trust-model improvements beyond regulated-industries baseline. | Post-v1.5 |

---

## Regulated industries readiness (v1.5)

Items relevant before a bank, insurer, or healthcare provider can deploy
Agent Receipts in production. Sequenced together because they share one
target audience (regulated-industries adopters) rather than dripped into v2.

The split below reflects a triage by cost-to-build against existing
plumbing, not by label: the cheap-and-core items (timestamp anchoring,
revocation, store-completeness — all of which reuse the daemon's existing
out-of-band anchoring) stay `planned`; the heavy-and-substitutable items
(HSM, a separate verifier service, at-scale multi-tenancy docs) are
`deferred` until a concrete regulated deployment drives them.

| Item | ADR | Issue | Status |
|---|---|---|---|
| RFC 3161 TSA timestamp anchoring (elevated from v2) | ADR-0019 § P3 | #482 | planned |
| Regional TSA support (eIDAS, ICP-Brasil, etc.) — layers on #482 | new ADR needed | #492 | planned |
| Revocation list format and reference implementation (elevated from v2) | ADR-0019 § O1 | #483 | planned |
| `CheckpointPublisher` with object-lock reference backend — base checkpoint anchoring shipped (#889); production object-lock sink remains | ADR-0019 § O2 | #484 | planned |
| Content-addressed payload storage (GDPR erasure) | ADR-0019 § S3 (extends) | #731 | planned |
| Downloadable conformance test suite (packaged suite extending the base vectors shipped in #474) | ADR-0019 § S1 (extends) | not filed | planned |
| PKCS#11 / CloudHSM `Signer` adapter | ADR-0018 | #489 | deferred |
| Standalone verifier service (separable from SDK) — `obsigna verify` CLI already covers the air-gapped audit case | new ADR needed | #490 | deferred |
| Multi-tenancy guidance — key management at scale | docs | #491 | deferred |

The `deferred` rows are closed as not-planned (#489, #490, #491). They are
not required for v1.5 adoption: HSM-backed custody is substitutable by the
existing file/KMS `Signer` paths, standalone verification is already served
by the `obsigna verify` static binary, and at-scale multi-tenancy docs would
describe infrastructure that does not yet exist. Each reopens, or gets a
fresh scoped issue, when a real regulated deployment needs it.

---

## Post 3 blockers

These are the minimum subset of v1 work required before the HN-targeted
OpenClaw demo. The criterion is "would a sharp commenter immediately spot
this and undermine the protocol's credibility?"

| # | Item | ADR | Issue | Status |
|---|---|---|---|---|
| 1 | Cross-SDK canonicalisation conformance vectors | ADR-0019 § S1 | #474 | done |
| 2 | Silent chain termination — `status` field on `agent_end` | ADR-0019 § P1 | #475 | done |
| 3 | `GeneratingKeyProvider` unreachable in production | ADR-0019 § S2 | #476 | done |
| 4 | Sequential receipt construction enforced under parallel tool calls | ADR-0020 | #488 | done |

Item 4 is in this list because the OpenClaw plugin may fire concurrent tool
invocations during the demo. If concurrent emission produces a broken chain
live on HN, that is the failure mode that gets quoted in the top comment.

---

## v1 blockers (post Post 3)

Everything required for a credible public protocol release. Grouped by
workstream rather than priority — items within a workstream are ordered;
across workstreams they can be parallelised.

### Protocol semantics

| Item | ADR | Issue | Status |
|---|---|---|---|
| Explicit `sessionId` binding in verifier | ADR-0019 § P4 | #477 | done |
| Strict `sequenceNumber` contiguity in verifier | ADR-0019 § P5 | #479 | done |
| `idempotencyKey` field for retry deduplication | ADR-0019 § S5 | #480 | done |

### SDK emitter layer

| Item | ADR | Issue | Status |
|---|---|---|---|
| `HttpEmitter` with sync / fire-and-forget strategies | ADR-0020 | #486 | done |
| WAL for at-least-once delivery (long-lived + ephemeral) | ADR-0020 | #487 | done |
| Verifier-side `incomplete_tool_roundtrip` classification | ADR-0019 § O3 → ADR-0020 | (folded into WAL issue) | done |
| Deployment guide for ephemeral compute (Lambda, Cloud Run, Fargate, Azure Functions) | ADR-0018/0019/0020 | #535 | done |

### Collector (receiver)

| Item | ADR | Issue | Status |
|---|---|---|---|
| Reference collector service implementing `POST /receipts` contract | ADR-0020 | #533 | done |
| Operator guide for the reference collector | ADR-0020 | #536 | done |

### SDK cloud key management

| Item | ADR | Issue | Status |
|---|---|---|---|
| Cloud KMS `Signer` adapters (AWS KMS, GCP Cloud KMS, Azure Key Vault) | ADR-0018 | #534 | done |

### SDK payload handling

| Item | ADR | Issue | Status |
|---|---|---|---|
| Bound remaining inline plaintext fields — cap `error` / `prompt_preview` + truncation flag (hash-first model superseded the original `PayloadStrategy` framing; content-addressed/GDPR erasure split to #731, v1.5) | ADR-0019 § S3 | #478 | planned |
| `parameterDisclosure` Phase A — cross-SDK + OpenClaw migration (envelope, Python SDK, OpenClaw rename, cross-SDK tests all shipped) | ADR-0012 | #280 | done |

### Cross-SDK parity

| Item | ADR | Issue | Status |
|---|---|---|---|
| Python SDK `eventType` naming alignment | ADR-0019 § S1 | (folded into conformance vectors) | done |
| `KeyProvider` / `Signer` parity across TS, Python, Go | ADR-0018 | tracked per-SDK | planned |
| `HttpEmitter` parity across TS, Python, Go | ADR-0020 | tracked per-SDK | done |

---

## v2 — deferred

Items remaining for v2 after the regulated-industries elevation. Most have
an issue open; parallel sub-chains is intentionally unfiled until the v1
emitter work clarifies whether the feature is needed. None are scheduled.

| Item | ADR | Issue | Status |
|---|---|---|---|
| Unauthenticated chain origin (witnessed `agent_start` or trust registry) | ADR-0019 § P2 | #481 | deferred |
| `InMemoryKeyProvider` memory safety improvements | ADR-0019 § S4 | #485 | deferred |
| Parallel sub-chains (forked chains + merge receipt) | ADR-0020 | not filed | deferred |

The following were originally targeted for v2 but elevated to v1.5
(regulated-industries readiness):

- Trusted timestamp binding (ADR-0019 § P3)
- Key revocation (ADR-0019 § O1)
- Receipt store completeness (ADR-0019 § O2)

---

## How to update this document

- A new ADR adds items here; the ADR itself only records the decision.
- An item moves between milestones (e.g. v1 → Post 3, or v1 → v2) by editing
  this file. The originating ADR is not amended.
- An item is marked `done` only when the corresponding issue is closed.
- When item numbers in ADR-0019's priority table conflict with this roadmap,
  this roadmap is authoritative.

## ADR index

| ADR | Title | Status |
|---|---|---|
| ADR-0018 | Signer abstraction and cloud-agnostic KeyProvider design | Accepted |
| ADR-0019 | Protocol integrity gaps and mitigations | Accepted |
| ADR-0020 | Emitter abstraction and remote receipt delivery | Accepted |
