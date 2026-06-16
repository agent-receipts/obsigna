# ADR-0029: Attribution-Primary Product Model

## Status

Accepted (2026-06-06). Supersedes the undo-primary framing in ADR-0028.

## Context

ADR-0028 was written with undo as the primary product and attribution
as supporting metadata. Pressure-testing the cascade model produced a
structural observation that inverts that framing.

The observation: "any move is a barrier" fires constantly in real
coding-agent sessions. Per-action cascade undo degrades to checkpoint
restore in practice. Checkpoint restore ("restore the filesystem to a
content-addressed snapshot") is a solved problem — it is precisely what
nono already ships: per-session content-addressed snapshots, Merkle-root
integrity, atomic restore, `.gitignore`-style exclusions. These reversal
mechanics are commodity and are not the basis of a defensible
differentiated product.

The part the cascade pressure-test kept discovering but treating as a
side effect — per-file-identity indexing, blast-radius surfacing,
cross-agent attribution, per-principal mandate tracking — is the part
nono structurally cannot do. nono operates as a single linear actor at
host level. It cannot tell you which of N interleaved actions came from
which subagent under which mandate, or which actions across other files
in the same turn break if you pull one. That is receipt-native and
observer-side, which the reversal-heavy model is not.

The same observation resolves the apparent coding-agent / enterprise
tension. Developers want "what did my swarm just do and what depends on
what." Enterprise compliance wants "what did the agent do, for which
customer, under which mandate, and what is the blast radius of
reversing it." These are the same query over the same attribution engine;
the audience changes, not the core.

## Decision

### 1. The product is attribution and blast-radius; reversal is the thin tier beneath it.

Attribution is not a property of undo — attribution is the feature.
Reversal is the action you offer where the attribution graph and the
drift gate permit. A session that shows attribution and blast-radius
with no reversal capability at all is a complete, useful product. A
reversal-first product without attribution is undifferentiated from
existing filesystem snapshot tools.

This inversion changes what ships first and what the project defends as
its differentiator. It does not invalidate the taxonomy or cascade model
in ADR-0028; those become the operative technical spec for the reversal
tier.

The reason reversal is commodity rather than differentiator is structural,
not incidental: checkpoint-restore mechanics (content-addressed object store,
atomic file restore, Merkle-root integrity, `.gitignore`-style exclusion,
`WalkBudget` limits) are already a solved, widely-distributed capability —
nono ships exactly this, and other filesystem snapshot tools do too. Investing
in richer reversal mechanics produces a better implementation of something that
already exists; it does not produce a capability gap that only Agent Receipts
can fill. Per-agent attribution, cross-chain blast-radius, and per-principal
mandate tracking are structurally receipt-native: they require the signed
issuer identity, the chain ordering, and the delegation graph that no
host-level snapshot tool captures. That is the gap. "Improve the product"
therefore means "deepen attribution and blast-radius", not "invest in the
reversal tier."

### 2. Reversal tier: checkpoint-primary, tip-undo as special case.

The primary reversal unit is the **checkpoint** — a turn-level (one user
prompt → N tool calls) content-addressed snapshot of the filesystem state
before the turn ran. Restoring a checkpoint is atomic and requires no
cascade reasoning.

Per-action undo is a special case, clean only at the tip: the most recent
action on a file identity, with nothing built on top. Interior undo is
compensation with merge conflicts, never clean rollback. The checkpoint
primary design matches how agents actually work (constant renames,
restructures, barrier actions throughout a turn) and matches where
filesystem snapshot tooling already is.

Reversal mechanics (checkpoint restore, atomic write, Merkle integrity,
3-way fallback) are deliberately kept commodity. The implementation
follows the nono object-store design (SHA-256 content-addressed, sharded,
dedup, pure Go, no CGO) but is not differentiated by it. See ADR-0028
§2 for the snapshot store spec.

### 3. The differentiating layer: what attribution provides that reversal tools cannot.

**File-identity index.** An index from logical file identity →
ordered sequence of receipts that touched it, built from the receipt
chain by the attribution engine. This is the data structure that makes
blast-radius answerable.

**Blast-radius surface.** For any action or checkpoint: the set of later
receipts whose file-identity sets intersect it (state dependency) plus
the set of receipts from the same turn on other files (potential semantic
dependency). Semantic dependency (call site added in `Y.go` while
`X.go` was refactored) is not computable from receipts alone; honest
behavior is to surface the co-turn set as a warning, not to claim
correctness.

**Cross-agent attribution.** The receipt schema already carries `issuer`
(agent DID), `principal` (human), `authorization.scopes`, and
`delegation` (parent chain, delegating agent). For a multi-agent session,
the attribution engine groups actions by issuer and links sub-agent chains
to their parent via `delegation.parent_chain_id`. nono sees one host
process; the receipt chain sees N agents under M principals with explicit
mandate scope.

**Cross-principal mandate tracking.** `authorization.grant_ref` and
`delegation` together describe what each agent was permitted to do and
by whom. Blast-radius with mandate scope answers "if I undo this
checkout, which other changes were made under the same grant, and does
reverting any of them exceed the scope of the original authorization?"
This is the enterprise compliance read; it runs over the same engine as
the developer read.

**Reversal as gated action, not raw capability.** Because attribution
is primary, reversal is offered as an attributed action: the attribution
engine computes the blast radius and drift status, the policy gate
approves or flags, and the reversal receipt is signed with `reversal_of`
linking it into the same chain — making the undo itself auditable,
attributable, and mandate-scoped. A standalone checkpoint-restore tool
has none of this.

### 4. Smallest buildable thing

**Attribution and blast-radius read over a real multi-agent session, with
no reversal.** This is a read-only query over the existing SQLite receipt
store; it requires no new capture, no snapshot store, no undo agent.

Inputs available in the store today:
- `chain_id`, `sequence` (indexed); `issuer_id`, `principal_id` (columns, not indexed)
- `action_type`, `timestamp`, `risk_level` (indexed); `status` (column, not indexed)
- Full `receipt_json` carrying `action.target.resource`, `delegation`,
  `authorization`, `intent.prompt_preview`, `credentialSubject.chain`

Query shape (pseudocode, implemented in the dashboard):

```
For a given session (all chains sharing issuer.session_id):
  1. Build file-identity → [(chain_id, sequence, issuer_id, action)] index
     from action.target.resource in receipt_json across all chains.
     NOTE (v0): action.target.resource is a path string, used as a proxy
     for logical file identity. ADR-0028 §4 prohibits path strings for
     the conflict relation (moves, symlinks, case-insensitive FSes make
     path strings unreliable). v0 accepts this limitation explicitly;
     a follow-on adds identity graph tracking for moves.
  2. Group into turns: cluster consecutive receipts from the same issuer
     by time proximity or by chain sequence runs.
  3. For each action:
       blast_radius = {
         state_deps:      later receipts whose path-string sets intersect
                          this one (verified by chain ordering — these are
                          real state dependencies within the path-string
                          approximation),
         semantic_deps:   co-turn receipts from any issuer touching other
                          paths (heuristic only — receipts cannot prove
                          symbol-level coupling; surface as a warning,
                          not a confirmed dependency),
         cross_agent_state:    state_deps from a different issuer_id,
         cross_agent_heuristic: semantic_deps from a different issuer_id,
       }
  4. Render grouped by issuer (agent), within each: grouped by turn,
     within each: actions with blast-radius annotations.
```

`session_id` is not a stored column today (it lives in `receipt_json`
via `issuer.session_id`). For v0 the query scans `receipt_json` for all
chains in the time window and groups by parsed `session_id`. A follow-on
schema migration adds `session_id` and `delegation_parent_chain_id`
(extracted from `credentialSubject.delegation.parent_chain_id`) as
indexed columns.

This is buildable in the `dashboard` repo against its existing read-only
store interface with no changes to the capture path, the daemon, or the
wire format. If looking at N actions grouped by agent identity and file
contact — with blast-radius annotations and turn boundaries — is useful
against an orchestrator session with no reversal capability at all, the
product is proven and reversal is an additive tier on top. If it is not
useful, the reversal tier does not rescue it.

**Success criterion.** The MVP is validated by running it against a real
multi-agent or orchestrator session (not a synthetic fixture) and making a
binary judgment with zero reversal capability present: does per-agent
attribution grouped by turn, with blast-radius annotations, answer questions
a developer or operator could not answer from raw logs alone? If yes, the
attribution engine has earned its place and reversal can be layered on top.
If no, adding reversal to the same read does not change the answer — the
attribution layer itself needs rethinking first. Shipping without this
judgment, or substituting a synthetic session for a real one, does not count
as validation.

### 5. Nono relationship

nono (Apache 2.0) solves checkpoint-restore mechanics well. The
no-CGO constraint (project-wide) precludes linking nono as a library.
The relationship is:

- **Design: borrow.** Object-store sharding, TOCTOU re-hash, APFS
  `clonefile`, atomic restore, `WalkBudget`, `ExclusionFilter` — these
  are the right designs; implement them in pure Go for v1.
- **Sidecar: optional deep mode (v2).** Users who run the agent inside
  nono get full-filesystem + shell coverage the PreToolUse hook cannot
  reach. The attribution engine reads nono's snapshot manifests
  alongside receipts. This is opt-in for users who want it.
- **Not a competitor.** nono is a single-session host-level sandbox.
  Agent Receipts is a multi-agent, multi-principal attribution layer.
  They address different parts of the same problem space and compose
  cleanly.

## Consequences

- The dashboard gains an attribution and blast-radius view as the primary
  new feature, built against the existing store interface.
- The undo agent (ADR-0028 §6) is deprioritized below the attribution
  read; it ships as a gated action through the attribution engine, not as
  a standalone tool.
- `session_id` and `delegation_parent_chain_id` (from
  `credentialSubject.delegation.parent_chain_id`) become candidates for
  promoted indexed columns in the store schema.
- The project's value proposition shifts from "undo what your agent did"
  to "see exactly what your agent swarm did, who authorized it, and what
  breaks if you pull any piece of it." Reversal is what you offer where
  the graph permits — not the headline.
- The shared core (attribution engine) serves both developer and
  enterprise audiences without architectural bifurcation. The query
  differs; the engine does not.
