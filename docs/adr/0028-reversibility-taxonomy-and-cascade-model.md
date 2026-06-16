# ADR-0028: Reversibility Taxonomy and Cascade Model

## Status

Accepted (2026-06-06). Framing superseded by ADR-0029 (attribution-primary); taxonomy and cascade model remain operative.

The pre-commit PreToolUse-hook capture decision (§2) applies to the **reversal
tier only** and is **deferred** until reversal beyond checkpoint restore is
built. The attribution + blast-radius MVP (ADR-0029 §4) requires no new capture
and does not depend on this hook. A future reader should not interpret the
"Accepted" status of §2 as a signal that in-process capture is in scope for
the attribution sprint.

## Context

The Agent Receipts schema has carried reversibility fields (`reversible`,
`reversal_method`, `reversal_window_seconds`, `reversal_of`,
`state_change.before_hash`, `state_change.after_hash`) since the initial
spec. As of v0.4.0 none of these fields are populated by any emitter,
daemon, hook, or proxy — they appear in SDK type definitions and
cross-SDK canonicalization test vectors but no live capture path writes
them. This ADR pins the design required to make them load-bearing,
records the architectural decisions a pressure-test of the cascade model
surfaced, and establishes the explicit limits where undo is not possible.

ADR-0029 supersedes the framing of this ADR: the product is
attribution-and-blast-radius, not undo. This ADR is retained because its
taxonomy and cascade conclusions are correct and remain the operative
technical model for the reversal tier that ADR-0029 places underneath
attribution.

## Decision

### 1. Reversibility taxonomy

Reversibility is a function of capture completeness, elapsed time, and
external mutation since the action — not of action type alone. The tier
is the floor over all effects of an action; heterogeneous actions (a
shell command that edits files and hits the network) take the minimum
tier across their effects.

**T0 — Reconstruct-reversible.** The reverse is computable from the
captured `tool_input` without any separate snapshot. The before-state is
implicit in the structured diff. Examples: `Edit`/`MultiEdit`
(swap `old_string`/`new_string`); `mkdir`; `mv a b` where `b` did not
exist.

**T1 — Snapshot-reversible.** The reverse requires the captured
before-image. Before-state must be captured at a pre-commit point; it
cannot be recovered from `PostToolUse` alone. Examples: `Write` (full
overwrite), `rm`, `git checkout -- file` over a dirty tree.

**T2 — Window-reversible.** A provider offers timed reversal via an API
(e.g. `gmail:undo_send`). Silently decays to T4 when the clock expires.
The `reversal_window_seconds` field was designed for this tier.

**T3 — Compensable-only.** No rollback; a new forward action approximates
restoration. The compensation has its own observable side effects. The
compensation action must be declared by the tool or server, not inferred
from the tool name. Examples: `git push` → `git revert` (visible extra
commit); `git reset` of pushed history is not T3 — it is a destructive
action against collaborators.

**T4 — Irreversible.** Two subtypes:
- *Physics-irreversible*: the effect left the trust boundary and was
  received or acted on (email read, money settled, package published,
  webhook consumed downstream).
- *Self-inflicted-irreversible*: no snapshot was captured and
  reconstruction from input is not possible. This is an engineering gap,
  not a physical limit; moving capture earlier converts self-inflicted T4
  to T1. The distinction matters for roadmap honesty.

### 2. Pre-commit capture via PreToolUse hook

Before-state capture for T1 actions is only possible at the pre-commit
point — by the time `PostToolUse` fires, the original bytes are gone.

The capture mechanism is the existing `PreToolUse` hook path (already
parsed in `hook/cmd/agent-receipts-hook/claude_code.go`, mapping to
`decision="pending"`). This keeps the collector out-of-process and
non-invasive for structured file-editing tools whose target paths are
explicit in `tool_input` (`Write`, `rm`). The snapshot store design
follows the nono content-addressable store pattern: SHA-256 addressed,
git-style two-character prefix sharding, `.gitignore`-style exclusion
filters, `WalkBudget` entry/byte limits, atomic temp-file-plus-rename
writes. A pure-Go implementation is required (no CGO — project-wide
constraint).

Shell (`Bash`) targets are T4 by default: `argv` is observable but the
set of files the command will touch is not enumerable pre-commit without
kernel-level interception. Shell coverage requires a sandbox layer (e.g.
nono in sidecar mode); it is not addressable by the hook path alone.

### 3. Wire change: additive at frame version "1"

The reversibility fields (`state_change`, `reversible`, `reversal_method`,
`reversal_window_seconds`, `reversal_of`) are added as optional
`omitempty` fields to both `emitter.frame` (`sdk/go/emitter/emitter.go`)
and `pipeline.EmitterFrame` (`daemon/internal/pipeline/build.go`). The
version string stays `"1"`. Rationale:

- Frame decode is non-strict (`json.Unmarshal` without
  `DisallowUnknownFields`); old daemons silently ignore new optional
  fields — forward-compatible.
- The `v` version gate (`validateFrame`) guards interpretation of existing
  fields, not presence of new optional ones. A bump is warranted only
  when the *meaning* of existing bytes changes or a new field is required.
- ADR-0024 Gate #8 (daemon ↔ SDK protocol compatibility, implemented by
  `scripts/daemon_protocol/check.py`) catches non-negotiable SDK/daemon
  pairs at release time; this change does not trigger it.

The **actor model** for state-change fields: at `PreToolUse` the hook
writes the target file's content hash to a pending entry in the undo log
(keyed by `tool_use_id`); at `PostToolUse` the hook reads that entry to
populate `before_hash`, computes `after_hash` from the current file state,
and includes both in the emitter frame. `emitter.Event` must gain
`StateChange`, `Reversible`, `ReversalMethod`, `ReversalWindowSeconds`,
and `ReversalOf` fields alongside the frame fields. If the `PreToolUse`
entry is absent (hook was not installed, or snapshot failed), the fields
are omitted and the action is marked non-reversible in the undo log.

> **Runtime note:** `tool_use_id` is a Claude Code-specific concept
> (present in `hook/internal/claudeCodeFrame`). It is not part of the
> protocol schema, `emitter.Event`, or `emitter.frame`. Runtimes other
> than Claude Code need an equivalent per-invocation correlation ID to key
> the undo log; the implementation strategy is runtime-specific.

A **parity test** is required: `emitter.frame` and `pipeline.EmitterFrame`
are hand-mirrored by convention with no compiler enforcement. The test
must fail if the two structs diverge.

### 4. Cascade model

**Conflict relation.** Two actions conflict when their target sets
intersect over *logical file identity*, not path strings. Moves are
reparenting edges that rewrite the identity graph at runtime; path strings
lie (case-insensitive filesystems, symlinks, hardlinks).

**Barrier actions.** Any action that subsumes prior state rather than
augmenting it is a **barrier**: `Write` (full overwrite), `rm`, `mv`
(source side), `git checkout -- file`, directory ops, symlink traversals,
binary files. A barrier ends the cascade for its target identity; the
only clean undo past a barrier is a turn-level checkpoint restore.

**Cascade ordering.** Undo of action N requires undoing the transitive
closure of later actions whose target identities intersect N's, in reverse
order. This is reverse-topological over the conflict graph, not
LIFO-over-all. The conflict graph is a secondary index the undo agent
builds by scanning the chain; the chain itself provides ordering.

**Primary unit: checkpoint restore. Special case: tip undo.** Barriers
fire constantly in real coding-agent sessions (agents rename and
restructure throughout their work), so per-action cascade undo degrades
to checkpoint restore in practice. This is not a tuning problem; it is
evidence that the checkpoint is the right primary unit. Per-action undo
is clean only at the *tip* — the most recent action on a given file
identity, with nothing built on top of it. Interior undo (undoing a
non-tip action in a dependent history) is compensation only, with
possible merge conflicts; it must be flagged as such and never implied
to be a clean rollback.

**Drift gate.** Safe undo requires `hash(current_state) == recorded
after_hash`. The full gate is chain reconciliation: the per-file sequence
of `(before_hash, after_hash)` pairs must be contiguous. Any
discontinuity indicates an unobserved mutation (external tool, human
editor, non-hooked process). The receipt chain cannot distinguish a benign
human save from a dangerous rewrite; the fail-safe rule is: any
discontinuity → manual 3-way or refuse. Never auto-restore across a gap.

**3-way fallback.** On drift, the three sides are: *base* = `after_hash`
(state right after the agent's action), *ours* = current on-disk state,
*theirs* = `before_hash` (target restore state). Reverse-apply the
agent's diff (`old_string`/`new_string` for T0; `diff(before, after)` for
T1) onto *ours*. Conflict markers appear where the human edited the same
hunks. Binary files have no line merge — refuse on drift.

**Semantic blast radius.** The conflict graph sees state dependency, not
semantic dependency. An edit to `X.go` and a call-site added to `Y.go`
in the same turn have non-intersecting target sets; the graph says
independent. Undoing the `X.go` edit in isolation breaks the call in
`Y.go`. Honest behavior: always surface the set of later actions that
touched *other* files in the same turn as a blast-radius warning, even
when the state undo is clean.

**Cross-chain ordering.** Multiple agents sharing a session have no
global clock (wall-clock `action.timestamp` is unreliable across
processes; `trusted_timestamp` is optional). Cross-chain conflict ordering
is approximate; fail-safe to manual when chains interleave on the same
file identity. Cross-principal cascades (undoing agent A's action
requiring undoing agent B's later action) require the higher of the two
authorizations and human approval.

### 5. Undo as a privileged action

- Reversal receipts use `reversal_of` (defined in the JSON schema at
  `outcome.reversal_of`; the Go SDK `receipt.Outcome` struct must be
  extended with `ReversalOf string \`json:"reversal_of,omitempty"\``).
  The reversal receipt's `state_change.after_hash` must equal the original
  receipt's `before_hash`, making undo cryptographically verifiable in the
  chain.
- Authorization: undo requires ≥ the original action's authorization
  level. A low-privilege context cannot undo a high-privilege action.
- Policy gate: undo must enforce pass/flag/pause/block semantics
  equivalent to the MCP proxy's policy engine. The undo agent implements
  this gate directly — it cannot import `mcp-proxy/internal/policy`
  across the module boundary. High-risk undo → pause/human-in-the-loop;
  never auto-applied above low risk.
- Snapshot integrity gate: `hash(blob) == before_hash` before any restore.
  A poisoned snapshot store must not become an arbitrary-write primitive.
- Undo-bombing: "undo the last N actions" triggered by untrusted content
  is a destructive primitive. Rate-limit, require confirmation, treat
  large cascades as high-risk.

### 6. Component model

- **Undo agent** (new CLI `agent-receipts undo` or daemon subcommand):
  owns the undo log, the snapshot store (v1), the drift/authorization/
  integrity gates, and restoration. Issues reversal events to the daemon.
- **Daemon** (existing, sole writer): signs and persists reversal receipts.
  No change to sole-writer invariant (ADR-0010).
- **Dashboard** (existing, read-only): displays reversibility and triggers
  undo via the undo agent. Never performs restoration directly (ADR:
  dashboard-is-read-only).
- **Snapshot store** (v1, pure Go): content-addressed store for T1
  before-images. Separate from the receipt store; holds plaintext bytes
  including potential secrets. Must apply `.gitignore`-style exclusion
  filters plus secret-pattern detection; mode-0600; local-only; TTL GC.

### 7. Explicit limits

Shell is T4 without kernel interception. "Any move is a barrier" is
correct and fires frequently — this is not conservatism to be tuned away;
it is the proof that checkpoint-primary is the right model. Interior undo
is compensation only. Anything past the trust boundary (email received,
money settled, package published) is physics-irreversible; refuse, do not
compensate silently. The closed-world assumption required for chain
reconciliation is violated by any non-hooked mutation; passive capture
cannot guarantee completeness.

## Consequences

- `state_change.before_hash` and `after_hash` are populated by real
  emitters for the first time. The Merkle-root-as-hash design (from the
  nono snapshot store) makes these cryptographically committed.
- `reversal_of` is used in production for the first time, completing the
  chained verifiable-undo loop the schema anticipated.
- A new parity test must be added for `emitter.frame` /
  `pipeline.EmitterFrame` field alignment.
- The undo agent is a new binary; the snapshot store is new on-disk state
  (plaintexts, not just hashes) and a new security surface.
- Shell undo is explicitly out of scope without a sandbox integration.
  Over-promising on shell reversibility would be a correctness bug.
