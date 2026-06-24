# OPERATIONS.md — Active work graph

> **Purpose.** This file is the operational source of truth for what is in flight, what is blocked, and what is next. Updated whenever a node's state changes. Read by humans and by agents.
>
> **Scope.** Captures the *active subgraph* of work: current foreground work, what is blocked on a decision, and what is next. Does not capture every open issue — most open issues are background, not blocking the current focus. Items enter this file when they become active; they leave it when they ship. Shipped work is collapsed into the dated ledger below, then drops off entirely; git history and the PRs remain the durable record.

---

## How to use this file

**Otto:** Open this first when starting a session. Scan `## Decisions blocked on Otto` first — those are foreground. Then scan `## Next farmable (computed)` — those are what can be dispatched to agents right now.

**Agent (Claude Code driver session):** Read this file. Compute the set of nodes where `state: open` AND all `depends_on` are `shipped` AND no node in `conflicts_with` is currently `in-flight`. From that set, surface to Otto any `blocked on otto` items first. If none, pick the node with the most dependents (clears the most downstream work). Execute the prompt referenced in its issue. On completion, update this file: set `state: shipped`, record the merged PR.

**Agent (subagent doing one node's work):** Read this file for context, but do not modify it. Your scope is one node's issue.

---

## Last updated

`2026-06-24` — **Active DAG is clear.** The two foreground closures both completed: forensic **response disclosure** shipped (#936 merged, #819 closed — Go SDK + daemon caught up to TS/Py, protocol bumped to 0.6.0/context v3), and the **checkpoint-anchoring** thread closed out (#932 crypto extraction + #933 browser-verifier wiring merged; #872 closed — its v1-relevant hardening shipped in #914, the v1.5 residue folded into #484). No open active nodes remain. **The headline "next" is now a decision, not code: declare v1** — see *Decisions blocked on Otto*. v1 is engineering-complete (all Post-3 + v1 blockers done, Signer/KeyProvider parity verified across SDKs, no open in-flight limitation).

`2026-06-23` — **Reconciliation sweep after a two-week gap.** ~100 PRs merged since the prior `2026-06-08` snapshot retired the entire old active DAG (closures 0–2, wave-1/2 items, and all ADR-0024 verification gates had already shipped). The shipped detail for those is removed from this file (git + PRs are the record) and the live sections below are rebuilt around the work that is genuinely in flight. Headline: the **Obsigna brand split + dual-site docs** and the **ADR-0037 Go vanity-path migration** both completed; **grounded-principal** (ADR-0038) and **checkpoint anchoring** landed as features; release train carried sdk/go to **0.23.0** and the umbrella to **0.29.0**.

---

## Decisions blocked on Otto

- **Declare v1 (the headline).** v1 is engineering-complete and has no open in-flight limitation. What remains is a decision + a release act, not code:
  1. **Version-label call** — spec is at `0.6.0`, SDKs at `0.x` (sdk-go 0.23.0, sdk-ts 0.15.0, sdk-py 0.14.0, umbrella 0.29.0). Decide what carries the 1.0 stamp: spec → 1.0.0 only / coordinated 1.0 across everything / positioning-only declaration keeping 0.x numbers.
  2. **v1 limitations statement** — mostly assembled already in `docs/threat-model.md`; consolidate the deferred gaps (v1.5: #482/#483/#484/#492/#731; v2: #481/#485; out-of-scope: #151) into one explicit "known limitations" note.
  3. **Announcement / positioning** — ties to the Post-3 HN demo, whose blockers are cleared.
- **PR #708** (`doc-e2e persona fleet`) — scheduled CI that executes the documented journeys. Parked on Otto: repo secret + action-SHA pin + workflow `permissions` sign-off. Unchanged for weeks; decide to land-with-guardrails or close.
- **Draft-PR triage** — review-or-close decisions on three idle drafts:
  - **#532** hermes-agent plugin (open since 2026-05-22).
  - **#442** blog: "One Chain, Two Channels, Zero Secrets".
  - **#444** blog: "Native Tool Calls in the Audit Trail".
- **#803** rebrand leftover — data paths, OS user, and env vars still say `agent-receipts`. User-facing; needs a call on whether to break the path/env contract now (migration shim) or defer to a major.

---

## Active nodes (DAG)

**No open active nodes.** Both foreground closures completed (see the ledger below): forensic response disclosure (#819 → #936) and checkpoint anchoring (#932/#933 merged, #872 closed). The next foreground work is the **declare-v1 decision** under *Decisions blocked on Otto*, which is not a farmable code node.

In-flight PRs (background, not blocking the DAG):
- **#943** — `docs(threat-model): response disclosure is shipped` — flips the stale "not yet wired" note (interim #935 wording that #936 superseded). Docs-only, awaiting merge.
- **#942** — `feat(sdk-ts): add target to the daemon emitter frame` — cross-SDK parity for `action.target` on the TS emitter (mirrors Go/hook). New work.

---

## Recently shipped — ledger (`2026-06-08` → `2026-06-24`)

Collapsed record of closures that completed in this window. Detail lives in the PRs.

- **Forensic response disclosure — SHIPPED.** `outcome.response_disclosure` end-to-end (ADR-0012, #819). Spec v0.6.0 + TS + Py shipped in #913; Go SDK + daemon completed in #936 (`EncryptResponse`/`DecryptResponse`, daemon `--response-disclosure` sealing `f.Output`, `obsigna receipt disclose --response`), which also bumped the Go SDK to protocol 0.6.0 / context v3 to match TS/Py. Threat-model note flipped to shipped (#943).
- **Checkpoint anchoring — CLOSED OUT.** Crypto extraction into `obsigna.dev/sdk/go/checkpoint` (#932) + external-anchor verification wired into the browser verifier (#933) merged; #872 closed — its v1-relevant hardening shipped in #914 (async sink emission, `verify --against-anchor` scaling, cadence tuning), and the v1.5 residue (production-grade sinks, durability/retry spool, git-sink efficiency) folded into #484.
- **Obsigna brand split + dual-site docs — SHIPPED.** README reframed as Agent Receipts (protocol/spec) vs Obsigna (tools) (#829); docs split into two sites (#830), tooling links → obsigna.dev (#831); SDK/cmd-name alignment + CLI rename to `obsigna receipt <verb>` (#821–#827, #844); browse-link canonicalization `ar` → `obsigna` (#828); SEO + Plausible + Google Search Console (#838–#842); blog-source site retrigger (#854); examples-repo link + dashboard refresh (#874, #903).
- **ADR-0037 Go vanity-path migration — SHIPPED (completes the previously-flagged gap).** ADR-0037 (#846); full module migration to `obsigna.dev/…` (#922); go-import vanity meta tags + post-deploy liveness check (#912); release gates repointed at the vanity path (#926); `require obsigna.dev/sdk/go v0.22.0` in daemon/hook/mcp-proxy (#927) + collector (#928); integration test moved to the daemon module (#929); dependabot ignores internal modules (#881); dependency allowlist pruned (#931).
- **Grounded principal / attribution — SHIPPED.** Daemon derives receipt principal from kernel-attested peer uid → `did:user:<login>` (#847); ADR-0038 grounded-principal conformance tier (#895) implemented across SDKs (spec §7.9, #915); attribution blog "Your agents are isolated. Your shared state isn't." (#849, #850); EU AI Act traceability language (#845).
- **Taxonomy / action classification — SHIPPED.** Taxonomic `action_type` on the emit frame: hook (#896), sdk-py (#897), mcp-proxy (#898); risk primitives extracted into a receipt-free leaf package (#901); hook classifies shell `rm`/`mv`/`cp` so deletes carry a target + real risk (#893); `action.target` resource for non-file actions (#855); failed tool calls receipted via Claude Code `PostToolUseFailure` (#856).
- **Checkpoint anchoring (feature core) — SHIPPED.** Out-of-band anchor (#871), Flush docstring fix (#873), threat-model update — tail-truncation no longer partial (#889), production hardening (#914). Remaining work tracked as live nodes above.
- **Verify ergonomics — SHIPPED.** `obsigna receipt verify --json` (#886); `receipt.VerifyRaw` for raw-bytes signature verification (#887); browser-based verifier at `obsigna.dev/verify` (#924).
- **opencode-plugin @obsigna — SHIPPED.** Graduated 0.1.0 (#869); brand rename of exports (#866); OIDC trusted publishing (#862–#865); sdk-ts `/emitter` subpath export (#867).
- **Hardening / CI — SHIPPED.** Bound inline plaintext error + `prompt_preview` fields (#894); socket-wait loops break only on ENOENT/ECONNREFUSED (#891); lefthook no longer masks shellcheck failures (#884); release gated on dependency-manifest check pre-publish (#892); npm dependency management + pinned esbuild/dompurify (#875).
- **Release train.** Umbrella CHANGELOG 0.26.0 → 0.29.0; sdk/go 0.20.0 → 0.23.0; sdk-ts 0.15.0; sdk-py 0.14.0 (PEP 440 `0.14.0a1`). Stamp PRs #848, #859, #904, #905, #916–#920, #925, #930.

---

## Background — not in the active graph but worth noting

- **ADR-0027 opensandbox cluster** (`adr-followup`) — #768 (mTLS provisioning), #770 (`parentChainRef` in daemon IPC), #771 (`incomplete_session` classification), #772 (host relay binary), #773 (in-sandbox AR proxy binary), #774 (upstream native emit hook to OpenSandbox). A coherent follow-on body of work; not yet sequenced into the DAG.
- **Reliability / storage** — #739 (finish cross-emitter integration coverage), #729 (cross-SDK SQLite WAL parity), #730 (daemon at-rest encryption posture), #731 (content-addressed off-chain payload + GDPR erasure), #762 (export receipt chains as OTLP traces).
- **Repo hygiene** — #767 (move `hook/` into `integrations/` to complete the grouping).
- **Blog campaign** — draft PRs #442/#444 pending Otto writing time (also listed under decisions).

---

## Next farmable (computed)

As of `2026-06-24`: **no farmable code nodes remain** — the active DAG is clear. The next foreground work is the **declare-v1 decision** (above), which is Otto's to make, not an agent task.

The next *bodies* of work, once Otto sequences them, are background clusters that need breaking into nodes first:
- **v1.5 — regulated-industries readiness:** #482 (RFC 3161 TSA timestamp anchoring — cheap+core, rides on the shipped checkpoint anchor), #483 (key revocation), #484 (production-grade checkpoint sinks + the #872 residue), #492 (regional TSA), #731 (content-addressed payload + GDPR erasure).
- **ADR-0027 opensandbox cluster:** #768/#770–#774.
- **Reliability / storage:** #739, #729, #730, #762.

Foreground decisions pending Otto: declare v1 (headline), #708 (doc-e2e fleet), the idle drafts (#532/#442/#444), #803 (rebrand leftovers).

---

## Update protocol

When a node ships:
1. Find the node block in this file.
2. Change `state: open` → `state: shipped`.
3. Add the merged PR number under `prs:`.
4. Add `artifacts:` if the work produced a durable URL or file.
5. Recompute the "Next farmable" section. (Move newly-unblocked nodes up if needed.)
6. Periodically, collapse fully-shipped closures into the "Recently shipped" ledger and let older ledger entries drop off — the DAG is for live work.

When a decision is made:
1. Move the item out of `## Decisions blocked on Otto`.
2. If it was `farmable: no`, change it to `farmable: yes` and add the prompt reference.
3. File any implementation issues spawned by the decision; add them as new nodes.

When a new issue is filed that's part of an active closure:
1. Add it as a new node with full schema.
2. Wire up `depends_on` / `conflicts_with`.
3. Add to "Next farmable" if it qualifies.

When an issue closes that *isn't* in this file (background work):
1. No action. The file tracks active work, not all activity.

---

## Conventions

- A node's `issues` and `prs` are for cross-reference; the issues themselves remain the source of truth for *task* detail. This file is the source of truth for *graph* state.
- `conflicts_with` is for shared mutable state (same file, same config), not for logical coupling. Two unrelated docs touching different files don't conflict even if they cover related topics.
- `farmable: yes` means an agent can execute this node without Otto's involvement except to review the PR. `farmable: no` means Otto must do part of the work (writing, deciding) before the rest can run.
- A "closure" is editorial. Nodes don't need to belong to one; the closure groupings are how Otto thinks about the work, not how the DAG enforces it.
</content>
</invoke>
