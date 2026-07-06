# ADR-0039: Formal Verification of Receipt-Chain Tamper-Evidence (Alloy)

## Status

Accepted (2026-07-06)

## Context

Spec §3.2 and §7 make a security claim at the heart of the protocol: the receipt
chain is **tamper-evident** — "each receipt contains the hash of the previous
receipt, creating a tamper-evident log," and the §7.3 verification algorithm
detects modification, insertion, deletion, and reordering of stored receipts.

This claim has been argued in prose (spec §7, ADR-0008, ADR-0019) and pinned by
per-SDK unit tests, but it had never been **machine-checked as a property of the
verification algorithm itself**, independent of any one implementation. The
prose also contains a documented *floor* (tail truncation is undetectable in-band,
§7.3.1) and a documented *boundary* (a key-holder can forge, ADR-0019 P2/P3),
and it is easy for an informal reading to over- or under-state exactly which
tampers §7.3 catches. A formal model forces every conjunct of the verification
predicate to be written down and every adversary move to be enumerated, and it
either produces a counterexample or exhausts a bounded space cleanly.

The verification property is **structural and adversarial-construction over
bounded instances**: does there exist a tampered chain, built by an adversary
without the issuer's key, that still satisfies the §7.3 predicate? That is the
sweet spot of a **relational bounded model checker**, not a temporal one.

## Decision

Formalize the §7 receipt-chain verification algorithm and its tamper-evidence
property in **Alloy 6**, as an **additive** artifact under
[`formal/chain-invariants/`](../../formal/chain-invariants/), machine-checked
over increasing bounded scopes. Nothing in the spec, schema, or SDKs is changed.

### Tool choice and rationale

- **Alloy 6.2.0**, SAT4J (pure-Java) backend, run headless via Alloy's own
  built-in `exec` command (`alloy exec -c '*' -s sat4j`, wrapped by
  [`run.sh`](../../formal/chain-invariants/run.sh)). `exec` runs every command,
  enforces each command's `expect` annotation, and exits non-zero on any
  mismatch — its supported CLI, nothing custom to compile.

**Alloy vs TLA⁺.** The two tools answer different questions. **Alloy** is
relational logic over a bounded universe: it compiles to SAT and searches for a
*structure* — a configuration of atoms and relations — that satisfies or violates
a property. Its native question is "does there exist a structure such that…?"
**TLA⁺** specifies *systems that change over time*: an initial state, a next-state
action relation, and safety/liveness properties over all executions; its native
question is "over all behaviors, does this hold?" In a slogan: **Alloy is for
structure, TLA⁺ is for behavior over time.**

This property is structural. Tamper-evidence is a predicate over a *single stored
artifact* — the chain a verifier is handed — and the check is existential: *does
there exist a chain, built by adversary operations over a genuine one, that is
tampered yet still passes §7.3?* The adversary operators are one-shot
constructions of an alternative instance, not temporal transitions to interleave;
hash linkage, injectivity, the issuer-signed set, and sequence contiguity are
relations and functions over finite atoms. Alloy's SAT-based finder *is* the
search for a tampered-but-verifying witness. Expressing the same thing in TLA⁺
would shoehorn a static predicate into a state machine (effectively a one-state
spec), and TLC — an explicit-state enumerator — is a worse fit than SAT for
constructing a witness under injectivity constraints.

**Tool choice tracks the axis, not just this one property.** Record-integrity is
structural → Alloy. The properties this model defers — parallel emission,
crash-recovery / at-least-once delivery (ADR-0019 O3, ADR-0020), key-rotation
traversal over a live stream (§7.3.7) — are about interleavings, fairness, and
liveness over executions → TLA⁺, in a **separate future model**. The two are
complementary, split by property class, not substitutes.

**Bounded vs unbounded.** Both Alloy and TLA⁺'s TLC are *bounded* — finite scope
/ finite state — so neither, as a checker, proves the property for all chain
lengths. The route to unbounded assurance is a proof assistant: TLA⁺'s **TLAPS**
(or Coq/Isabelle/Lean) discharging the master soundness theorem as an *inductive*
proof on chain position (null-first anchors the genesis; hash injectivity forces
each `previous_receipt_hash` to name a unique predecessor). That is the one place
TLA⁺-family tooling would extend *this* property rather than a different one — see
"What is and is not guaranteed → Path to unbounded assurance."

*Two caveats.* (1) Alloy 6 added mutable state and linear temporal operators
(`always`, `eventually`), so "Alloy = structure only" is a simplification — but
serious concurrent/distributed behavior (fairness, complex liveness, refinement)
remains far more idiomatic in TLA⁺/TLC, and this property needs none of Alloy's
temporal features (it is plain relational Alloy). (2) This is a choice about the
*property*, not a ranking of the tools: were we verifying the receipt system's
*runtime* behavior, TLA⁺ would be the first reach.

### Threat model (encoded in the model, stated here in prose)

- **Adversary:** any party **without the issuer's private key** who wants to
  modify, insert, delete, or reorder receipts in a stored chain and still have
  the result pass §7.3 verification.
- **Cryptography is abstracted, not modeled:**
  - **Hash** — an injective function `Receipt → Hash` (fact
    `CollisionResistance`). Injectivity *is* the collision-resistance
    assumption. SHA-256 internals are not modeled.
  - **Signature** — a receipt is "validly signed by the issuer" iff it is a
    member of `IssuerSigned`. The adversary cannot enlarge that set — this is the
    **EUF-CMA unforgeability** assumption. Ed25519 internals are not modeled.
- **Boundary — explicitly OUT OF SCOPE:** a **Byzantine issuer** who *holds* the
  key and signs false-but-valid receipts. That includes backdating
  `issuanceDate` (no default trusted-timestamp binding — ADR-0019 P3) and
  fabricating an entire chain under a fresh keypair ("unauthenticated chain
  origin" — ADR-0019 P2, deferred to v2). The property proven is **integrity
  against non-key-holders**, not the **honesty of the key-holder**. Store-level
  completeness (deleting whole sessions) is likewise an operational control
  outside §7.3 (ADR-0019 O2, §7.3.5).

### Properties checked (each a named Alloy `check`)

The §7.3 algorithm is encoded as `verifies[l]` (signature §7.3 step 2a; null
first-hash step 4; hash linkage step 2b/2c; strict sequence contiguity step 3;
chain_id binding §7.3.4; receipt-after-terminal §7.3.2). Over a genuine chain,
each adversary operator is applied and the tampered log is asserted to fail:

- `Modification_Detected` — altering any signed field breaks verification.
- `Insertion_Detected` — inserting a receipt not signed-and-chained by the
  issuer breaks it.
- `Interior_Deletion_Detected` — removing the head or any interior receipt
  breaks it (tail truncation is deliberately excluded — see below).
- `Reorder_Detected` — permuting the receipts breaks it.
- `CrossChainSplice_Detected` — inserting a validly-signed receipt from another
  chain of the same issuer is rejected (§7.3.4).
- `AppendAfterTerminal_Detected` — appending after `chain.terminal: true` is
  rejected (§7.3.2).
- `Soundness_VerifiedIsGenuinePrefix` (master) — **any** verifying log is a
  genuine chain in issuer order, possibly tail-truncated. Subsumes all six
  operators.
- `Combined_OnlySurvivorIsTailTruncation` (master) — a verifying log that is not
  *exactly* a genuine chain is a *proper prefix* of one: pure tail truncation and
  nothing else.

Supporting commands: `genuineVerifies` / `genuineMultiVerifies` (the model is
not vacuous — genuine chains do verify); six `can*` runs (each adversary
operator is reachable at scope, so no `*_Detected` check passes vacuously);
`truncationSurvives` (the §7.3.1 floor, reproduced as a machine-checked fact).

### Scope

Run over increasing scopes, integer bitwidth stated as `Int`:

- Operator-level checks: scope **5** (`5 Int`) and **7** (`6 Int`);
  `CrossChainSplice` at scope **6** (`5 Int`) and **7** (`6 Int`) — it needs ≥2
  chains.
- Master theorems: scope **5** (`5 Int`), **7** (`6 Int`), and **8** (`6 Int`).

Every command carries an `expect` annotation and the headless runner fails on any
result that contradicts it (a `check` going SAT, or a non-vacuity `run` going
UNSAT), so a vacuity regression cannot pass green. Non-vacuity `run`s are supplied
at **every** scope a check runs at (including 7 and 8), so the strongest results
self-certify that their antecedents are reachable.

Scope *N* bounds every top-level signature (receipts, hashes, chain_ids, genuine
chains) to ≤ *N*, so chains of up to 8 receipts drawn from up to 8 distinct
hashes across up to 8 genuine chains are searched exhaustively for the master
theorems.

## Results

Alloy 6.2.0 / SAT4J. `check` → **UNSAT** means *no counterexample exists in
scope* (property holds); `run` → **SAT** means *the scenario is reachable*. Every
command carries an `expect` annotation and the runner fails on any mismatch;
a headless run reports **0 unexpected results, 0 errors (exit 0)**. Representative
timings:

| Command | Kind | Scope / Int | Result | Time |
|---|---|---|---|---|
| `genuineVerifies` | run | 5 / 5 · 7 / 6 · 8 / 6 | SAT (intended) | 0.4 s · 0.4 s · 0.4 s |
| `genuineMultiVerifies` | run | 6 / 5 | SAT (intended) | 0.3 s |
| `genuineFullLength` (length-8 chain) | run | 8 / 6 | SAT (intended) | ~50 s |
| `Modification_Detected` | check | 5 / 5 · 7 / 6 | UNSAT — holds | 0.1 s · 0.3 s |
| `Insertion_Detected` | check | 5 / 5 · 7 / 6 | UNSAT — holds | 0.3 s · 2.9 s |
| `Interior_Deletion_Detected` | check | 5 / 5 · 7 / 6 | UNSAT — holds | 0.1 s · 0.7 s |
| `Reorder_Detected` | check | 5 / 5 · 7 / 6 | UNSAT — holds | 0.1 s · 0.6 s |
| `CrossChainSplice_Detected` | check | 6 / 5 · 7 / 6 | UNSAT — holds | 0.3 s · 1.4 s |
| `AppendAfterTerminal_Detected` | check | 5 / 5 · 7 / 6 | UNSAT — holds | 0.1 s · 0.6 s |
| `canModify … canAppendTerminal` | run ×6 | 5 / 5 (splice 6 / 5) **and 7 / 6** | SAT (non-vacuity) | ≤ 0.75 s each |
| `Soundness_VerifiedIsGenuinePrefix` | check | 5 / 5 · 7 / 6 · **8 / 6** | UNSAT — holds | 0.7 s · 27 s · 62 s |
| `Combined_OnlySurvivorIsTailTruncation` | check | 5 / 5 · 7 / 6 · **8 / 6** | UNSAT — holds | 0.7 s · 42 s · 61 s |
| `truncationSurvives` | run | 5 / 5 | SAT (documented floor) | 0.1 s |

### One model artifact found and fixed (not a spec gap)

During development, `AppendAfterTerminal_Detected` reported a spurious
counterexample: Alloy's `seq.add`/`insert` are **no-ops when the sequence is
already at the scope's maximum length**, so the "appended" log came back
byte-identical to the genuine terminal chain — which of course verifies. The
instance dump confirmed `Presented.log == GenuineChain.order` with the append
witness already being the chain's last element. This was a misrepresentation of
the *append operator by the model at the scope boundary*, not a §7 violation:
the master `Soundness` check held in the very same scope, which is impossible if
a genuinely-appended chain could verify. The fix constrains append/insert to
actually grow the log (`#Presented.log = #c.order + 1`); the six `can*`
non-vacuity runs were added to guard the dual hazard (a check passing because its
tamper scenario was unreachable). Per the project's formal-methods discipline,
the model was adjusted only because it misrepresented the operator — no property
was weakened to force a pass.

### Review-driven hardening

A high-effort code review of the model and tooling drove several additive
strengthenings, all re-verified (still 0 unexpected results):

- **The harness enforces non-vacuity.** Every command carries an `expect`
  annotation (`check … expect 0`, `run … expect 1`), and `alloy exec` fails on
  any mismatch — crucially, a non-vacuity `run` that regresses to UNSAT fails the
  suite instead of silently exiting green while its paired `*_Detected` check
  passes over an empty antecedent. Confirmed by a negative test (a deliberately
  mis-annotated command makes `exec` exit non-zero). This enforcement is native
  to Alloy's built-in executor, so it needs no bespoke driver.
- **Non-vacuity is now certified at every scope a check runs at**, including the
  `can*` runs at scope 7 and `genuineVerifies` at scopes 7 and 8, plus a
  `genuineFullLength` run proving a maximal-length chain is constructible at
  scope 8 — so the strongest results self-certify their antecedents are reachable.
- **`CrossChainSplice_Detected` gained a second, larger scope (7/6)** to match its
  siblings.
- **`§7.3.2 / §7.3.4` are documented as defense-in-depth, not independently
  load-bearing** against a non-key-holder (mutation-tested: deleting either
  conjunct still leaves the paired checks UNSAT) — see interpretation note 3.
- **`run.sh` now fetches the Alloy jar atomically and verifies a pinned SHA-256**
  (cross-checked against Maven's published `.sha1`/`.md5`), so an interrupted or
  substituted download fails loudly instead of poisoning the cache or executing
  unverified — matching the supply-chain caution in AGENTS.md.

### Interpretation notes (minor spec ambiguities surfaced)

Neither is a soundness break; both are recorded for a future spec revision.

1. **§7.3 step 1 "ordered by `chain.sequence`"** can be read as *sort-then-check*
   or *check-the-given-order*. The reference SDK verifiers (e.g.
   `sdk/go/receipt/chain.go`) check the given order; the model matches that, so
   `Reorder_Detected` is a genuine failure rather than a silent
   sort-normalization. The sort-first reading is **not machine-checked** here —
   under it a reordered store verifies-after-sort and `Reorder_Detected` would
   not hold as written; we *argue* (but do not prove in Alloy) the guarantee is
   unchanged because order is pinned by the signed `sequence` field. §7.3 should
   say which the verifier does.
2. **"First receipt has `sequence: 1`"** lives in §4.3.2 (schema) while §7.3
   step 4 checks only the null previous-hash; the Go verifier checks
   `sequence >= 1` at index 0. The model requires only what §7.3 states; the
   null-first check already forces the first verifying receipt to be a genuine
   genesis. Worth a cross-reference in §7.3.
3. **§7.3.2 / §7.3.4 are defense-in-depth against the out-of-scope Byzantine
   issuer, not independently load-bearing against a non-key-holder.** Mutation
   testing confirms this: deleting the receipt-after-terminal or chain_id
   conjunct from `verifies` still leaves `AppendAfterTerminal_Detected` and
   `CrossChainSplice_Detected` UNSAT, because a non-key-holder cannot forge a
   receipt that hash-links and sequences correctly yet carries a foreign
   chain_id or follows a terminal. Those §7.3 checks earn their keep only against
   a key-holder who *can* forge a matching hash link — the case named out of
   scope. They are modeled to encode §7.3 faithfully and to remain sound if the
   adversary is later widened. This is a coverage nuance, not a defect: the
   master Soundness theorem and hash/signature checks are what catch these
   tampers here.

## What is and is not guaranteed (honest statement)

This is **bounded model checking relative to the cryptographic assumptions.** It
proves the **chain protocol logic of §7 is sound** — the verification algorithm
detects the tampering it is meant to detect — **given** collision-resistant
hashing and unforgeable signatures, over all instances up to the checked scopes.

It does **not** prove: (1) the primitives themselves (SHA-256 / Ed25519 are
assumptions); (2) the **Byzantine-issuer** case (a key-holder can sign
false-but-valid receipts — out of scope by construction, ties to ADR-0019 P2/P3);
(3) detection of **tail truncation of an open chain** or **store-level deletion**
(the documented §7.3.1 floor and ADR-0019 O2 — mitigated only by out-of-band
witnesses / append-only storage, not by §7.3); (4) **behavioral/concurrent**
properties (future TLA⁺); or (5) **unbounded** correctness (no counterexample up
to scope 8 is strong evidence, not a proof for all lengths).

**Path to unbounded assurance (future work).** The master statement —
*verifies(l) ⟹ l is a prefix of a genuine chain* — is provable unboundedly by
induction on chain position: the null-first check anchors the genesis and hash
injectivity forces each `previous_receipt_hash` to name a unique predecessor.
Discharging this as a machine-checked **inductive invariant** (TLAPS, or an
Alloy inductive proof over an explicit successor relation) would lift the result
from "scope ≤ 8" to "any length." Noted, not claimed here.

## Consequences

- The tamper-evidence claim of §3.2 / §7 now has a machine-checked model that
  any reviewer can re-run (`formal/chain-invariants/run.sh`), independent of any
  single SDK.
- The precise **residual** of the property is now pinned in a checkable form:
  the *only* tamper that survives §7.3 is tail truncation (§7.3.1 floor),
  reproduced as `truncationSurvives`. This makes the "no tampered chain verifies"
  intuition honest rather than over-broad.
- Two spec-clarity nits (§7.3 step-1 ordering; the split of the "sequence starts
  at 1" rule) are documented for a future spec revision. They are **not** acted
  on here — modifying `spec/` requires explicit human approval per AGENTS.md.
- The model is additive and CI-agnostic (Java + one Maven-Central jar). Wiring it
  into a verification gate (ADR-0024) is possible future work but not required by
  this ADR.
- Follow-up: an inductive/unbounded proof, and a separate TLA⁺ model for the
  behavioral properties, are the natural next formal-methods steps. The
  cross-layer sequencing — CI gate now, TLA⁺ for the emission/recovery runtime at
  ≈ v1.5, Tamarin for the key-rotation protocol later — with the why-now /
  why-not-yet for each, is recorded in [`formal/README.md`](../../formal/README.md).

---

*Model, README, and runner: [`formal/chain-invariants/`](../../formal/chain-invariants/).
Related: spec §3.2, §7; ADR-0001 (Ed25519), ADR-0002 (RFC 8785), ADR-0008
(chain completeness / truncation floor), ADR-0019 (integrity gaps — P2/P3/P5/O2),
ADR-0024 (verification contract).*
