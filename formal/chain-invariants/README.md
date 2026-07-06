# Formal chain tamper-evidence model (Alloy 6)

This directory contains a machine-checked formalization of the **tamper-evidence
property** of the Agent Receipt Protocol receipt chain — the guarantee in
spec §3.2 that "each receipt contains the hash of the previous receipt, creating
a tamper-evident log."

It formalizes the verification algorithm of **spec §7 (Receipt Chain
Verification)** and proves, by bounded model checking, that no party *without the
issuer's private key* can modify, insert, delete (interior), reorder, or
cross-chain-splice a stored chain and still have it pass §7.3 verification — the
sole residual being the *deliberately documented* tail-truncation floor
(§7.3.1 / ADR-0008).

- **Model:** [`chain-tamper-evidence.als`](./chain-tamper-evidence.als)
- **Decision record:** [`docs/adr/0039-formal-verification-chain-invariants.md`](../../docs/adr/0039-formal-verification-chain-invariants.md)
- **Tool:** Alloy 6.2.0, SAT4J (pure-Java) backend.

Behavioral / concurrent properties (parallel emission, crash-recovery,
at-least-once delivery) are **out of scope** for this model — they are
TLA⁺-shaped and left to a future model. This model covers the *structural,
adversarial-construction* property, which is Alloy's sweet spot.

---

## How to run

You need Java 17+ (tested on OpenJDK 21) and the Alloy 6 distribution jar.

```sh
cd formal/chain-invariants
./run.sh
```

`run.sh` will, on first use, download **Alloy 6.2.0** from Maven Central
(`org.alloytools:org.alloytools.alloy.dist:6.2.0`) and verify it against a pinned
SHA-256, then run every `check` and `run` in the model through Alloy's own
built-in headless executor:

```sh
java -jar alloy.jar exec --command '*' --solver sat4j chain-tamper-evidence.als
```

`exec -c '*'` runs all commands with the pure-Java SAT4J solver (no native
dependencies), enforces each command's `expect` annotation, prints a
one-line-per-command summary, and **exits non-zero if any result contradicts its
`expect`**. This is Alloy's supported command-line entry point — there is nothing
custom to compile or maintain. (Full solutions and a machine-readable
`receipt.json` are written under `./out/`, which is git-ignored.)

- Already have the jar? `ALLOY_JAR=/path/to/alloy.jar ./run.sh` (skips the
  fetch + checksum; the pinned SHA-256 is only enforced on jars this script
  downloads or previously cached).
- Prefer the GUI? Open `chain-tamper-evidence.als` in the Alloy 6 Analyzer and
  use **Execute → Execute All**. Every command is self-contained.

**Every command carries an `expect` annotation** — `check … expect 0` (expect
UNSAT / no counterexample) and `run … expect 1` (expect SAT / scenario
reachable) — and `exec` **fails on any result that contradicts it**, in either
direction:

| Command | Annotated | Pass condition | A failing result means |
|---|---|---|---|
| `check` (an `assert`) | `expect 0` | **UNSAT** — no counterexample in scope → property holds | **SAT**: a counterexample → property violated |
| `run` (a `pred`) | `expect 1` | **SAT** — scenario reachable | **UNSAT**: a sanity/non-vacuity scenario became unreachable → a paired check may now pass **vacuously** |

Enforcing the `expect` on **runs** is what closes the vacuity hole: if a
non-vacuity `can*` run ever regressed to UNSAT, `exec` flags it instead of
silently exiting green while its paired `*_Detected` check passes over an empty
antecedent. `alloy exec` exits **0** when every command matched its `expect` and
**non-zero** if any did not (or on a solver/parse error).

---

## What each command means

### Sanity (must be SAT — the model is not vacuous)

| Command | Claim |
|---|---|
| `genuineVerifies` | An untampered genuine chain **passes** §7.3 verification. |
| `genuineMultiVerifies` | A ≥3-receipt genuine chain passes (real hash-linkage exercised). |
| `canModify`, `canInsert`, `canDeleteInterior`, `canReorder`, `canCrossChainSplice`, `canAppendTerminal` | Each adversary operator is actually **reachable** at the checked scope, so the matching `*_Detected` check is a *real* detection, not a vacuous pass over an unsatisfiable antecedent. |

### Tamper-detection (must be UNSAT — the property holds)

Each maps one adversary operator over a genuine chain to the claim "the tampered
chain fails §7.3 verification":

| Check | §7 basis | What it proves |
|---|---|---|
| `Modification_Detected` | §7.3 step 2a (+2b/3) | Altering **any** signed field of any receipt breaks verification (the altered body is not issuer-signed). |
| `Insertion_Detected` | §7.3 steps 2a / 2b / 3 / §7.3.4 | Splicing in a receipt the issuer did not sign-and-chain breaks verification. |
| `Interior_Deletion_Detected` | §7.3.5 sequence contiguity (+2b) | Removing the head or any interior receipt breaks verification. |
| `Reorder_Detected` | §7.3 step 3 (+2b) | Presenting the same receipts in any other order breaks verification. |
| `CrossChainSplice_Detected` | §7.3.4 chain_id binding | Inserting a validly-signed receipt from a *different* chain of the same issuer is rejected. |
| `AppendAfterTerminal_Detected` | §7.3.2 receipt-after-terminal | Appending any receipt after a `chain.terminal: true` receipt is rejected unconditionally. |

### Master theorems (must be UNSAT)

| Check | What it proves |
|---|---|
| `Soundness_VerifiedIsGenuinePrefix` | **Any** sequence that passes §7.3 verification is a genuine issuer chain, in issuer order, possibly with a truncated tail. This single theorem subsumes all six operators above. |
| `Combined_OnlySurvivorIsTailTruncation` | If a verifying log is not *exactly* a genuine chain, it is a *proper prefix* of one — i.e. pure tail truncation and nothing else. The precise, honest form of "no tampered chain verifies." |

### The truncation floor (must be SAT — a documented limitation, reproduced)

| Command | What it demonstrates |
|---|---|
| `truncationSurvives` | Dropping the final receipt of a genuine, **non-terminal** chain still verifies. This is **not a bug**: it is the deliberate floor of §7.3.1 / ADR-0008 — an in-chain field cannot commit to successors the issuer had not yet produced. We surface it as a machine-checked fact rather than hide it. |

---

## Results (as committed)

Run with Alloy 6.2.0 / SAT4J. `check` results are UNSAT (**property holds in
scope**) unless noted; `run` results are SAT (**scenario reachable**) unless
noted. Scopes are stated as Alloy scope / integer bitwidth.

| Command | Scope(s) | Result |
|---|---|---|
| `genuineVerifies` | 5/5, 7/6, 8/6 | SAT (as intended) |
| `genuineMultiVerifies` | 6/5 | SAT (as intended) |
| `genuineFullLength` (length-8 chain constructible) | 8/6 | SAT (as intended) |
| `Modification_Detected` | 5/5, 7/6 | UNSAT — holds |
| `Insertion_Detected` | 5/5, 7/6 | UNSAT — holds |
| `Interior_Deletion_Detected` | 5/5, 7/6 | UNSAT — holds |
| `Reorder_Detected` | 5/5, 7/6 | UNSAT — holds |
| `CrossChainSplice_Detected` | 6/5, 7/6 | UNSAT — holds |
| `AppendAfterTerminal_Detected` | 5/5, 7/6 | UNSAT — holds |
| `can*` (six non-vacuity runs) | 5/5 (splice 6/5) **and 7/6** | SAT (as intended) |
| `Soundness_VerifiedIsGenuinePrefix` | 5/5, 7/6, **8/6** | UNSAT — holds |
| `Combined_OnlySurvivorIsTailTruncation` | 5/5, 7/6, **8/6** | UNSAT — holds |
| `truncationSurvives` | 5/5 | SAT (documented floor, as intended) |

Every command matched its `expect` (**0 unexpected results, 0 errors**, runner
exit 0). No `check` produced a counterexample at any scope; every non-vacuity
`run` was reachable at every scope its paired check runs at. The scope-8
master-theorem checks are the most expensive (~1 minute each on SAT4J), and
`genuineFullLength` at scope 8 takes ~50 s (it searches for a maximal-length
chain); the rest complete in seconds. See ADR-0039 for the full results with
timings.

> **One model artifact was found and fixed during development, not a spec gap.**
> Alloy's `seq.add`/`insert` are *no-ops when a sequence is already at the
> scope's maximum length*. An early `AppendAfterTerminal` check reported a
> spurious counterexample in which the "appended" log was byte-identical to the
> genuine terminal chain (the append silently did nothing), which of course
> verifies. The fix constrains the append/insert operators to actually grow the
> log (`#Presented.log = #c.order + 1`). This corrects the *model's*
> representation of the operator; it does not weaken any property. The
> non-vacuity `can*` runs guard against the dual hazard (a check passing because
> its tamper scenario was unreachable).

---

## What is and is NOT proven

**This is bounded model checking, relative to the cryptographic assumptions.**
It proves that the **chain protocol logic of §7 is sound** — i.e. the
verification algorithm actually detects the tampering it is meant to detect —
**given** that:

- the hash is **collision-resistant** (modeled as an injective
  `Receipt → Hash`), and
- signatures are **unforgeable** by non-key-holders (EUF-CMA; modeled as: the
  adversary cannot add any receipt to the issuer-signed set),

over **all instances up to the checked scopes** (up to 8 receipts / 8 hashes /
8 chains, integer bitwidth 6, for the master theorems).

It does **NOT** prove:

1. **The primitives themselves.** SHA-256 collision resistance and Ed25519
   unforgeability are *assumptions*, not results. If SHA-256 collisions become
   practical, or the Ed25519 private key leaks, the guarantee does not hold —
   and that is out of this model's scope by construction. Key lifecycle is
   spec §9.6 / §10.8 / ADR-0001 territory.
2. **The Byzantine-issuer case.** A party who *holds* the issuer's private key
   can sign false-but-valid receipts, backdate `issuanceDate` (§7 has no trusted
   timestamp binding by default — ADR-0019 P3), or fabricate an entire chain
   under a fresh keypair (ADR-0019 P2, "unauthenticated chain origin", deferred
   to v2). This model proves integrity **against non-key-holders**, not the
   **honesty** of the key-holder. See ADR-0039 "Threat model boundary".
3. **Tail truncation of an open chain** (the `truncationSurvives` floor) and
   **store-level completeness** (deleting whole sessions). §7.3.1 documents that
   these are undetectable by the in-chain algorithm alone; the mitigations
   (`ExpectedLength` / `ExpectedFinalHash` witnesses, `RequireTerminal`,
   append-only storage, chain-head anchoring) live *outside* the §7.3 core and
   are deliberately not modeled here.
4. **Behavioral / concurrent properties** — parallel emission, crash-recovery,
   at-least-once delivery, key-rotation *traversal* dynamics (§7.3.7). These are
   temporal and belong in a separate TLA⁺ model.
5. **Unbounded correctness.** A `check` that finds no counterexample up to scope
   *N* is strong evidence but not a proof for *all N*. Alloy's small-scope
   hypothesis argues that structural bugs of this kind surface at small scope;
   the master theorem's proof sketch (injectivity of the hash forces a verifying
   log to be a genuine prefix) suggests it holds unboundedly, but that is not
   discharged here.

### §7.3.2 and §7.3.4 are defense-in-depth, not independently load-bearing here

The `AppendAfterTerminal_Detected` (§7.3.2) and `CrossChainSplice_Detected`
(§7.3.4) checks *hold*, but within this threat model they are **not
independently necessary**: mutation testing (deleting either conjunct from
`verifies`) leaves both checks UNSAT, because a party **without the issuer key**
cannot produce a receipt that hash-links and sequences correctly yet carries a
foreign `chain_id` or sits past a terminal — that requires re-signing. Those two
automatic checks exist to stop a **Byzantine issuer** who *can* forge a matching
hash link (e.g. splice two of its own chains, or reopen a terminal chain) — the
case this model names as out of scope. They are modeled to encode §7.3
faithfully and to stay sound if a future model widens the adversary; the master
Soundness theorem, hash-linkage, and signature checks are what actually catch
these tampers against a non-key-holder.

### Path to unbounded assurance (future work)

The master soundness statement — *verifies(l) ⟹ l is a prefix of a genuine
chain* — is provable unboundedly by an **inductive argument** on chain position:
the null-first check anchors the genesis, and injectivity of the hash forces
each `previous_receipt_hash` to name a unique predecessor, so a verifying log is
pinned to the genuine order by induction. Discharging that as a machine-checked
**inductive invariant** (e.g. in **TLAPS**, or as an Alloy inductive proof over
an explicit successor relation) would lift the result from "no counterexample up
to scope 8" to "holds for chains of any length." This is noted as future work in
ADR-0039; it is **not** claimed here.

---

## Interpretation notes (spec ambiguities surfaced)

Modeling §7 precisely surfaced two points where the prose admits more than one
reading. Neither is a soundness break; both are recorded here and in ADR-0039 so
a future spec revision can tighten the language.

1. **§7.3 step 1 — "retrieve all receipts … ordered by `chain.sequence`."** This
   can be read as (a) the verifier *sorts* the input by sequence before checking,
   or (b) the verifier checks the *given* order and relies on step 3 to reject a
   non-sequence order. The reference SDK verifiers implement (b) — e.g.
   `sdk/go/receipt/chain.go` iterates the receipts *as given* and fails the
   step-3 increment check on a scrambled order. This model uses (b), which is
   why `Reorder_Detected` is a genuine failure rather than a silent
   normalization. The sort-first reading (a) is **not machine-checked here** —
   under it a reordered store would verify-after-sort instead of being rejected,
   so `Reorder_Detected` would not hold as stated. We *argue* (but do not prove
   in Alloy) that the security guarantee is unchanged under (a) because the
   logical order is pinned by the signed `sequence` field either way; a future
   revision could add a `verifiesSorted` variant to discharge that argument
   mechanically. Recommend §7.3 state explicitly that the verifier checks the
   presented order.

2. **First-receipt sequence value.** §7.3 step 4 checks only that
   `previous_receipt_hash` is null on the first receipt; the "sequence starts at
   1" requirement lives in §4.3.2 (schema), and the Go verifier checks
   `sequence >= 1` at index 0 (not `== 1`). The model does not require the first
   presented receipt to have `seqNum == 1`, faithfully to §7.3; the null-prevHash
   check already forces the first presented receipt to be a genuine genesis,
   which by well-formedness has `seqNum == 1`. No behavioral difference results,
   but the split of the "starts at 1" rule across §4.3.2 and §7.3 is worth a
   cross-reference.
