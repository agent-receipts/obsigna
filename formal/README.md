# Formal models

Machine-checked formal models of Agent Receipts protocol properties. Each model
targets one *layer* of assurance. Today the receipt-chain tamper-evidence model
is the shipped piece; the rest of this document is the sequenced roadmap, with the
**why-now / why-not-yet** made explicit so the ordering is on record.

## What's here now

- [`chain-invariants/`](chain-invariants/) — an **Alloy 6** model of the §7.3
  receipt-chain **tamper-evidence** property: any receipt sequence that passes
  verification is a genuine issuer chain in issuer order, possibly tail-truncated
  (the documented §7.3.1 floor). Shipped; runnable via `chain-invariants/run.sh`.
  Decision, threat model, and honest statement of guarantee: **[ADR-0039](../docs/adr/0039-formal-verification-chain-invariants.md)**.

## The four layers of assurance

Different tools answer different questions. It helps to be explicit about which
layer a given claim lives in, because it's easy to conflate "the algorithm is
sound" with "the primitives are sound" or "the running system is correct."

| Layer | Question it answers | Tool family | obsigna status |
|---|---|---|---|
| 1 — Primitives | Is SHA-256 / Ed25519 *itself* sound? | computational crypto proofs (EasyCrypt), or trust | **assumed** (as everyone does) |
| 2 — Protocol | Given idealised crypto, does a *message exchange* resist an active network attacker, over unbounded sessions? | **Tamarin** / ProVerif (symbolic, Dolev-Yao) | not modelled — see below |
| 3 — Structure / logic | Given the crypto *assumptions*, is the *verification algorithm* sound? | **Alloy** (relational, bounded) | ✅ `chain-invariants/` |
| 4 — Behaviour / time | Given the algorithm, does the *concurrent, crash-prone system* that produces and stores chains preserve the invariants? | **TLA⁺** (temporal; TLC checker, TLAPS prover) | deferred — see below |

The `chain-invariants` model sits at **layer 3**: it proves the *verifier* is
sound *given* collision-resistant hashing and unforgeable signatures. It takes
layers 1–2 as axioms and layer 4 as out of scope. Tamarin and TLA⁺ are the tools
for layers 2 and 4 — the question for each is simply *whether obsigna has anything
in that layer worth proving.*

## Roadmap

### Now — CI-gate the Alloy model

The tamper-evidence model is a shipped, asserted property, so it belongs behind a
CI gate per **[ADR-0024](../docs/adr/0024-project-verification-contract.md)**
("every asserted property has a gate"). `run.sh` already exits non-zero on any
`expect` mismatch, so the gate is a thin wrapper. **This is the immediate
next step.**

### Next, sequenced ≈ v1.5 — TLA⁺ for the emission / recovery runtime

**Why.** The Alloy model verifies the *verifier* — given a stored chain,
tampering is caught. It says nothing about the *producer*: the concurrent,
crash-prone runtime that *builds* the chain. That's a state machine —

- the signing **daemon** owns the chain while multiple emitters feed it
  ([ADR-0010](../docs/adr/0010-daemon-process-separation.md)): concurrent appends,
  sequence assignment, no races producing gaps / duplicates / forks;
- the **WAL + at-least-once + crash-recovery** path
  ([ADR-0019 §O3](../docs/adr/0019-protocol-integrity-gaps-and-mitigations.md),
  [ADR-0020](../docs/adr/0020-emitter-abstraction-and-remote-receipt-delivery.md)):
  write-ahead log → deliver → crash anywhere → replay on restart;
- best-effort terminal on `SIGTERM` (§7.3.3).

The safety property to prove: *no accepted action ends up without a durable
receipt, and replay never produces a sequence gap or duplicate that breaks §7.3.*
Plus liveness: *every pending receipt is eventually durable, under fair
scheduling.* These are interleaving- and crash-timing properties — exactly what
Alloy cannot express and TLA⁺ is built for. **Alloy proves the check is sound;
TLA⁺ would prove the system that builds the checked artifact is also correct.**

**Why not yet.** The daemon / WAL / multi-emitter design is still settling;
modelling it now would formalise a moving target. It is worth the weight once that
path is real *and* correctness-under-concurrency/crash is a deployment concern —
which is precisely the **regulated-industries (v1.5)** milestone
([ROADMAP.md](../ROADMAP.md)), where ADR-0019 §O2/§O3/§P3 already sit and where "no
action goes unrecorded, recovery never corrupts the chain" become compliance
gates rather than good intentions. **First target:** the WAL / at-least-once +
crash-recovery machine (TLC over bounded emitters/crashes; TLAPS if unbounded is
later wanted).

### Later, narrow — Tamarin for the key-rotation protocol

**Why.** obsigna's core (§7.3) is a *data format + a local, offline verification
algorithm*, not a message-exchange protocol — so there is little for a
protocol-level active-attacker tool to prove that the structural model has not
already covered. The one genuine exception is **key rotation**
([§7.3.7](../spec/v0.5.0/spec.md), [ADR-0015](../docs/adr/0015-key-rotation-byok-anchoring.md)):
rotation *is* a mini-protocol — a receipt signed with the outgoing key binds the
incoming key. Tamarin could prove that across **unbounded** rotations an attacker
without the key cannot hijack a chain's future (no key-confusion, downgrade, or
cross-chain rotation-replay). It is the highest-consequence case: a broken
rotation hands an attacker the chain's *future*, worse than tampering with stored
history. (Delegation §7.6 and remote/daemon signing are secondary candidates if
they grow challenge–response exchanges.)

**Why not yet.** The surface is small (one protocol), and it is only worth the
distinct tool and mental model once rotation's adversarial resistance must be
*proven* rather than argued — e.g. a security audit demands it. Not urgent, and
narrower than the TLA⁺ work. Note Tamarin is *symbolic*: it idealises the
primitives (it does not prove Ed25519), so it discharges the layer-2 *protocol*
question, not layer 1.

### Out of scope everywhere — the primitives (layer 1)

SHA-256 collision resistance and Ed25519 unforgeability are **assumed**, not
proven, by every model here. Proving them is computational-crypto territory
(EasyCrypt or hand proofs) and is not on this roadmap; the honest boundary is
stated in each model's guarantee section.

## Adding a model

Each model gets its **own subdirectory**, its own README + run script, and its own
CI gate (ADR-0024); record the decision in an ADR. This directory is the index.
When the TLA⁺ / Tamarin work is firmed up (not just candidate), track its
milestone placement in [ROADMAP.md](../ROADMAP.md) like any other deliverable.
