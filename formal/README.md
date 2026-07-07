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

### Now — CI-gated

The tamper-evidence model is a shipped, asserted property, so it sits behind a CI
gate per **[ADR-0024](../docs/adr/0024-project-verification-contract.md)** ("every
asserted property has a gate"):
[`.github/workflows/formal.yml`](../.github/workflows/formal.yml) runs `run.sh` on
every change under `formal/**` and fails the build on any `expect` mismatch (a
counterexample, or a non-vacuity run gone UNSAT).

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

### Key-trust — Tamarin (deferred by *readiness*, not by consequence)

> The order in this roadmap is a **readiness** order, not a criticality order.
> Read "later" as "not yet buildable / not yet ours to build," not as
> "unimportant" — this section is, by consequence, arguably the most load-bearing
> unproven area in the system.

**What the target actually is.** Not the chain — that is structural and Alloy
owns it. The target is the **key-trust chain the whole tamper-evidence result
rests on.** The Alloy model proves integrity *relative to* "an issuer-signed set
the adversary cannot enlarge" — i.e. it assumes the verifier already holds the
**correct issuer key.** The realistic attack on a signed-audit log is almost never
"forge the hash chain" (proven hard here); it is "get the verifier to accept the
*wrong* key" — a rotated-out key, a key valid for a different chain, or a key
injected at distribution. That assumption is the ballgame, and it has three
distinct parts with different readiness:

- **Genesis key trust** — delegated to DID resolution (§7.8 step 2), which this
  version deliberately does **not** specify (§9.6, `UNRESOLVABLE_DID`;
  [ADR-0007](../docs/adr/0007-did-method-strategy.md)). With a self-certifying
  method (`did:key`) there is no protocol to verify; with a registry or `did:web`
  the trust is an *external* PKI concern. This part may simply be **not ours.**
- **Rotation traversal** ([§7.3.7](../spec/v0.5.0/spec.md),
  [ADR-0015](../docs/adr/0015-key-rotation-byok-anchoring.md)) — a genuine
  in-project cryptographic protocol: a receipt signed with the outgoing key binds
  the incoming key, and a verifier chains through unbounded rotations from the
  genesis key alone. **This design is settled and shipped.** It is Tamarin's exact
  home turf: can any active attacker without the outgoing key hijack the active
  key (key-confusion, downgrade, cross-chain rotation-replay)?
- **Origin authentication** — the P2 gap
  ([ADR-0019 §P2](../docs/adr/0019-protocol-integrity-gaps-and-mitigations.md)):
  an attacker who can write the store fabricates a genesis under a fresh key and
  the chain verifies internally. The fix (trust registry / witnessed
  `agent_start`) is **deferred to v2 and undesigned.**

**Why defer — and the honest reasons, kept separate.** The earlier framing ("the
core isn't a message-exchange protocol") is a *non-sequitur* here: it argues
against pointing Tamarin at the chain, which nobody proposes — the target is the
key-trust protocol, which the same breath concedes *is* a protocol. The real
reasons split by part:

- Rotation traversal is settled, so its defer is purely **priority** — small,
  shipped, no forcing function demanding a proof yet.
- Origin authentication is defer-by-**readiness**: verifying a v2 sketch would
  model a moving target and ship a spec obsolete on merge — the "model that lies"
  failure mode. This is a *readiness* reason, not a consequence one, and the two
  resolve on different timelines.
- Genesis trust may be **not ours** at all. The fork that decides the real scope —
  *is issuer-key trust bespoke to agent-receipts, or delegated to a DID method /
  external PKI?* — is itself unsettled (§9.6, ADR-0007) and should be stated
  before any Tamarin effort, since it determines whether there is an in-project
  protocol to verify.

**If the aim is to learn, not to close a gap.** As a *pedagogical* target — does
Tamarin earn its place? — the rotation/key-trust protocol is near-ideal: small,
self-owned, genuinely message-exchange-shaped, consequential. The one discipline:
such a model stays clearly **exploratory and out of CI**. The Alloy model earned
its gate; an exploratory protocol model masquerading as an assurance artifact is
the one way to do real harm here. Tamarin is *symbolic*: it idealises the
primitives (it does not prove Ed25519); it discharges the layer-2 *protocol*
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
