# ADR-0040: Signature Algorithm Agility and Post-Quantum Migration Path

## Status

Proposed (draft). The agility mechanism under *Decision* is proposed. Three decisions under *Open decisions* are deliberately left unresolved and are written as options only. This ADR can't be accepted until the owner has recorded an outcome for each.

Tracking: epic [#32](https://github.com/agent-receipts/obsigna/issues/32); this ADR is [#1210](https://github.com/agent-receipts/obsigna/issues/1210).

## Context

### Where the protocol stands

ADR-0001 chose Ed25519 as the sole signature algorithm and recorded algorithm agility as a **prerequisite for v1.0**. It also noted that receipts are long-lived signed records, so a migration path has to exist before a cryptographically relevant quantum computer (CRQC) does, not after. Today the algorithm is fixed in three places:

- **Spec §4.3.3:** `proof.type` MUST be `Ed25519Signature2020`.
- **Spec §7.3.7b:** `keyRotation.old_algorithm` and `new_algorithm` MUST name a supported algorithm, and the only supported algorithm is `"ed25519"`.
- **Verifiers:** `verifyCanonical` in `sdk/go/receipt/signing.go`, and the equivalents in `sdk/ts/src/receipt/signing.ts` and `sdk/py/src/obsigna/receipt/signing.py`, reject any other `proof.type`.

ADR-0015 already did the structural half of the work. `KeySource` is algorithm-agnostic, `Rotate()` returns distinct outgoing and incoming algorithm tags for cross-algorithm rotations, and the `key_rotated` event carries `old_algorithm` / `new_algorithm` inside `credentialSubject.keyRotation`, which is signed. What's missing is a wire-level rule for how a verifier picks an algorithm, how a chain moves to a new one, and what stops it moving back.

### Quantum exposure

- **Ed25519** is broken outright by Shor's algorithm. Anyone holding a CRQC can derive the private key from a public key and forge receipts under it.
- **SHA-256** (chain linkage, `parameters_hash`, `response_hash`, fingerprints) is not broken. Grover roughly halves preimage security to about 128 bits, and quantum collision search gives no practical advantage over classical. ADR-0001's "Hash function scope" paragraph is corrected separately ([#1208](https://github.com/agent-receipts/obsigna/issues/1208)). This ADR keeps SHA-256.
- **Disclosure envelopes** (ADR-0012, X25519 HPKE) are a confidentiality problem rather than a signature problem: harvest-now-decrypt-later. They're handled by a separate ciphersuite addition ([#1209](https://github.com/agent-receipts/obsigna/issues/1209)) and are out of scope here, except for decision 3 (when that work ships).

### Facts about the current wire format that constrain the design

1. **The signature does not cover `proof`.** Signing input and chain hash are both the RFC 8785 canonical form of the receipt *with `proof` removed* (spec §7.1, §7.3 step 2b, §7.8 step 3). As a result:
   - `proof.type` is **not signed**, so anyone can relabel it. A verifier can't treat `proof.type` alone as evidence of which algorithm the issuer intended. The algorithm has to be pinned by state that *is* signed, which here is the chain's rotation history.
   - Removing, adding, or replacing a proof component **does not break hash linkage**. The chain hash can't detect PQ-proof stripping. Only signature-verification rules can.
2. **`keyRotation` is signed** (it lives in `credentialSubject`), and it is signed by the *outgoing* key (`signed_with: "old"`). A rotation event's `new_algorithm` is therefore exactly as trustworthy as the outgoing key.
3. **Ed25519 batch verification** is cited in ADR-0001 as a reason for the choice. PQ signature schemes (ML-DSA, FIPS 204) have no equivalent.
4. **ML-DSA-65 sizes:** the public key is 1,952 bytes and the signature is 3,309 bytes (about 4.4 KB as multibase base64url), compared with 32 and 64 bytes for Ed25519.

## Decision (proposed)

### 1. Algorithm dispatch is an explicit allow-list

Verifiers select the signature-verification routine from `proof.type` by looking it up in an **explicit allow-list** compiled into the verifier. A `proof.type` that isn't on the list MUST fail verification. It is never skipped, ignored, or treated as "unverifiable but OK".

Each allow-listed `proof.type` maps to exactly one rotation algorithm tag (`ed25519` today; the hybrid tag is named once open decision 1 is resolved). Because `proof.type` is unsigned (constraint 1), the dispatch result MUST be cross-checked against the chain's **active algorithm** (§3). A mismatch MUST fail.

### 2. v0.x receipts are implicitly Ed25519

Every receipt that predates this ADR carries `proof.type: Ed25519Signature2020` and no other algorithm metadata. Such receipts, and any chain with no cross-algorithm rotation, verify exactly as they do today. The genesis active algorithm of every chain is `ed25519`.

### 3. A cross-algorithm `key_rotated` receipt is the migration point

A chain migrates by emitting a `key_rotated` receipt (ADR-0015, spec §7.3.7) where `old_algorithm: "ed25519"` and `new_algorithm` is the hybrid tag. The receipt is signed by the outgoing Ed25519 key and carries the incoming hybrid public key inline in `new_public_key`.

A verifier maintains, alongside the active key it already tracks under §7.3.7, an **active algorithm**. It is initialised to `ed25519` and changes only when a verified rotation receipt hands over to a `new_algorithm`. Each receipt's `proof.type` MUST map to the active algorithm.

### 4. Downgrade rule

Once a chain's active algorithm is a hybrid (post-quantum) algorithm:

- every later receipt that verifies under Ed25519 alone MUST fail; and
- a `key_rotated` receipt whose `old_algorithm` is a post-quantum algorithm and whose `new_algorithm` is not MUST fail. Migration is one-way.

Without this rule, an adversary who can forge Ed25519 could append Ed25519-only receipts after a genuine migration, or present a stripped receipt, and the result would still verify.

### 5. Formal model

Extend the Alloy model in `formal/chain-invariants/` (ADR-0039). Today it abstracts signing as a single non-enlargeable `IssuerSigned` set (EUF-CMA). The extension:

- adds a `Key` with an algorithm class (`Classical`, `Hybrid`) and models the active-key/active-algorithm traversal of §7.3.7;
- adds a **quantum adversary** who *can* enlarge the signed set for `Classical` keys and cannot for `Hybrid` keys;
- adds checks `Downgrade_Detected` (an Ed25519-only receipt after migration fails), `RotateBack_Detected`, and a stripping check whose exact form depends on open decision 1;
- adds an expected-SAT `run` showing that **a fork before the migration point survives without an external anchor** (see *Consequences*), recorded as a machine-checked floor in the same way `truncationSurvives` is today.

### 6. Spec and repo instruction changes (follow-on, each requiring human approval)

- Spec §4.3.3 (`proof.type` allow-list), §7.3.7 (active algorithm, downgrade rule), §7.8 step 3, and §10 item 2 ("single proof type for this version"). This needs a spec minor bump and a new JSON-LD context version (ADR-0021).
- `AGENTS.md` and `.github/instructions/general.instructions.md` both currently say "Ed25519 is the only supported signing algorithm". Both are amended to "Ed25519, plus the post-quantum hybrid defined in ADR-0040; do not introduce any other scheme" **when this ADR is accepted, not before**.

## Open decisions

These are recorded as options. **No decision is recorded here.** The owner picks one per item and amends this section before acceptance.

### Open decision 1: proof shape — composite proof vs W3C proof set

**Option A: composite proof.** One `proof` object with one hybrid `proof.type`. `proofValue` carries both signatures in a fixed-length encoding (Ed25519 ‖ ML-DSA-65), and both MUST verify.

- *Pros:* A receipt is valid or invalid atomically. Stripping the PQ half produces a malformed proof, not a valid legacy one. `proof` stays an object, so the schema shape is unchanged. Verifier logic is a single dispatch target. This is the shape the IETF LAMPS composite-signature work takes.
- *Cons:* It needs a project-defined `proof.type` name, which has weaker W3C VC ecosystem recognition than a proof set. Dropping Ed25519 later means another new type and another rotation.
- *Sub-question the owner must settle with this option:* should both components sign the **same canonical bytes** (the briefing's lean), or a **domain-separated message** (a fixed context prefix plus the canonical bytes, as the IETF composite drafts do for non-separability)?
  - With the same bytes, the Ed25519 half on its own is a valid `Ed25519Signature2020` over the receipt. An attacker can lift it out and present a legacy-shaped receipt. Only the chain-context downgrade rule (§4) catches this.
  - With domain separation, the Ed25519 half doesn't verify standalone, so stripping fails even in single-receipt verification. The cost is a signing input that differs from today's.

**Option B: W3C proof set.** `proof` becomes an array of independent proofs: an `Ed25519Signature2020` proof and a separate ML-DSA proof, each signing the canonical body. Policy: all proofs MUST verify.

- *Pros:* It aligns with W3C Data Integrity proof sets and the in-progress quantum-safe cryptosuites. Individual algorithms can be added or retired without a combined type. A legacy verifier sees at least one familiar proof.
- *Cons:* `proof` changes from an object to an array, which is a schema break and touches every SDK's parse and verify path. Removing the ML-DSA element leaves a well-formed receipt with a valid Ed25519 proof, and because `proof` is outside both the signature and the chain hash (constraint 1), nothing in the receipt itself detects this. Stripping is caught only by the chain-context downgrade rule (§4). It also introduces "which proofs must verify" policy surface (all, any, or a named subset) that has to be identical across three SDKs.

*Common to both:* single-receipt verification with no chain context (`VerifyRaw`, single-receipt mode in the web verifier) can't apply the downgrade rule. The caller has to supply the expected algorithm or key.

### Open decision 2: TypeScript runtime floor

`sdk/ts` currently declares `engines: node >=22.11.0`. ML-KEM and ML-DSA in `node:crypto` need Node 24.7+ with OpenSSL 3.5 (to be verified at implementation time). The browser `web-verifier` needs ML-DSA verification regardless; WebCrypto support has to be checked.

- **Option A: raise `engines` to `node >=24.7`.** This uses `node:crypto` natively with no new dependency, which keeps the supply-chain surface unchanged, consistent with the existing hand-rolled HPKE on `node:crypto` (#473). It gives native OpenSSL performance and a FIPS-capable path. The cost is dropping Node 22 LTS consumers of `@obsigna/sdk-ts` while 22 is still in maintenance. The web verifier would still need a separate answer (WASM or noble) if browsers lack ML-DSA.
- **Option B: add `@noble/post-quantum` as a fallback.** Keep `>=22.11`, use `node:crypto` when available, and fall back to noble otherwise. This keeps runtime support wide, and one library also covers the browser verifier. The cost is a new cryptographic dependency, which needs AGENTS.md justification: check maintenance, audit status of the PQ package specifically, and bus factor. It means two code paths to test for byte-identical output, and slower pure-JS ML-DSA.
- **Option C (variant of B): `@noble/post-quantum` only**, on every runtime. One code path everywhere, including the browser. It has the same dependency cost as B and gives up native performance and the FIPS-capable path.

### Open decision 3: Phase 1 (hybrid KEM disclosure, #1209) timing

- **Option A: before Post 3.** This stops harvest-now-decrypt-later exposure from accruing at the earliest point, and the demo could state that disclosures are post-quantum-confidential. The costs: a spec and context bump close to the demo, an earlier forced answer to open decision 2 (ML-KEM in TS), and building against draft-ietf-hpke-pq codepoints that may still move.
- **Option B: v1.** This batches the spec and context bump with Phase 2 (this ADR), and gives draft-ietf-hpke-pq more time to settle. The cost is that every disclosure sealed until v1 stays HNDL-exposed permanently. Re-sealing isn't possible because the daemon can't decrypt past envelopes (ADR-0012).

## Consequences

### Positive

- The protocol gets a defined, fail-closed path off Ed25519 that reuses ADR-0015 rotation instead of inventing a second mechanism.
- Chains that never opt in are unaffected. They verify byte-for-byte as today.
- Verifiers that predate this ADR reject hybrid receipts (unknown `proof.type`) instead of mis-verifying them, because they fail closed.

### Negative / explicitly accepted

- **Pre-migration history isn't retroactively protected.** Once a CRQC exists, an adversary can derive the Ed25519 key and forge an alternative history from any point *before* the genuine migration, including a forged `key_rotated` to an attacker-controlled hybrid key. The downgrade rule can't distinguish that fork from the genuine chain. The only defence is **external anchoring of the genuine rotation and checkpoints, made before the break, to a sink whose integrity does not itself rest on a classical signature** (S3 object-lock, a widely witnessed transparency log; #484). Ed25519-signed checkpoints in an operator-writable file don't qualify. This couples the migration's security to production anchor adapters (#484).
- Hybrid receipts are about 4.4 KB larger per signature and lose batch verification. Phase 3 (#1211) benchmarks the store growth and daemon throughput before the regulated profile ships.
- `did:key` resolution for hybrid keys depends on multicodec code points for ML-DSA, which have to be confirmed (ADR-0007).
- Three SDKs, the daemon, and the web verifier each gain a second verification path that cross-SDK vectors have to cover. Required vectors: Ed25519 → hybrid rotation, downgrade-after-migration rejection, rotate-back rejection, unknown-`proof.type` rejection, and stripped-PQ rejection (form depends on open decision 1).

## Alternatives considered

- **Replace Ed25519 with ML-DSA outright (no hybrid).** Rejected for now: it puts all trust on a young scheme and its implementations, with no classical fallback if a structural or implementation flaw turns up. Hybrid fails only if both halves fail.
- **Carry the algorithm in a new signed body field instead of relying on rotation state.** It isn't needed. `keyRotation.new_algorithm` is already signed, and the active algorithm follows from it deterministically. A second carrier would be redundant and could disagree with the first.
- **SLH-DSA (FIPS 205, hash-based).** It's more conservative in its assumptions, but signatures are roughly 8–50 KB, which is prohibitive for receipt chains. It could be reconsidered for low-volume artefacts such as checkpoints.

## Related ADRs

- ADR-0001: Ed25519 for receipt signing (makes agility a v1 prerequisite).
- ADR-0007: DID method strategy (`did:key` multicodec for hybrid keys).
- ADR-0012: payload disclosure (HPKE suite agility; Phase 1).
- ADR-0015: key rotation, `KeySource`, external anchoring (migration point; the anchor backstop).
- ADR-0021: spec and context versioning.
- ADR-0039: formal verification (model extension).
