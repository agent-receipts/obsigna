# ADR-0015: Key Rotation, BYOK Abstraction, and External Anchoring

## Status

Accepted (2026-05-12). Phase A implementation in progress (`KeySource` interface present in `daemon/internal/keysource/`, file-backed adapter partial, `Rotate()` not yet implemented; the rotation-event anchor sink that Phase A also requires is not yet implemented). Phase B (checkpoint anchoring for tail-truncation detection) and Phase C (HSM/KMS adapters) deferred — see *Implementation phasing* below.

## Context

The daemon (ADR-0010) holds a single Ed25519 signing key. Three gaps remain in the design:

1. **Rotating that key** without breaking historical chain verification.
2. **Where the key lives.** The daemon assumes a file on disk with `0600` permissions. That works for solo-dev but is not the answer enterprise operators will accept (HSM, cloud KMS, customer-managed key store).
3. **What happens when the daemon itself is compromised.** Chain verification catches mid-chain tampering but not tail truncation ([#171](https://github.com/agent-receipts/obsigna/issues/171)) or a forged rotation history. Without external anchoring of rotation events and periodic chain commitments, "the daemon protects the chain" is a circular argument — the same key that signs the receipts also signs the rotation history.

The threat model ([#155](https://github.com/agent-receipts/obsigna/issues/155)) names tail-truncation and post-compromise integrity as load-bearing concerns. Both depend on a sink the daemon does not control. Centralized credential-vault tools cannot match this property by their architecture — they hold customer credentials and SaaS access in the call path, so a compromise cascades. The daemon holds *one* signing key, no customer credentials, and (with anchoring) a verifiable history that survives daemon-key compromise.

This ADR scopes the design that closes those three gaps. Implementation is split into follow-on issues; this document is the Proposed-status ADR only.

## Decision

Two primitives, designed together because their interfaces interlock: a `KeySource` abstraction for where the signing key lives, and an external-anchor write contract for what survives daemon compromise.

### `KeySource` interface

The daemon reads its signing key from a configurable backend rather than a fixed filesystem path. Operations the interface MUST support:

- **`Sign(canonical bytes) → (signature bytes, algorithm tag, error)`** — the primitive. Some adapters (file-based) hold the private key in process memory; others (PKCS#11, cloud KMS) keep it remote and submit canonical bytes for signing without ever exposing the key to the daemon process. The algorithm tag returned here is **internal to the `KeySource` interface**: the daemon uses it to populate rotation events' `old_algorithm` / `new_algorithm` schema fields and to enforce algorithm-aware retry/halt logic, but it is *not* propagated into the receipt envelope. The current wire format hardcodes `proof.type: Ed25519Signature2020` per ADR-0001, and this ADR does not amend that. Wire-level algorithm carriage is the job of [#32](https://github.com/agent-receipts/obsigna/issues/32) (algorithm agility) when it is drafted.
- **`PublicKey() → (key material, algorithm tag, error)`** — for verifier consumption and for emitting fingerprints into rotation events.
- **`Rotate() → (old fingerprint, new fingerprint, new public key, old algorithm, new algorithm, transcript bytes, error)`** — produces a new signing key and returns: the two fingerprints (computed per the canonical-bytes rule below); the *raw incoming public key bytes* (so the caller can populate the rotation event's `new_public_key` field — the schema requires it inline, see below); both algorithm tags (so `old_algorithm` and `new_algorithm` can be set directly); and the canonical bytes of the rotation event itself, signed by the *outgoing* key before the new key takes over. Same-algorithm rotations return the same algorithm tag twice; cross-algorithm rotations (e.g. Ed25519 → ML-DSA) return distinct outgoing and incoming tags.
- **`Init(config) → error`** and **`Teardown() → error`** — adapter-specific bring-up and shutdown. Init MUST fail loudly at daemon start if the backend is unreachable; the daemon refuses to come up rather than silently fall through to a degraded mode.

Backends in scope (adapters land in follow-on issues, not this ADR):

- **File** (default) — current behaviour, `~/.agent-receipts/signing.pem` with `0600` (and `signing.pem.pub` `0644`), matching the existing mcp-proxy `init` convention. Solo-dev tier.
- **PKCS#11** — HSM, smartcard, or TPM via the standard interface.
- **Cloud KMS** — AWS KMS, GCP KMS, Azure Key Vault. Key never leaves the KMS; daemon submits canonical bytes for signing each receipt.

The interface is **algorithm-agnostic by design**. ADR-0001 (Ed25519) is the current commitment, but [#32](https://github.com/agent-receipts/obsigna/issues/32) (algorithm agility) requires that adding a post-quantum signing scheme later does not force a `KeySource` redesign. Operation signatures MUST NOT bake Ed25519-specific assumptions — `Sign` operates on canonical bytes and returns opaque signature bytes plus an algorithm tag.

**Error semantics.** Adapters surface backend-specific errors (KMS rate limits, HSM lock-out, network partitions) as structured `KeySource` errors with a `transient` flag. The daemon retries transient errors with bounded backoff and treats persistent errors as a halt condition — the daemon refuses to sign new receipts rather than emit unsigned ones.

### Rotation event schema

When the daemon rotates its signing key, a `key_rotated` synthetic receipt is appended to the local chain. Required fields (in addition to the daemon-supplied chain fields `seq`, `prev_hash`, `ts_recv` per [ADR-0010](./0010-daemon-process-separation.md)'s schema-split — these are the daemon-internal names; the verifier-facing AgentReceipt envelope wraps them as `credentialSubject.chain.sequence`, `previous_receipt_hash`, and the receipt's `issuanceDate` at emission):

| Field | Type | Description |
|---|---|---|
| `event_type` | string | Constant `"key_rotated"` |
| `new_public_key` | string | The *incoming* public key inline. Raw key bytes per the algorithm's canonical encoding (Ed25519: 32 bytes per RFC 8032 §5.1.5), multibase-encoded `u`-prefixed base64url (per ADR-0001 encoding choice). This field is what verifiers consume to validate subsequent receipts; it is bound to the outgoing key by the rotation event's signature (`signed_with: "old"`). |
| `old_key_fingerprint` | string | SHA-256 of the outgoing public key (raw bytes, see "Fingerprint canonical form" below), encoded as `sha256:<lowercase hex>` to match the repo's existing hash-bearing field convention (`previous_receipt_hash`, `tip_hash`, the SDK `hashReceipt` helpers, `spec/AGENTS.md`). Index field, not a substitute for the outgoing key material — the outgoing key is resolved via the receipt envelope's `proof.verificationMethod` (or, for the very first rotation, the genesis key registered out-of-band). |
| `new_key_fingerprint` | string | Same encoding (`sha256:<hex>`), of the incoming public key. Index field for fast chain traversal; redundant with `new_public_key` but cheap to carry and useful for offline lookup. |
| `old_algorithm` | string | Algorithm tag of the outgoing key (e.g. `"ed25519"`). Used to verify the rotation event's own signature, since `signed_with: "old"`. |
| `new_algorithm` | string | Algorithm tag of the incoming key (e.g. `"ed25519"`). Used to verify subsequent receipts. In same-algorithm rotations equal to `old_algorithm`; differs only across cross-algorithm migrations (e.g. Ed25519 → ML-DSA per [#32](https://github.com/agent-receipts/obsigna/issues/32)). |
| `signed_with` | string | Constant `"old"` — the rotation event itself is signed with the *outgoing* key, anchoring the transition to the key being retired |

**Wire-format placement is out of scope for this ADR.** The fields above describe the daemon's local representation of a `key_rotated` event — its on-chain content as the daemon writes it. They do *not* yet specify where those fields live in the verifier-facing AgentReceipt envelope, which currently closes `credentialSubject.action` / `chain` / `outcome` with `additionalProperties: false` and requires `action` / `outcome` / `principal`. Mapping `key_rotated` onto the envelope (whether via a new `credentialSubject.keyRotation` extension namespace, an `action.type = "key_rotated"` reuse, or a separate top-level field) is a schema-amendment decision that has to land alongside a spec change and corresponding SDK migrations. That mapping is intentionally deferred: the integrity properties of this ADR — outgoing-key signs over `new_public_key`, anchor write precedes local commit (next section), single chain across rotations — are independent of placement and survive whichever carrier shape is later chosen. A follow-up ADR (or a rev of this one once the schema work is sequenced) will pin down the envelope-side layout.

**Fingerprint canonical form.** Fingerprints are SHA-256 over the *raw public key bytes* as defined per algorithm (Ed25519: the 32-byte public key per [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) §5.1.5; future algorithms specify their canonical raw encoding when added) and rendered as `sha256:<lowercase hex>` — the same encoding the rest of the protocol uses for SHA-256 hash-bearing fields. SPKI/PEM wrappers and backend-specific handles (KMS key IDs, PKCS#11 object handles) MUST NOT be hashed — those representations vary across adapters and would produce different fingerprints for the same underlying key.

The next receipt after a `key_rotated` event is signed with the new key. Verifiers chain through rotations by:

1. Obtaining the outgoing public key from the receipt envelope's `proof.verificationMethod` (DID URL per ADR-0007, or equivalent) and verifying the `key_rotated` event's signature with that public key under `old_algorithm`. (`old_key_fingerprint` is checked against the outgoing key as a sanity index, not used for resolution.)
2. Reading the incoming public key directly from the rotation event's `new_public_key` field. The outgoing key has just signed this field, so by step 1's verification it is now bound to the previous chain segment — no separate resolution step is required.
3. Treating subsequent receipts as signed by the incoming public key under `new_algorithm`, until the next `key_rotated` event.

The rotation event is therefore a self-contained witness of the key transition: anyone with the chain plus the originating verification method can chain through arbitrary rotations without consulting an external key registry. Fingerprints exist for fast chain-traversal indexing and for cross-checking the inline public key bytes; they are not the resolution path. The genesis (first) signing key still needs to be registered out-of-band — there is no rotation event that introduces it — and that registration is what the very first receipt's `proof.verificationMethod` resolves against.

**`proof.verificationMethod` across rotations.** Receipts after a rotation continue to carry the issuer's stable DID URL in `proof.verificationMethod` — the same URL that pre-rotation receipts carry. A DID URL identifies the *issuer*, not a specific key; key rotation is internal to the issuer's key history. DID resolvers that support key history return the key valid at the receipt's `issuanceDate` (a standard DID resolution mode); resolvers that only return the current key still validate the most recent receipts and can fall back to the rotation-event witness chain for historical ones. Verifiers MUST NOT treat `proof.verificationMethod` as fingerprint-equivalent or as a per-key identifier — that interpretation would dissolve under rotation. The rotation-event witness chain (this ADR's contribution) and DID-resolved keys are complementary: the chain is sufficient on its own for a verifier with the chain and the genesis key; DID resolution is what makes the genesis-key registration step lookup-able rather than out-of-band per verifier.

Signing the rotation event with the outgoing key is the standard cryptographic-rotation idiom but it is also the failure mode if the outgoing key was already compromised at the moment of rotation: a compromised daemon could forge a rotation event that "retires" the legitimate key in favour of an attacker-controlled key. This is why **rotation events MUST be mirrored to the external anchor** (next section) — the anchor is the only construct that prevents an attacker from rewriting the rotation history alongside the receipt history.

### External anchor write contract

The daemon writes a subset of events to an operator-configured external sink. Two event types:

- **`rotation`** — rotation events are **anchor-first**. The daemon writes the rotation to the external sink *before* appending the `key_rotated` event to the local chain; the local append is downstream confirmation that the anchor write succeeded, not an independent commit. This makes anchor-write failure a clean abort: the rotation is deferred (block mode: until the sink recovers; queue mode: same outbox semantics as for checkpoints, but the local chain does not commit until acknowledged) rather than a torn state where the daemon has a locally committed rotation that no external witness records. The ordering rule applies regardless of failure mode — it is the structural property that makes the post-compromise integrity claim survive a sink outage. Standard receipts (non-rotation) keep their existing append-then-anchor ordering via `checkpoint`s, since checkpoint loss is a recoverable cadence problem rather than a permanent witness gap.
- **`checkpoint`** — at operator-configured intervals (default: hourly), the current `(issuer.id, seq, tip_hash, public_key_fingerprint)` tuple is written to the sink. `issuer.id` identifies the daemon emitting the checkpoint, so checkpoints from multiple daemons (multi-host or test environments) cannot be conflated. `tip_hash` is **exactly `hashReceipt(tip)`** — the same hash function the SDK helpers use to compute `previous_receipt_hash`: the receipt with `proof` removed, RFC 8785 canonicalized, with the ADR-0009 null-handling rules applied, then SHA-256, then rendered as `sha256:<lowercase hex>`. Reusing the existing definition (rather than defining a parallel "hash of the full receipt") is what makes the anchored value round-trip into existing `ExpectedFinalHash`-style verifier APIs without re-hashing. The checkpoint commits *to* the tip; a verifier comparing the local chain against the most recent anchored checkpoint detects tail truncation as a mismatch on `issuer.id`-scoped `seq` or `tip_hash`.

  Scope of the truncation guarantee: this mechanism detects tail truncation that occurred *before* the most recent anchored checkpoint. Receipts appended after the most recent checkpoint and then truncated remain invisible until the next checkpoint anchors — they live in the operator-controlled gap between checkpoint cadence (default: hourly) and detection. Operators who need a smaller invisible window shorten the cadence; the trade-off is sink write volume. Rotation events do not have this window because they are anchored individually as `rotation` events (see below), not via checkpoints.

Transport-agnostic. The sink interface is a single operation:

```
Write(event_type, payload bytes) → error
```

`payload bytes` MUST be the same RFC 8785 canonical-JSON serialization the receipt itself uses (per ADR-0002, ADR-0005, and ADR-0009), so any SDK or sink adapter produces byte-identical anchor payloads for the same logical event. This is the same canonicalization rule that makes cross-SDK signature verification work; relaxing it for anchors would dissolve verifier interop with the sink.

**A sink is not just any endpoint.** To qualify as an anchor (rather than mere transport), the sink MUST provide:

- **Append-only retention** — a compromised daemon writing later events cannot rewrite or delete earlier entries. Object-lock on S3, write-only logs, transparency-log Merkle trees, and managed SIEM ingestion all qualify; a plain webhook to an attacker-mutable endpoint does not.
- **Sink-controlled ordering or timestamps** — the daemon does not get to choose the entry's position or recorded time; the sink does. This is what makes "the daemon does not control the anchor" structurally true.

Adapters land in follow-on issues; representative targets that meet both properties: S3 PUT with object-lock, transparency log append, customer SIEM ingestion endpoint with sequence-stamping, syslog over TLS to an immutable log host. A bare webhook POST without these properties is a transport, not an anchor — operators who want the post-compromise integrity claim must choose a sink that delivers them.

**Failure semantics on sink unavailability — operator-configurable, not architectural.** Failure modes are per event type, because the consequence of an unanchored event is asymmetric: a missed checkpoint costs a periodic state snapshot, recoverable on the next cadence; a missed rotation event is a permanent gap in the key history that an attacker can later forge a replacement for. The two event types therefore have different mode menus.

**Rotation events** — modes (note the anchor-first ordering above: in both modes the local chain append happens *only* after the anchor write is acknowledged):

| Mode | Behaviour | When to choose |
|---|---|---|
| `block` | Daemon stops accepting new events while the sink is unreachable; the rotation does not commit locally until anchored. Per ADR-0010, emitters are non-blocking and drop events via the `EAGAIN` mechanism while the daemon refuses; those drops are recorded as `events_dropped` synthetic receipts in the local chain. | Maximum integrity in the sense of *no silent loss* — gaps appear in the chain rather than absent. Lowest availability. Compliance-driven deployments where any discoverability gap MUST be in-chain rather than untracked. |
| `queue` (default) | Rotation is staged in the local outbox (not yet on the chain) and the daemon continues signing under the *outgoing* key; outbox flushes and the rotation commits to the chain only when the sink acknowledges. Operator alerts on outbox depth. | Balanced default. Tolerates transient sink outages — the rotation is held until anchored, so the local chain never reflects an unanchored key handoff. Operators alert on outbox depth so prolonged queueing is visible. |

`drop` is **not available** for rotation events: an unanchored rotation creates a permanent witness gap that a later daemon compromise can exploit by forging a replacement rotation. The whole point of external anchoring is to make the rotation history something the daemon cannot rewrite alone — `drop` would dissolve that property at exactly the event type where it matters most. Operators whose sink is permanently down and who want to skip rotation anchoring should treat that deployment as opt-out of the post-compromise integrity guarantee, not as opt-in to a third mode.

**Checkpoint events** — modes:

| Mode | Behaviour | When to choose |
|---|---|---|
| `block` | Same blocking semantics as for rotation. | Rare in practice; checkpoints are periodic and a blocked daemon is usually too high a cost relative to a missed snapshot. |
| `queue` (default) | Same outbox semantics as for rotation. | Balanced default. Cadence is recoverable: a missed checkpoint anchors on the next interval after the sink returns. |
| `drop` | Daemon writes the event to the chain only, logs the sink failure, continues. | Available even when the sink is permanently down. Operator explicitly accepts that the truncation-detection window grows for the duration of the outage and any pre-outage gaps go uncovered. |

Same code path and same event format across both types; the difference is the mode menu.

### Periodic chain commitments — scope decision

**Decision: in-ADR.** The chain-checkpoint mechanism is described above as a peer of rotation events, not as a separate construct.

Rationale: tail truncation ([#171](https://github.com/agent-receipts/obsigna/issues/171)) and forged-tail-after-compromise both fall to the same primitive — periodic commitments to a sink the daemon does not control. Splitting into a sibling ADR would force operators to configure two sinks for one threat surface and would fragment the documented mitigation across two specs.

Implementation phasing keeps the integrity claim honest:

- **Phase A** (the ADR's first implementation): rotation events anchored. Tail integrity is named as a known gap until Phase B.
- **Phase B** (follow-on issue): checkpoint anchoring lands. Tail integrity claim becomes defensible. Threat model ([#155](https://github.com/agent-receipts/obsigna/issues/155)) updates concurrently to assert the conditional integrity guarantee.
- **Phase C** (follow-on issue, deferred): HSM (PKCS#11) and cloud-KMS adapters land as additional `KeySource` backends. Trigger conditions: (a) an enterprise deployment requires key custody outside the file system; (b) the file-backed adapter is mature enough that the interface is unlikely to change.

### Implementation status (as of 2026-05-12)

What has landed:

- `KeySource` interface skeleton at `daemon/internal/keysource/keysource.go` with the `Sign` / `PublicKey` / `Init` / `Teardown` operations defined per this ADR.
- File-backed adapter scaffolding (signing key load from `~/.agent-receipts/signing.pem`), used by the daemon for the existing single-key signing path.

What has **not** landed and is in scope for Phase A:

- `Rotate()` currently returns `ErrNotImplemented`. No rotation event schema, no `key_rotated` synthetic receipt emission path, no verifier-side rotation traversal.
- The external anchor write contract for rotation events. Until the anchor sink exists, **the post-compromise integrity guarantee is not honoured** and any rotation work that lands before it is partial.

Phase B (checkpoint anchoring) and Phase C (HSM/KMS adapters) are explicitly deferred and not on a schedule.

### Update (2026-06-10): rotation verification and offline rotation landed

The status above is superseded for the rotation mechanism itself:

- **Wire format + verifier traversal** landed across the schema, the spec (§4.3.2, §7.3.7), and all three SDKs. `credentialSubject.keyRotation` is modelled and the chain verifiers chain through a rotation: a `key_rotated` receipt is verified under the outgoing key, then the inline `new_public_key` takes over. The spec rotation-event vector is verified by all three SDKs (matching canonical hashes) and schema-validated in CI.
- **Offline rotation** landed as `agent-receipts-daemon --rotate` (`daemon.RotateKey`): it appends a `key_rotated` receipt signed by the outgoing key, archives the outgoing public key, and swaps in the new key pair. Restart picks up the new key.
- **Interface deviation from the *`KeySource` interface* section above.** `Rotate()` was **removed** from `KeySource` rather than implemented on it. A `key_rotated` receipt's signature covers the whole envelope (including chain fields the `KeySource` cannot know), and the file backend needs the public-key path and the receipt store — neither of which a `KeySource` holds. Rotation is therefore daemon-orchestrated (the chain owner). A live-rotation prepare/commit pair on the interface can be designed later against a concrete HSM/KMS backend rather than speculatively against the file backend.

- **External anchor write contract (anchor-first ordering)** landed. A `Sink` interface (`Write(eventType, payload)` + `Close`) lives at `daemon/internal/anchor`, with a dependency-free append-only file-log reference adapter. `--rotate --anchor-log <path>` writes the rotation event (the receipt's RFC 8785 canonical form) to the sink *before* any local change; a sink-write failure aborts the rotation with nothing committed, exactly the anchor-first abort this ADR specifies. This narrows the residual crash window to the gap between a successful anchor write and the local commit.

- **Rotation-aware `agent-receipts verify`** landed. Pointed at the published key, the verify CLI rediscovers a rotated chain's genesis key from the archived `.rotated-*` keys, traverses the rotation, and pins the result to the published key (a chain that does not hand its rotation lineage off to the published key reports `BROKEN`, so a planted archive cannot forge a `VALID`).

Still **not** landed: real anchor *adapters* that meet the append-only + sink-controlled-ordering bar (S3 object-lock, transparency log, SIEM ingest) — the file-log adapter is a reference that is only as tamper-evident as the storage beneath it. **Checkpoint anchoring (Phase B)** for tail-truncation detection is unstarted.

## Consequences

### Positive

- **Post-compromise integrity becomes a defensible claim.** Conditional on a configured external sink: without anchoring, post-compromise integrity remains aspirational; with anchoring, the chain's history survives daemon-key compromise. The conditional is now load-bearing and explicitly stated.
- **Algorithm agility falls out of the abstraction.** This ADR preserves ADR-0001's Ed25519 commitment unchanged — the `KeySource` interface treats Ed25519 as the only currently-supported algorithm — while leaving room for [#32](https://github.com/agent-receipts/obsigna/issues/32) (algorithm agility) to add post-quantum schemes later without forcing a `KeySource` redesign. The ADR that actually introduces algorithm agility (#32) will be the one to amend ADR-0001's "sole supported algorithm" claim; this ADR does not narrow ADR-0001 unilaterally.
- **Enterprise key custody is reachable without re-architecting.** HSM, cloud KMS, multi-recipient escrow all absorb into the adapter pattern. The daemon's interface to keys is the same regardless of where they live.
- **Tail truncation gets a structural answer.** [#171](https://github.com/agent-receipts/obsigna/issues/171) moves from "known gap, no roadmap" to "Phase B implementation."
- **Cross-cuts cleanly with ADR-0012.** ADR-0012's forensic encryption keypair is a separate construct from the signing key; lifecycles are independent. Neither key surface reuses the other, exactly the property ADR-0012 already commits to.

### Negative / explicitly accepted

- **Two-event-type sink surface (rotation + checkpoint).** Mitigated by serving both from the same `Write` interface and the same operator config. Documented as one sink with two event types, not as two systems.
- **Sink-unavailability mode is an operator choice with no universal default.** `queue` is the proposed default but `block` and `drop` deployments will exist. Documented prominently with deployment-tier guidance.
- **`queue` mode has a non-zero post-compromise integrity window.** Events staged in the local outbox between stage-time and sink-acknowledge are not yet anchored externally; a daemon compromised mid-window can rewrite the outbox before it flushes. Sink-acknowledged events are immune. The anchor-first ordering for rotations narrows the failure mode — the local chain itself does not commit a rotation until the anchor acknowledges, so there is no torn state where the chain reflects a rotation the anchor does not — but it does not eliminate the outbox-rewrite exposure during the unflushed window. Operators in tightly compliance-bound deployments should choose `block` instead, accepting the availability tradeoff.
- **Old public keys (or their resolution records) must be retained for verification of historical chain segments.** Retired *private* signing keys SHOULD be destroyed once rotation is anchored externally — unlike ADR-0012's forensic decryption keypair (which legitimately requires private-key retention to read historical encrypted payloads), signing verifiers only need the public key. Reducing private-key blast radius is a positive consequence of rotation, not a tax on it.
- **Rotation event itself is signed with the outgoing key.** Standard cryptographic-rotation idiom, but documented because operators rotating in response to suspected compromise need to understand they are authenticating the transition with the key they are already retiring. The mitigation is anchoring every rotation event to the external sink, so a compromised daemon cannot forge a backdated rotation that the anchor does not know about.
- **The `KeySource` interface cannot encode every backend's idiosyncrasies.** KMS rate limits, HSM lockouts, cloud throttling all surface as backend-specific errors with a structured `transient` flag; the daemon's retry/halt policy is uniform across adapters but the operator's alerting must be backend-aware.
- **Sink configuration becomes a load-bearing operational concern from Phase A onward.** Operators who skip configuring an external sink keep the chain integrity guarantees they had before this ADR — but lose the post-compromise integrity guarantee that motivates the design. The `KeySource` work and the anchor work are both required for the full claim; Phase A delivers both for rotation events, Phase B extends the same property to tail integrity via checkpoints.

## Alternatives considered

- **Drop BYOK; keep file-only key storage.** Solo-dev would still work, but the daemon would have nothing to say to operators with HSM or KMS requirements. Rejected: the daemon's value proposition extends to deployments where on-disk keys are non-starters.
- **Anchor every receipt to the external sink, not just rotations and checkpoints.** Strongest possible integrity, but the sink becomes a per-receipt latency component and a per-receipt outage point. Rejected as the wrong default; the sink interface does not preclude operators choosing this mode if their sink can handle the throughput.
- **Bake the sink interface into ADR-0010 (daemon process separation).** Considered when ADR-0010 was drafted but excluded as scope. Splitting external anchoring out lets ADR-0010 ship without the anchor adapter ecosystem and lets this ADR settle the integrity story independently.
- **Use the same `KeySource` adapter for the forensic keypair (ADR-0012).** Tempting because the abstraction shape is similar (Sign vs. Decrypt). Rejected: signing-key lifecycle (rotate freely, retain old keys for verification) and forensic-key lifecycle (do not rotate without re-encrypting historical receipts, retain old private keys forever) are different enough that one interface would force compromises in both.
- **Sibling ADR for periodic chain commitments.** Considered as a cleaner separation of concerns. Rejected: same sink, same operator config surface, same threat lineage. Two ADRs would fragment the mitigation story across two documents readers would need to assemble themselves.

## Related ADRs

- [ADR-0001 (Ed25519 signing)](./0001-ed25519-for-receipt-signing.md) — sole supported algorithm; preserved unchanged by this ADR. The `KeySource` interface is algorithm-agnostic so #32 (algorithm agility) can amend ADR-0001 later without a redesign here, but this ADR does not itself amend ADR-0001.
- [ADR-0007 (DID method strategy)](./0007-did-method-strategy.md) — public-key resolution path for the genesis (first) signing key and for each receipt's `proof.verificationMethod` (the outgoing key at any rotation). The incoming key at a rotation is carried inline in the rotation event, so DID resolution is not on the rotation chain-traversal path itself.
- [ADR-0010 (daemon process separation)](./0010-daemon-process-separation.md) — substrate this ADR sits on; the daemon is the only thing that holds a `KeySource`.
- [ADR-0012 (payload disclosure policy)](./0012-payload-disclosure-policy.md) — separate keypair (forensic encryption), separate lifecycle. Informs the "do not reuse keys across purposes" property recorded here.

## Amendments

### 2026-05-18: Amendment — rotation event envelope placement (`credentialSubject.keyRotation`)

**Status of this amendment:** *Accepted* (2026-05-19). Placement option (a) `credentialSubject.keyRotation` is the wire format for rotation events. The fields above (`event_type`, `new_public_key`, `old_key_fingerprint`, `new_key_fingerprint`, `old_algorithm`, `new_algorithm`, `signed_with`) and their semantics are unchanged by this amendment — only their envelope-side carriage is pinned. This amendment closes the gap the original *Rotation event schema* section flagged with "Wire-format placement is out of scope for this ADR." See ADR-0017 *Preconditions* (rotation-event canonical wire format) for the consumer that requires this pin.

**Decision.** Rotation events live at `credentialSubject.keyRotation` — a dedicated sub-object on `credentialSubject`, additive to today's `principal` / `action` / `outcome` / `chain` layout. The seven fields from *Rotation event schema* above map into `keyRotation` verbatim; no field is renamed.

**Why option (a) `credentialSubject.keyRotation`.** Today's `spec/schema/agent-receipt.schema.json` declares `additionalProperties: false` on the root and on most nested objects, but the `credentialSubject` definition itself omits that constraint. [ADR-0003 §"Subset compliance"](./0003-w3c-vc-envelope-format.md#subset-compliance) calls this out explicitly: extension fields within `credentialSubject` are permitted by the schema. Adding `keyRotation` as a sibling of `principal` / `action` / `outcome` / `chain` therefore lands as a strictly additive change — no `additionalProperties` flip, no breakage of the verifier-side allowlist for existing receipts. Tightening the schema with a normative `keyRotation` `$ref` lands as a follow-up once this placement is accepted, paired with the version bump under *Schema version implication* below.

**Why not option (b) `action.type = "key_rotated"`.** The `action` block today represents an external tool call: it carries `target.system`, `target.resource`, `parameters_hash`, `risk_level`, and `timestamp`; the broader receipt carries `outcome.response_hash` (added in 0.2.0). Reusing it as a polymorphic envelope for daemon-internal events erodes the type's clarity — `target` and `parameters_hash` have no meaning for a rotation, and verifiers downstream of the daemon would either have to ignore them or invent meanings. Daemon-internal events and tool calls are different vocabularies; collapsing them into one is the wrong abstraction.

**Why not option (c) a new top-level envelope field.** Top-level fields sit at the same layer as `@context`, `id`, `type`, `issuer`, `issuanceDate`, `credentialSubject`, `proof`. The schema's root **does** set `additionalProperties: false` (the root object's `additionalProperties` constraint), so adding a top-level `keyRotation` field forces every verifier in the wild to bump its allowed-keys set or fail closed. That is the biggest possible blast radius for what is conceptually a sub-namespace of the existing credential subject. Reserve top-level extension for cases where a sub-namespace genuinely cannot represent the semantics — rotation events are not that case.

**What lives in `keyRotation` (normative).**

| Field | Type | Description |
|---|---|---|
| `event_type` | string | Constant `"key_rotated"`. |
| `new_public_key` | string | Incoming public key inline, raw bytes per the algorithm's canonical encoding, multibase-`u`-prefixed base64url (same encoding ADR-0001 defines for `proof.proofValue`, applied here to raw public-key bytes). For Ed25519, the 32 raw bytes per RFC 8032 §5.1.5. |
| `old_key_fingerprint` | string | `sha256:<lowercase hex>` of the outgoing public key (raw bytes — *not* SPKI/PEM, *not* a backend handle). |
| `new_key_fingerprint` | string | `sha256:<lowercase hex>` of the incoming public key (same canonical-bytes rule). |
| `old_algorithm` | string | Algorithm tag of the outgoing key (e.g. `"ed25519"`). |
| `new_algorithm` | string | Algorithm tag of the incoming key. Equal to `old_algorithm` for same-algorithm rotations. |
| `signed_with` | string | Constant `"old"`. The receipt's `proof.proofValue` is computed with the outgoing key. |

`keyRotation` is **optional**. A receipt that is not a rotation event MUST NOT include it. A receipt that is a rotation event MUST include all seven fields.

The receipt's `action.type` SHOULD be `"agent.key.rotate"` (taxonomy entry to be registered alongside the schema-integration follow-up) so that downstream filters can locate rotation receipts without parsing `credentialSubject.keyRotation`. The presence of `keyRotation` is authoritative; `action.type` is the index hint.

**Verifier-side traversal (normative).** Restating ADR-0015 *Rotation event schema* steps 1–3 against this placement:

1. **Detect.** If `credentialSubject.keyRotation` is present, the receipt is a rotation event. Otherwise it is a normal receipt and rotation traversal does not apply.
2. **Verify the rotation event's own signature.** Obtain the *outgoing* public key: for the genesis rotation, resolve it from `proof.verificationMethod` via ADR-0007; for any subsequent rotation, it is the `keyRotation.new_public_key` carried forward from the previous rotation event (no external registry lookup). Compute `sha256` of its raw bytes and check it equals `keyRotation.old_key_fingerprint` (index check; non-equality is a hard error). Verify the receipt's signature using the outgoing key under `keyRotation.old_algorithm`. The signature covers the canonical bytes of the receipt with `proof` removed (per ADR-0003 deviation 2).
3. **Bind the incoming key.** Decode `keyRotation.new_public_key` (multibase `u` → raw bytes). Compute `sha256` of those raw bytes and check it equals `keyRotation.new_key_fingerprint` (consistency check; non-equality is a hard error).
4. **Continue chain traversal.** Treat any receipt with `chain.previous_receipt_hash` pointing at this receipt as signed by the incoming public key under `keyRotation.new_algorithm`, until the next rotation event.

The rotation event remains a self-contained witness of the key transition: step 2 verifies the outgoing key signs over the field (step 3) that step 4 will rely on. No external key registry is consulted on the rotation chain-traversal path.

**Backward compatibility.** Existing `0.1.0` and `0.2.0` receipts do not carry `credentialSubject.keyRotation`. Verifiers MUST treat absence of `keyRotation` as "no rotation in this receipt," not as malformed. This is the same `present-or-absent` discipline ADR-0008 establishes for `outcome.response_hash` and `chain.terminal`. No existing receipt's canonical bytes change as a result of this amendment — `keyRotation` is purely additive and is only emitted by issuers that opt in to rotation event emission.

**Canonical form and signature.** RFC 8785 governs unchanged (per ADR-0009). The receipt body (with `proof` removed) is canonicalised, signed by the outgoing key, and the signature is encoded as the receipt's `proof.proofValue` in multibase-`u` base64url (per ADR-0001). The same `hashReceipt` helper SDKs already use for `chain.previous_receipt_hash` and the anchor `checkpoint.tip_hash` (per [ADR-0008](./0008-response-hashing-and-chain-completeness.md) and ADR-0015's *External anchor write contract*) applies without modification.

A worked example with all values recomputable from RFC 8032 §7.1 test keys is at `spec/test-vectors/rotation-event/example.json`. Its canonical-bytes SHA-256 is `sha256:6983c9bd6fb24e844b90f7616315a914fdedc5fef8126e11d46149ba2f320457`.

**Schema version implication.** Adding `keyRotation` to the canonical receipt body is a wire-format change in the sense that issuers gain a new field to emit, even though no existing receipt's bytes are affected. Recommend a `0.2.1 → 0.3.0` schema-version bump under the same rationale ADR-0008 used for `0.1.0 → 0.2.0`: schema version as a security signal — verifiers that see `0.3.0` know the issuer is operating in an environment where rotation events are expressible, while `0.2.0` / `0.2.1` receipts retain their original meaning unchanged. The version-enum extension (`"0.3.0"` added to the `version` schema property) and the `keyRotation` `$ref` integration are deliberately **not** part of this PR; they land in a follow-up gated on this placement being accepted.

**Cross-references for the consumer track.** ADR-0017 §"Preconditions" names "rotation event canonical wire format" as a precondition for hub implementation; this amendment closes that precondition. The two sibling spec PRs — `did:key` resolution and the disclosure envelope — derisk the other two preconditions independently.
