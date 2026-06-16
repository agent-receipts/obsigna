# ADR-0012: Payload Disclosure Policy (`parameterDisclosure`)

## Status

Accepted (2026-05-12), amended 2026-05-18 (see *Amendments*). **Phase A is complete as of 2026-05-21**: the HPKE envelope is implemented end-to-end across the Go, TypeScript, and Python SDKs, pinned in the spec at v0.3.0, and exercised by cross-SDK byte-identical test vectors. See *Implementation status* and *Phase A landed* below.

## Context

Receipts today commit to action parameters via `parameters_hash` only. That is the right default — it is privacy-preserving, tamper-evident, and small. But the most common forensic question after an incident is "what did the agent actually send?" and a hash cannot answer it.

The OpenClaw plugin already documents an opt-in `parameterPreview` config that selectively discloses parameters by risk class. The TypeScript SDK exposes the field shape as `parameters_preview` on `Action` ([sdk/ts/src/receipt/types.ts](../../sdk/ts/src/receipt/types.ts)), with a CHANGELOG warning that the value is permanent and signed and that callers MUST NOT populate `parameters_preview` from raw tool arguments. Python and Go SDKs do not have the field. The MCP proxy has no equivalent knob, though it does have opt-in AES-256-GCM encryption of redacted audit fields via `BEACON_ENCRYPTION_KEY` ([mcp-proxy/cmd/mcp-proxy/main.go](../../mcp-proxy/cmd/mcp-proxy/main.go)) — prior art for non-signing key handling.

The result is that the forensic question gets a different answer depending on which channel produced the receipt. We want a uniform, operator-controlled, privacy-preserving-by-default position across every emitter, documented as a deliberate design decision rather than buried in installation config.

### Forces in tension

- **Forensic completeness.** Hash-only receipts can prove tampering but cannot answer "what command ran?" without out-of-band logs.
- **Privacy / least-disclosure.** Payloads routinely contain API keys, PII, file contents, and prompt text. Storing plaintext changes the threat model and pulls the receipts store into GDPR / data-handling scope.
- **Tamper-evidence.** Anything visible to forensics must also be tamper-evident, or it is worse than no record at all.

### Architectural facts that further constrain the solution

- **Storage will be pluggable.** SQLite is the only adapter today, but the contract must work for Postgres, S3-backed object stores, append-only files, and OTel exporters. Encryption cannot be a property of any single adapter.
- **SIEM / telemetry fan-out is on the roadmap.** Those sinks must receive enough for trend analysis (counts, rates, action types, risk levels, hashes, timing, decisions) but never raw payloads. The disclosure boundary needs to be expressible as a single key, not as N per-adapter redaction configs.
- **The daemon (ADR-0010) owns fan-out** when present. The agent process must not own its own audit trail; the same logic must extend to disclosures.

The existing TS-SDK design — `parameters_preview` as a *plaintext signed field* — conflicts with the SIEM / telemetry fan-out and daemon-owned fan-out constraints. Because the chain commits to plaintext, any attempt to selectively encrypt, redact, or omit that field inside the signed receipt body for some downstream sinks would change the signed bytes and break signature verification. Whole-store encryption at rest for a database or file is still possible, but it does not solve the per-sink disclosure problem.

## Decision

Operator-controlled, privacy-preserving by default, with **asymmetric encryption of the disclosure field inside the signed receipt body**. The emitter holds only the public key; the private key lives with the forensic responder / escrow holder. The chain commits to ciphertext.

### Naming

- Config knob: **`parameterDisclosure`** (renamed from `parameterPreview`).
- Receipt field: **`parameters_disclosure`** (renamed from the existing TS `parameters_preview`).

The previous names misdescribe ciphertext. "Preview" implies a glimpse; "raw" / "plain" imply plaintext. "Disclosure" is honest: the field discloses on demand, to the holder of the right key, and is opaque otherwise.

### Operator control

- The default for every channel is **hash-only**. Identical commitment via `parameters_hash` (already standard).
- Disclosure is opt-in via `parameterDisclosure` with the existing OpenClaw value space: `false | true | "high" | string[]`. (`"high"` defers to the taxonomy's risk classification; the array form is an explicit allowlist of action types.)
- The setting **MUST** live in operator config (env, on-disk config, or daemon config under ADR-0010), never in agent-supplied input. Reject any in-receipt or per-call agent override.

### Asymmetric encryption

- Emitter holds **only the forensic public key**.
- Private key lives with the forensic responder / escrow holder, separate from the encryptor.
- Encryptor genuinely cannot decrypt its own past disclosures — same trust property as ADR-0010 (the agent must not own its own audit trail).
- Verifiers verify the chain without holding any encryption key. Forensic responders, holding the private key, recover plaintext on demand.
- **Hard rule:** the Ed25519 signing key is never reused as an encryption key. Different purposes, different lifecycles. X25519 is the natural sibling for an X25519-class hybrid construction.

### Forward-compatible envelope shape

The disclosure field carries a structured envelope:

```jsonc
"parameters_disclosure": {
  "v": 1,                               // envelope schema version
  "alg": "...",                         // e.g. "hpke-x25519-aes256gcm-sha256"
  "recipients": [                       // length 1 in MVP; multi-recipient later
    { "kid": "...", "encap": "..." }    // alg-specific (e.g. HPKE encapsulated key)
  ],
  "nonce": "...",
  "ct": "..."                           // ciphertext over the parameters JSON
}
```

Single-recipient v1 ships with `recipients` length 1. Multi-recipient (HPKE-style envelope to N forensic public keys) lands later **without a format change**. Older verifiers reading newer receipts ignore unknown `alg` values gracefully and still verify the chain — they just cannot decrypt.

The exact `alg` string, AEAD primitive, and `kid` registry mechanism are deferred to a follow-up implementation ADR. What this ADR commits to is the envelope's *shape* and its forward-compatibility properties, because once a receipt is signed, its canonical-JSON bytes are permanent.

Cross-SDK serialisation of this envelope is load-bearing — all three SDKs must produce byte-identical canonical JSON (per ADR-0009).

### Modes

The same architecture serves three personas. No migration is required between them; only key custody changes.

| | Solo dev | Small team | Enterprise |
|---|---|---|---|
| **Public key (encrypt)** | Auto-generated on first run, stored next to signing key | Distributed to laptops via config or daemon-served | Daemon-served from key registry; baked into images |
| **Private key (decrypt)** | Same machine as public — operator owns both | Held by security lead, not on dev laptops | HSM / KMS, multi-recipient escrow (security + legal + corporate root) |
| **Storage** | Local SQLite | Local SQLite + optional remote sync | Pluggable: Postgres, S3, OTel exporters |
| **Fan-out** | None | Optional SIEM / shared dashboard | SIEM, archive, compliance store |
| **Decrypt UX** | `mcp-proxy inspect <id>` reads local private key | Security lead runs the same `mcp-proxy inspect <id>` workflow with their key | Forensic responder retrieves private key from KMS, decrypts in IR tooling |
| **Code path** | Identical | Identical | Identical |

### Storage and fan-out

- **Storage adapters are opaque durability.** No adapter is required to know about encryption. SQLite, Postgres, S3, OTel exporters — all see the same signed-receipt blob. Pluggable storage and SIEM fan-out fall out for free.
- **Daemon owns fan-out** (per ADR-0010). The daemon dispatches signed receipts to local store and any configured sinks. SDK-direct mode keeps local-only behaviour.
- **Schema versioning.** Today's implicit `ALTER TABLE` migrations are acceptable for a hash-only world; introduce a `schema_version` row in the metadata table as a precondition to landing disclosures so we don't lose forensic data through a silent migration.

### Implementation phasing

This ADR's *architecture* is decided now (because the receipt format is permanent once signed). The *implementation* is sequenced behind real value to real personas:

- **Phase A — SDK-direct, solo-dev value.** `parameterDisclosure` config + auto-generated forensic key pair + basic CLI for key export / import. Pre-daemon.
- **Phase B — Daemon-owned (post-ADR-0010).** Daemon serves public keys, owns fan-out, and is the only process that briefly holds plaintext during encryption. Emitters become thin.
- **Phase C — Enterprise.** Multi-recipient HPKE, HSM / KMS adapters, pluggable remote stores, retention knobs, operator-facing key-management documentation.

Phase A receipts are forward-compatible with Phase B and C — no re-encryption, no migration.

### Implementation status (as of 2026-05-21)

#### Phase A landed

Phase A is complete as of 2026-05-21. The HPKE envelope is implemented end-to-end across all three SDKs and pinned across the spec and the cross-SDK test harness:

- **HPKE primitives.** All three SDKs encrypt, decrypt, and round-trip the v1 envelope under the pinned ciphersuite (`hpke-x25519-hkdf-sha256-aes-256-gcm`):
  - Go SDK: PR [#468](https://github.com/agent-receipts/obsigna/pull/468).
  - TypeScript SDK: PR [#472](https://github.com/agent-receipts/obsigna/pull/472), hand-rolled from `node:crypto` (no `@hpke/core` dependency).
  - Python SDK: PR [#494](https://github.com/agent-receipts/obsigna/pull/494).
- **Forensic key-pair lifecycle.** Each SDK ships `GenerateForensicKeyPair` (or its language-idiomatic equivalent); on-disk layout next to the signing key and CLI export/import are tracked alongside the daemon's envelope-side wiring under #280.
- **Spec at v0.3.0.** [`spec/schema/agent-receipt.schema.json`](../../spec/schema/agent-receipt.schema.json) inlines the envelope `$defs` (and the new `peer_credential` / `emitter_metadata` typed action fields) so the main receipt schema validates v0.3.0 receipts directly. PR [#496](https://github.com/agent-receipts/obsigna/pull/496).
- **Cross-SDK byte-identical test vectors.** [`cross-sdk-tests/v030_vectors.json`](../../cross-sdk-tests/v030_vectors.json) pins both the envelope-shape receipt and the daemon-attested-fields receipt; every SDK must reproduce the pinned `expectedReceiptHash` byte-for-byte. PR [#499](https://github.com/agent-receipts/obsigna/pull/499).
- **Typed daemon-attested fields land.** `action.peer_credential` and `action.emitter_metadata` replace the Phase-1 stash inside `parameters_disclosure` ([`daemon/internal/pipeline/build.go`](../../daemon/internal/pipeline/build.go)); the daemon-attested metadata now rides on dedicated typed fields, not on the envelope channel. Across the SDKs: Go in PR-C, TypeScript in PR-D, Python in PR-E (tracked under #280).

The renamed config knob (`parameterDisclosure`) and the OpenClaw value space (`false | true | "high" | string[]`) continue to be honoured at the config layer; the disclosure pipeline now wires through the v1 envelope rather than the legacy flat-map shape.

#### Pre-Phase-A behaviour now deprecated

- The legacy flat-map shape of `action.parameters_disclosure` (Phase-1 daemon-attested keys like `peer.platform`, `emitter.drop_count`, and the redacted-plaintext `input`/`output` written under `--parameter-disclosure`) is **removed from the SDK type space** as of v0.3.0. SDK `Action.ParametersDisclosure` now only accepts the v1 envelope. Daemon-attested metadata lives on the dedicated `action.peer_credential` and `action.emitter_metadata` typed fields. The schema's oneOf still accepts the legacy shape for backwards compatibility on receipts already at rest; SDKs cannot round-trip such receipts through the typed `AgentReceipt` going forward.
- The daemon's `--parameter-disclosure` flag is preserved as a documented no-op pending envelope-mode disclosure in #280 — the legacy plaintext-in-body shape is no longer representable on the wire.

#### Remaining (deferred to Phase B / #280)

- Daemon-side encrypt-then-attach an envelope for tool input/output (replaces the no-op `--parameter-disclosure` flag).
- Forensic-key CLI (export, import, rotate).
- Operator-facing key-management documentation.

Phase B and Phase C are unchanged and remain sequenced behind daemon work (ADR-0010) and enterprise pull respectively.

## Consequences

### Positive

- Uniform answer to the most common forensic question, across every emitter.
- Operator-only control closes the "agent disables its own logging" footgun.
- The asymmetric construction matches ADR-0010's trust model: the encryptor cannot read its own past output, exactly as the agent cannot rewrite its own audit trail.
- Storage stays pluggable. Adapters never see plaintext and never inherit key-management responsibility.
- SIEM / OTel fan-out works trivially: the same signed receipt goes everywhere; the forensic private key gates disclosure mathematically, not configurationally. Trend-analysis sinks get hashes, action types, risk levels, timing, and decisions — never the payload.
- **Crypto-shredding is the GDPR right-to-erasure story.** Destroying the forensic private key (or a per-subject key, if scoped) makes ciphertext meaningless while the chain stays intact. Cleaner than tombstones in an immutable chain.
- The same architecture serves solo, team, and enterprise personas without migration — only key custody changes.

### Negative / explicitly accepted

- **Cross-SDK canonical shape becomes load-bearing.** The disclosure envelope must serialise byte-identically across TS / Py / Go (ADR-0009 territory).
- **Two keys to manage.** Operators now hold an Ed25519 signing key *and* a forensic key pair. Rotation, backup, escrow, and recovery stories all needed.
- **Old private keys must be retained forever.** Receipts are immutable; we cannot re-encrypt historical disclosures when the forensic private key rotates. Public key can rotate freely; private keys accumulate.
- **Verifier UX shifts.** Verification of the chain is unchanged, but forensic recovery now requires the private key. Document explicitly: signing-key holders cannot read disclosures; private-key holders cannot forge receipts.
- **Plaintext window in the encryptor.** The encryptor briefly holds plaintext between "receive parameters" and "encrypt + sign + ship". Daemon mode (ADR-0010) keeps that window out of the agent process; SDK-direct mode keeps it in the SDK process. Documented as the principal reason to prefer daemon mode in non-solo deployments.
- **GDPR / data-handling.** Operators handling PII inherit data-controller obligations even with crypto-shredding available. Surface prominently in docs, not just here.
- **Existing TS `parameters_preview` field is repurposed.** Plaintext-in-body is removed as a supported mode; the field is renamed to `parameters_disclosure` and now carries an envelope, not a string map. This is a behaviour-breaking change (likely a TS SDK major version bump). OpenClaw plugin config also migrates from `parameterPreview` to `parameterDisclosure` with a deprecation alias.
- **Retention is still needed.** Crypto-shredding handles confidentiality long-term, but operators may still want row TTL for storage cost reasons. In-scope to introduce a retention knob (default: keep forever, matching today).

## Alternatives considered

- **Always store raw plaintext.** Strongest forensics, worst default privacy posture. Rejected.
- **Never store raw payloads.** Strongest privacy, leaves the forensic question unanswered. Rejected.
- **Per-tool config without taxonomy integration.** Pushes risk classification onto every operator. Rejected in favour of taxonomy defaults (`"high"`) with explicit allowlist override.
- **Plaintext-in-body (TS SDK today).** Tamper-evident but blocks pluggable-storage encryption *and* SIEM fan-out (any sink seeing the receipt sees the payload). Rejected — superseded by encrypted-in-body.
- **Symmetric encryption (single shared key).** Rejected. The encryptor would be able to decrypt its own past output, breaking parity with ADR-0010's trust model. Also forces fragile key partitioning if SIEMs must be denied decryption capability.
- **Encryption at the storage adapter** (SQLCipher / Postgres TDE / S3 SSE-KMS). Each adapter reinvents key handling, plaintext crosses the adapter boundary, SIEM/telemetry fan-out needs separate redaction. Crypto-shredding only as good as the weakest adapter. Rejected — wrong layer.
- **Sidecar table outside the signed chain.** Avoids canonical-JSON entanglement and allows independent encryption / deletion, but the sidecar is not tamper-evident. Rejected; reserved as a future ADR if right-to-erasure pressure forces selective deletion beyond what crypto-shredding already provides.
- **Defense-in-depth (in-body AND adapter encryption).** Strongest, but doubles the operator's key-management surface. Out of scope for v1.
- **Wait until daemon (ADR-0010) ships.** The daemon is a deployment shift, not an architecture shift. Receipt format is permanent once signed, so the format and envelope must be settled now. Implementation phasing follows the daemon timeline (Phase A pre-daemon, Phase B post-daemon).

## Related ADRs

- [ADR-0001 (Ed25519 signing)](./0001-ed25519-for-receipt-signing.md) — signing key strictly separated from forensic key pair.
- [ADR-0002 (RFC 8785 canonicalization)](./0002-rfc8785-json-canonicalization.md) — disclosure envelope must respect canonical JSON; field ordering and null-vs-omitted handling become verification concerns.
- [ADR-0004 (SQLite storage)](./0004-sqlite-for-local-receipt-storage.md) — this ADR explicitly does not extend SQLite-specific encryption; storage stays opaque.
- [ADR-0008 (response hashing and chain completeness)](./0008-response-hashing-and-chain-completeness.md) — same forensic-vs-privacy argument applies to response payloads; this ADR scopes itself to *parameters* and flags responses as the obvious follow-up.
- [ADR-0009 (canonicalisation profile)](./0009-canonicalization-and-schema-consistency.md) — the disclosure envelope shape is exactly the kind of cross-SDK consistency this ADR is about.
- [ADR-0010 (daemon process separation)](./0010-daemon-process-separation.md) — the daemon owns fan-out and the plaintext window; "operator-controlled" is a real boundary because of this ADR.
- [ADR-0011 (Zod runtime validation)](./0011-zod-for-runtime-validation.md) — the disclosure envelope schema must be added to the Zod store-load validation in the TypeScript SDK.

## Amendments

### 2026-05-18: Envelope canonical shape and algorithm choice (accepted: HPKE)

**Status of this amendment:** all decisions below are locked in, including the cryptographic primitive choice (HPKE base-mode, ciphersuite `hpke-x25519-hkdf-sha256-aes-256-gcm`). The HPKE-vs-sealed-box tradeoff and the recommendation are documented in the *HPKE vs libsodium sealed-box* section below for the record.

**Scope.** The original ADR commits to the envelope's *shape* and forward-compatibility properties (the table under *Forward-compatible envelope shape*) but defers `alg`, the AEAD primitive, and the `kid` registry mechanism to a follow-up. This amendment pins those for v1. It also pins the canonicalisation rules and produces cross-SDK test vectors. The amendment is the **user-facing gate** for ADR-0017 (central receipt hub, draft — will be linked once merged): the hub MUST reject pre-envelope disclosure shapes (plaintext map, redacted-plaintext map), which is unsafe to enforce until conformant envelope producers exist. The two sibling spec tracks landing in parallel are `did:key` resolution (consumed by ADR-0017's JWS auth) and the rotation-event canonical wire format (deferred in ADR-0015).

**Note on the earlier *Forward-compatible envelope shape* illustration.** The illustrative snippet earlier in this ADR (showing the envelope shape) predates this amendment and uses `v: 1` (integer), includes a `nonce` field, and names the encapsulated-key field `encap`. **That snippet is superseded by this amendment.** The v1 canonical shape — `v: "1"` (string), no `nonce`, `enc` (not `encap`) — is the one normative for any new implementation. The earlier snippet is retained in the original section purely for ADR-history readability; readers building against the envelope MUST follow this amendment's field set and types, not the earlier illustration.

**Locked in.**

1. **JSON Schema.** [`spec/schema/parameters-disclosure.schema.json`](../../spec/schema/parameters-disclosure.schema.json) describes the envelope content. It is a sibling schema; the main receipt schema (`agent-receipt.schema.json`) is not yet amended to reference it, because that wiring requires the SDK implementations and the cross-SDK byte-identical harness to land first.
2. **Field set for v1:** `v` (version string), `alg` (ciphersuite tag string), `recipients[]` (length 1 in v1), `ct` (AEAD ciphertext). No `nonce` field — see *Single-shot vs streaming HPKE* below.
3. **Recipient descriptor:** `{ kid, enc }`. The original ADR's sketch named the encapsulated-key field `encap`; this amendment renames it to `enc` to match the RFC 9180 §4.1 vocabulary. The cost is one renamed field in a not-yet-shipped schema; the benefit is no perpetual translation between spec text and library APIs.
4. **`v` is a JSON string, not an integer.** `"1"`, not `1`. This avoids any RFC 8785 number-encoding ambiguity at the verifier. The version-bump rule is: any change to the field set, encoding rule, AEAD/KEM/KDF, or canonicalisation rule is a v2. Bug-fixes to the *implementation* of v1 do not bump.
5. **Encoding:** all binary fields are unpadded base64url (RFC 4648 §5), matching ADR-0009 / spec §4 `proofValue`. Standard base64 is not accepted; padding is not accepted.
6. **Canonicalisation:** RFC 8785 JCS over the envelope (per ADR-0009) and over the plaintext parameters object before AEAD encryption. The latter is what makes the cross-SDK byte-identical claim meaningful — two SDKs that disagree about JCS produce different ciphertexts and the receipt's `parameters_hash` will mismatch.
7. **`recipients` is always an array, length 1 in v1, max 1 in v1.** The array shape is forward-compatible with the Phase C multi-recipient extension; the v1 upper bound prevents a producer from accidentally shipping a multi-recipient envelope under a `v: "1"` label. v2 multi-recipient relaxes the upper bound and adds a per-recipient wrapped-key shape; `ct` remains a single shared ciphertext under a content-encryption key wrapped per recipient.
8. **HPKE base-mode parameters for v1:** `info` = empty string; AAD = empty string. The surrounding signed receipt envelope already authenticates `parameters_disclosure` via signature; no out-of-band context binding is added at the HPKE layer.

**Accepted: HPKE base-mode, ciphersuite `hpke-x25519-hkdf-sha256-aes-256-gcm`.** That is RFC 9180 base mode with KEM = DHKEM(X25519, HKDF-SHA256) (`0x0020`), KDF = HKDF-SHA256 (`0x0001`), AEAD = AES-256-GCM (`0x0002`). The `alg` field carries the human-readable tag rather than the numeric triple so verifiers dispatch on string equality; the numeric triple is recorded in the schema description as the cross-reference for implementers.

**HPKE vs libsodium sealed-box — the one-pager.**

| Axis | HPKE (RFC 9180) | libsodium sealed-box |
|---|---|---|
| Standardisation | IETF RFC, Feb 2022. Wire format and ciphersuite IDs are stable across implementations. | libsodium convention. No RFC; the wire format is "whatever libsodium does." |
| Multi-recipient (ADR-0012 Phase C) | Composable: same ephemeral content-encryption key, wrapped to N recipients with one HPKE encapsulation each. Single `ct`. | Not native. Multi-recipient means N independent sealed-boxes per receipt — N ephemeral keys, N ciphertexts. Loses the single-`ct` property that the Phase C design rests on. |
| Library maturity (Go / TS / Py) | Go: `github.com/cloudflare/circl/hpke` is mature. Py: `pyhpke` is workable. TS: `@hpke/core` is workable but younger than libsodium bindings. The gap is real and closing. | All three languages have mature libsodium bindings (`nacl` / `libsodium-wrappers` / `pynacl`). The maturity gap is in HPKE's favour as of 2026 but small. |
| API surface for v1 single-recipient | More moving parts (KEM/KDF/AEAD triple, `info`, AAD). | Simplest possible API: `crypto_box_seal(plaintext, recipient_pk)`. |
| Phase C migration cost | n/a (HPKE was chosen for v1 here; multi-recipient is additive, not a wire-format change). | High — multi-recipient is a wire-format change, not an additive change. Existing receipts would carry single-`ct` semantics that the v2 design has to either preserve or fork. |

**Recommendation: HPKE.** The library-maturity gap is real but small and shrinking, and the cross-SDK byte-identical test vectors this amendment produces will surface any divergence early. Sealed-box would be perfectly fine for v1 functionally, but would force a wire-format change at Phase C — exactly the kind of premature commitment we want to avoid on a permanent-once-signed receipt format. The IETF status of HPKE also matches the way the rest of the protocol pins on standards (RFC 8032, RFC 8785, RFC 8037).

**Single-shot vs streaming HPKE — call made: single-shot, no `nonce` field.** RFC 9180 distinguishes single-shot encryption (one plaintext, one ciphertext, AEAD nonce derived internally from the KEM output) from streaming-mode encryption (multiple plaintexts under a single setup, application-managed nonce). Each receipt encrypts exactly one parameters object; there is no streaming use case. Single-shot makes the envelope smaller, removes one field worth of canonicalisation surface, and matches what HPKE libraries' "seal/open" APIs already do. Surfacing a `nonce` field in a single-shot envelope would be redundant at best and a footgun at worst (an implementer who supplies a custom nonce against a library that ignores it gets silently wrong behaviour). The schema therefore omits `nonce`; the *shape invariants* in the test vectors call this out so an SDK that adds the field by reflex fails fast.

**Cross-reference to ADR-0017 (central receipt hub, draft — will be linked once merged).** ADR-0017 §6 (precondition check, hub-side rejection of pre-envelope plaintext) MUST consume this schema. The hub rejects with HTTP 422 + diagnostic any `parameters_disclosure` that does not match `parameters-disclosure.schema.json` v1 (or, once shipped, v2). The daemon-attested additive metadata (`peer.*`, `emitter.drop_count`) and the legacy redacted-plaintext map (`input` / `output` under the `--parameter-disclosure` opt-in) are pre-envelope shapes and are rejected by §6 once the gate closes; a separate amendment to ADR-0010 will move the `peer.*` metadata to its dedicated namespace before the hub goes live.

**Test vectors.** [`spec/test-vectors/disclosure-envelope/`](../../spec/test-vectors/disclosure-envelope/) ships two static vectors using well-known X25519 test keys (RFC 7748 §6.1) and the deterministic-`ikmE` pattern from RFC 9180 §7.1.3 / §A.1.1 to make HPKE byte-reproducible. The first revision carries placeholders for the concrete `enc` and `ct` byte values; the first SDK to ship the HPKE primitive fills them in via a follow-up PR. Placeholders are deliberate — a wrong-looking value that all three SDKs happen to load from the same fixture would silently lock in a bug.

**Forward-compatibility note (Phase C extension story).** With `recipients` as an array and a single shared `ct`, the v2 multi-recipient extension is additive at the wire-format level: extend `recipients[].enc` to one HPKE encapsulation per recipient sharing the same content-encryption key (or move to HPKE's emerging multi-recipient mode if standardised), keep `ct` as the single AES-256-GCM ciphertext, and bump `v` to `"2"`. v1 verifiers reading a v2 envelope dispatch on `v` and refuse to decrypt; the receipt's chain signature still verifies, exactly as the original ADR's *Forward-compatible envelope shape* table promises. No re-encryption of historical receipts is ever required.

**Out of scope for this amendment.**

- SDK implementations of envelope encryption (Go / TS / Py). Tracked under #280.
- Daemon rewire of `--parameter-disclosure` from redacted-plaintext to envelope. Tracked under #280.
- Forensic-key CLI (export, import, rotate). Tracked under #280.
- ~~Reference of `parameters-disclosure.schema.json` from `agent-receipt.schema.json`. Lands with the SDK work, not the spec.~~ **Done** in spec PR [#496](https://github.com/agent-receipts/obsigna/pull/496): `agent-receipt.schema.json` inlines the envelope `$defs` directly, so a validator does not need to dereference the sibling schema. The sibling schema stays as the documentation-of-record per the *Locked in* note above.
- `kid` registry mechanism. v1 accepts either a `did:key` DID URL with a fragment or the `sha256:<hex>` fingerprint form; a normative registry is deferred.
- Algorithm agility in `alg`. v1 pins exactly one ciphersuite. Additional ciphersuites require a new ADR-0012 amendment and a v2 envelope.
