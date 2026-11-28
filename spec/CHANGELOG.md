# Changelog

All notable changes to the Agent Receipt Protocol specification will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Drafted in `spec/v0.7.0/spec.md`. Not yet tagged.

### Added
- Defined `issuer.type` values, one per signing deployment (§4.3.1): `"AIAgent"` when the agent signs its own receipts (client-side signing, ADR-0020), and `"AgentReceiptsDaemon"` when an observing daemon signs them (ADR-0010). Other values remain allowed, and verifiers MUST NOT reject an unrecognized value.
- §7.10 Signing mode and key custody. A receipt carries no in-band proof of which deployment signed it, because `issuer.type`, `issuer.id`, `action.peer_credential` and `action.emitter_metadata` are ordinary signed fields that a client-side signer can set. Verifiers MUST NOT conclude daemon signing from those fields alone, MAY do so with independent knowledge that the key is daemon-held, and SHOULD report the custody they could establish.
- Spec field rows for `action.peer_credential` and `action.emitter_metadata` (§4.3.2). Both were previously defined only in the schema.
- §9 open question 12, key custody evidence: binding daemon custody to the key rather than to receipt fields.
- JSON-LD **context v4** (`https://agentreceipts.ai/context/v4`) adds the `AgentReceiptsDaemon` term, so that issuer type expands to `ar:AgentReceiptsDaemon` instead of the W3C VC v2 catch-all IRI. Identical to v3 otherwise. Receipts at `0.7.0` reference context v4. Contexts are published when merged, so v4 is live and final from this entry on; 0.7.0 adds no further JSON-LD terms. v1–v3 remain permanent (ADR-0021 D3).
- Grounded-principal tier checks the receipt against the grant (§7.9, ADR-0041): validity at the issuer-asserted action time (§7.9.3) and scope containment (§7.9.2 step 5). New tier outcomes `GRANT_NOT_VALID_AT_ACTION_TIME`, `GRANT_VALIDITY_UNRESOLVED` and `GRANT_SCOPE_EXCEEDED`. A verifier-supplied clock-skew tolerance `δ` (default zero). A warning when the receipt's `granted_at` / `expires_at` disagree with the grant (§7.9.4). Receipt times are read as RFC 3339 date-times; an unreadable `action.timestamp` gives `GRANT_VALIDITY_UNRESOLVED`, and an unreadable stated `granted_at` or `expires_at` raises no warning.

### Changed
- Grant resolver contract (§7.9.1). The resolved grant now requires `subject`, `scopes`, `valid_from` (renamed from `issued_at`), `revocation` (`not_revoked`, `revoked` or `unknown`) and `issuer`; `expires_at`, which 0.6.0 listed in the minimum set, and `revoked_at` are optional. A grant that has expired or been revoked now resolves with its terms, when the resolver can establish them, instead of being a resolution failure, which reverses the "token revoked" case in 0.6.0's §7.9 step 2. Malformed grants are treated as resolution failures. This is a breaking change for grant-resolver implementations.
- `version` field now accepts `"0.7.0"` in addition to `"0.1.0"`–`"0.6.0"`. Verifiers MUST accept all eight.
- `issuer.type` previously had a single SHOULD (`"AIAgent"`), which the daemon never followed because it is not an AI agent. The SHOULD is now per signer role.
- Schema descriptions of `peer_credential` and `emitter_metadata` no longer call them "daemon-attested, not agent-claimed" without qualification. They are attested by the daemon only when the key is known to be daemon-held.

## [0.6.0] - 2026-06-21

### Added
- `credentialSubject.outcome.response_disclosure` — HPKE asymmetric encryption envelope sealing the tool response, mirroring the existing `action.parameters_disclosure` for tool input. The signed receipt commits to the ciphertext; only the forensic private-key holder can recover the plaintext. Same envelope structure: HPKE v1, same forensic keypair, same `kid`/fingerprint resolution, same `encrypt_disclosure`/`decrypt_disclosure` flow. `outcome.response_hash` remains the tamper-evidence commitment and is always authoritative; `response_disclosure` is additive. Operators enable response disclosure via a separate `--response-disclosure` policy flag (independent of `--parameter-disclosure`), so sealing outputs without sealing inputs or vice versa is supported. Implemented in the Go, TypeScript and Python SDKs and the daemon.
- JSON-LD **context v3** (`https://agentreceipts.ai/context/v3`) — adds the `response_disclosure` term (`@type: @json`) to the `outcome` context. Identical to v2 otherwise. Receipts at `0.6.0` reference context v3 in their `@context` array; v1 and v2 remain permanent for earlier receipts (ADR-0021 D3).
- `credentialSubject.keyRotation` — key-rotation event (ADR-0015 Phase A). A receipt signed with the outgoing key carries the incoming public key inline, so a verifier can chain through rotations from the genesis key alone. Spec §4.3.2 (field rows) and §7.3.7 (key-rotation traversal).
- Grounded-principal conformance tier (ADR-0038), spec §7.9. An opt-in verifier tier: for `high`/`critical` receipts, `authorization.grant_ref` must resolve through a configured grant resolver to a grant whose subject equals `principal.id`. New verifier outcomes `UNGROUNDED_PRINCIPAL` and `PRINCIPAL_GRANT_MISMATCH`, raised only in this tier.
- Taxonomy action types `filesystem.directory.list` (low), `system.code.execute` (high), `system.pty.open` (critical) and `system.pty.close` (high), and a new `network` domain with `network.egress.observed` (medium). Added to `spec/taxonomy/action-types.json` and to the spec §5 tables, where Network is §5.7; Unknown and Custom Action Types move to §5.8 and §5.9.
- Spec field-reference rows for `action.parameters_disclosure` and `outcome.response_disclosure` (§4.3.2). `parameters_disclosure` was previously defined only in the schema.

### Changed
- `version` field now accepts `"0.1.0"`, `"0.2.0"`, `"0.2.1"`, `"0.3.0"`, `"0.4.0"`, `"0.5.0"`, or `"0.6.0"`. Verifiers MUST accept all seven. All new receipts SHOULD use `"0.6.0"`.

### Fixed
- The `keyRotation` and §7.9 text above was first added by editing `spec/v0.5.0/spec.md` after the `spec-v0.5.0` tag. It belongs to 0.6.0, and `spec/v0.5.0/spec.md` is restored to its tagged text, per ADR-0021 D1 (released spec files are immutable). The 0.6.0 text lives at `spec/v0.6.0/spec.md`. That file and the `spec-v0.6.0` tag were cut after the date on this entry, which records when receipts at `0.6.0` were first emitted.
- `action.trusted_timestamp` prose (§4.3.2, §7.7) said the field MAY be set to `null`, and the §4.1 example emitted `null` for the optional fields `trusted_timestamp`, `outcome.error` and `authorization.grant_ref`. The schema has rejected these since ADR-0009 (optional fields MUST be omitted, never `null`). The prose and example now match the schema.

### Upgrade notes

**Issuers:** No action required to remain protocol-valid. To seal the tool response for forensic recovery, encrypt it with the forensic X25519 public key and populate `outcome.response_disclosure` using the same HPKE envelope as `action.parameters_disclosure`. Requires `--response-disclosure` to be enabled at the operator level. Upgrade to `"version": "0.6.0"` (and context v3) when emitting new receipts with this field. Omit optional fields that have no value; never emit them as `null`. This was already required by the schema (ADR-0009), but earlier spec prose allowed `null` for `action.trusted_timestamp`.

**Verifiers:** No breaking changes. Receipts at `0.1.0`–`0.5.0` validate unchanged against their pinned contexts. The `response_disclosure` field is optional; absence is not a failure. When present, verifiers with the forensic private key can recover the plaintext response using `decrypt_disclosure` (all SDKs). Chains that contain a `keyRotation` receipt verify only with a verifier that implements §7.3.7. The grounded-principal checks (§7.9) apply only when a verifier opts in by configuring a grant resolver.

## [0.5.0] - 2026-06-09

### Added
- `issuer.runtime` — optional open container for runtime/observability metadata the issuing runtime attaches to an action. Initially defined members: `runtime.agent_id` (identifier of the sub-agent that issued the receipt) and `runtime.agent_type` (runtime-reported agent type label, e.g. `"general-purpose"`). Absent for the root agent. Unlike every other issuer field, `runtime` is **not** `additionalProperties: false` in the schema and is typed `@json` in the JSON-LD context, so it is an opaque JSON literal that may carry additional keys. New runtime members (e.g. forthcoming W3C Trace Context / OpenTelemetry identifiers) MAY be added without a protocol-version or context-version bump. See spec §4.3.1 and ADR-0026.
- JSON-LD **context v2** (`https://agentreceipts.ai/context/v2`) — adds the `runtime` term (`@type: @json`). Identical to v1 otherwise. Receipts at `0.5.0` reference context v2 in their `@context` array; v1 remains permanent for earlier receipts (ADR-0021 D3).

### Changed
- `version` field now accepts `"0.1.0"`, `"0.2.0"`, `"0.2.1"`, `"0.3.0"`, `"0.4.0"`, or `"0.5.0"`. Verifiers MUST accept all six. All new receipts SHOULD use `"0.5.0"`.

### Upgrade notes

**Issuers:** No action required to remain protocol-valid. Receipts emitted through a daemon that knows a sub-agent's identity will carry `issuer.runtime.agent_id` / `agent_type`; the root agent omits `runtime` entirely. Upgrade to `"version": "0.5.0"` (and context v2) when emitting new receipts.

**Verifiers:** No breaking changes. Receipts at `0.1.0`–`0.4.0` validate unchanged against their pinned context v1. Treat unknown keys inside `issuer.runtime` as untrusted, signed-but-unvalidated metadata — never as identity.

## [0.4.0] - 2026-05-23

### Added
- `credentialSubject.action.idempotency_key` — optional stable identifier for the logical operation an action represents (e.g. a request ID). When an agent retries a tool call, the SDK or MCP proxy stamps the same `idempotency_key` on every receipt emitted for that operation, letting auditors distinguish a legitimate retry from a duplicated emission. MUST be a non-empty string when present; MUST NOT be `null`. The MCP proxy populates it automatically from the wrapped JSON-RPC request `id`. See spec §4.3.2, §7.3.6, and ADR-0019 §S5 (#480).
- Spec §7.3.6: normative verifier rule — two or more receipts in a chain sharing a non-empty `idempotency_key` are surfaced as a **warning**, never a verification failure. Retries are legitimate. SDK chain verifiers expose these advisories on their verification result (Go `ChainVerification.Warnings`, TS `ChainVerification.warnings`, Python `ChainVerification.warnings`).

### Changed
- `version` field now accepts `"0.1.0"`, `"0.2.0"`, `"0.2.1"`, `"0.3.0"`, or `"0.4.0"`. Verifiers MUST accept all five. All new receipts SHOULD use `"0.4.0"`.

### Upgrade notes

**Issuers:** No action required to remain protocol-valid. To deduplicate retries, stamp a stable `action.idempotency_key` on each receipt for the same logical operation — omit the field entirely when no stable identifier is available (never emit `null` or an empty string). Upgrade to `"version": "0.4.0"` when emitting new receipts.

**Verifiers:** No breaking changes. Receipts at `0.1.0`–`0.3.0` validate unchanged. Duplicate `idempotency_key` values produce an advisory warning on the verification result, not a failure.

## [0.3.0] - 2026-05-21

### Changed
- **BREAKING:** W3C VC type renamed from `AIActionReceipt` to `AgentReceipt`
- **BREAKING:** Schema file renamed from `action-receipt.schema.json` to `agent-receipt.schema.json`
- **BREAKING:** Spec document renamed from `action-receipt-spec-v0.1.md` to `agent-receipt-spec-v0.1.md`
- All example receipts updated to use `AgentReceipt` credential type
- `parameters_disclosure` widened from `{ map[string]string }` (legacy flat-map) to `{ oneOf: [legacy flat-map, HPKE asymmetric encryption envelope] }`. The envelope shape is defined by the sibling `parameters-disclosure.schema.json` introduced alongside ADR-0012 Phase A; SDK implementations: Go SDK #468, TS SDK #472, Python SDK #494. Receipts MUST NOT mix shapes within a single `parameters_disclosure` field; mode is per-emitter.
- `version` field now accepts `"0.1.0"`, `"0.2.0"`, `"0.2.1"`, or `"0.3.0"`. Verifiers MUST accept all four.

### Added
- `credentialSubject.action.peer_credential` — OS-attested peer process metadata captured by the daemon at the SDK↔daemon boundary (`platform`, `pid`, optional `uid`/`gid`/`exe_path`). Present only on receipts emitted through a daemon; daemon-attested, not agent-claimed. Replaces the `peer.*` keys that previously rode on `parameters_disclosure` in the daemon's legacy flat-map writes (ADR-0010).
- `credentialSubject.action.emitter_metadata` — Daemon-observed emitter-side metadata, currently a single `drop_count` field on synthetic events_dropped receipts. Replaces the `emitter.drop_count` key that previously rode on `parameters_disclosure`.

### Migration

**Issuers:** Daemon-mode emitters MUST move `peer.*` writes to `peer_credential` and `emitter.drop_count` writes to `emitter_metadata` when emitting 0.3.0 receipts. Direct-SDK emitters that use the envelope shape MUST set `version` to `"0.3.0"`.

**Verifiers:** No action required for 0.2.0 / 0.2.1 receipts (they validate unchanged against this schema). 0.3.0 receipts MAY carry either the legacy flat-map (continuing the 0.2.1 behaviour) or the envelope shape; verifiers handling both MUST dispatch on the JSON shape of `parameters_disclosure`.

## [0.2.1] - 2026-04-22

### Changed
- **Field rename (schema-and-spec only):** `validFrom` → `issuanceDate`. All three SDKs have always emitted `issuanceDate` (VC 1.x naming); the schema is now aligned. No wire-format change for any existing receipt. See ADR-0009.
- **Optional-nullable types tightened:** `outcome.error`, `authorization.grant_ref`, and `action.trusted_timestamp` no longer declare `null` in their schema type. These fields MUST be absent (not `null`) when not applicable. The sole remaining nullable type in the schema is `chain.previous_receipt_hash` (required-nullable).
- `version` field now accepts `"0.1.0"`, `"0.2.0"`, or `"0.2.1"`. Verifiers MUST accept all three.

### Added
- Spec §7.1.1: normative null/optional field handling rule — required-nullable fields MUST be emitted with their value (including explicit `null`); optional fields MUST NOT be emitted when null or absent. Closes #85 at the spec level.
- `cross-sdk-tests/canonicalization_vectors.json`: shared canonicalisation test vectors covering UTF-16 key-sort edge cases, ES6 number boundaries, RFC 8259 string escaping, null normalisation, and signature preservation.
- ADR-0009: records the two spec-level decisions (VC field name commitment, null rule) and the signature-preservation invariant for existing receipts.

### Upgrade notes

**Issuers and verifiers:** No action required for existing receipts. All shipped 0.1.0 and 0.2.0 receipts already use `issuanceDate` and none emit `null` on optional fields, so the wire format is unchanged. Upgrade to `"version": "0.2.1"` when emitting new receipts to signal conformance to the null-rule and the tightened schema.

## [0.2.0] - 2026-04-22

### Added
- `outcome.response_hash` — optional `sha256:`-prefixed hash of the RFC 8785 canonical JSON of the server's response, computed after secret redaction (redact → hash → sign). Issuers populate when emitting responses they wish to commit to; verifiers recompute when the response body is available and fail on mismatch. When the response body is absent the verifier notes "response hash present, body not supplied" and continues. Absence of the field is not a failure.
- `chain.terminal` — optional field restricted to the constant `true`. Marks the last receipt in a chain as closed. Explicit `false` is schema-invalid; absence means no claim. An automatic "receipt after terminal" integrity check invalidates any receipt that appears after a terminal receipt in the verified input sequence, regardless of linkage or caller parameters.
- `VerifyChain` gains three optional parameters across all SDKs — `ExpectedLength`, `ExpectedFinalHash`, `RequireTerminal` — for out-of-band and in-band truncation detection. When unsupplied, behaviour is identical to v0.1.0.
- Spec §7.3.1: normative language stating that chain verification does **not** detect tail truncation by default, documenting the three available mitigations, and stating the detection floor.
- Spec §7.3.2: normative language defining the unconditional receipt-after-terminal integrity check.

### Changed
- `version` field now accepts both `"0.1.0"` and `"0.2.0"`. Verifiers MUST accept both values. All new receipts SHOULD use `"0.2.0"`.

### Upgrade notes

**Issuers:** No action required to remain protocol-valid. To commit to the server's response, redact the response body, canonicalize (RFC 8785), hash (SHA-256), and populate `outcome.response_hash` before signing. To mark a chain as closed, set `chain.terminal: true` on the final receipt — omit the field entirely otherwise (never emit `false`).

**Verifiers:** No breaking changes. `VerifyChain` with no new parameters is identical to v0.1.0 behaviour. Pass `RequireTerminal: true` for chains that must close cleanly. Pass `ExpectedFinalHash` when you maintain an external audit record of chain state.

## [0.1.0] - 2026-03-31

### Added
- Core protocol specification (§1–§10)
- Action Receipt schema as W3C Verifiable Credential with `AIActionReceipt` type
- Ed25519Signature2020 signing and verification
- Receipt chain model with SHA-256 hash linking and sequence numbering
- Delegation model for multi-agent scenarios with parent chain references
- Reversal receipt model with `outcome.reversal_of` field
- Normative chain issuer rule: one issuer per chain, delegation creates new chains
- Action taxonomy with six domains: filesystem, system, communication, document, financial, data
- Risk level classification: low, medium, high, critical (no-downgrade rule)
- `unknown` action type fallback with mandatory `action.target.system`
- Custom action type support via reverse-domain prefixes
- JSON Schema (Draft 2020-12) for receipt validation
- Taxonomy JSON Schema for action type definitions
- Privacy-preserving design: parameters hashed, never stored in plaintext
- Optional RFC 3161 trusted timestamps
- Non-normative intent field guidance (conversation_hash, reasoning_hash)
- End-to-end receipt verification algorithm (§7.8)
- CI workflow for JSON syntax and schema validation
- AGENTS.md for AI coding agent context
- Open questions documented in §9 (concurrent chains, DID methods, batched receipts, etc.)
