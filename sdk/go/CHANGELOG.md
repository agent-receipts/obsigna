# Changelog

All notable changes to `github.com/agent-receipts/ar/sdk/go` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.6.0; earlier releases are recorded only in git history.
A repo-wide effort to auto-generate changelogs from Conventional Commits is
tracked in [#253](https://github.com/agent-receipts/obsigna/issues/253).

## [Unreleased]

## [0.20.0-alpha.1] - 2026-06-13

### Added

- **`Store.LatestRootChainID()`** — returns the chain id of the most recently written root receipt (the chain the daemon is currently appending to), or `found=false` for an empty store. Recency is by `rowid` (write order), not timestamp, so it is correct even when many receipts share the same RFC3339 second. Agent sub-chains (`…/agent/…`) are excluded. Used by `obsigna doctor` to target the live chain instead of guessing today's date.

## [0.19.0] - 2026-06-13

Graduates `0.19.0-alpha.1` after the alpha pass. No source changes since the alpha; see the `0.19.0-alpha.1` entry below for the full surface (`action.target.{system,resource}` on emitter events). Since the last stable `0.17.0`, this also carries the `0.18.0-alpha.1` surface (`KeyRotation` chain-verifier traversal, transcript-derived model/usage on `Runtime`, and the new taxonomy action types). The `0.20.0-alpha.1` line (`Store.LatestRootChainID()`) stays on the alpha track.

## [0.19.0-alpha.1] - 2026-06-12

### Added

- **`action.target.{system,resource}` on emitter events** ([#784](https://github.com/agent-receipts/obsigna/pull/784), ADR-0029) — `emitter.Target{System, Resource}` added to `emitter.Event`; wired into the wire frame as `target_system`/`target_resource` (both `omitempty`). New exported constant `MaxTargetResourceLen = 4096` (Linux PATH_MAX) caps `Target.Resource` client-side, mirroring the daemon's `validateFrame` limit. Client-side XOR validation in `Emit` rejects half-populated `Target` (system without resource, or vice versa) before the write.

## [0.18.0-alpha.1] - 2026-06-11

### Added

- **`KeyRotation` type and chain-verifier traversal** ([#778](https://github.com/agent-receipts/obsigna/pull/778), ADR-0015 Phase A) — `receipt.KeyRotation` carries the seven fields of the `credentialSubject.keyRotation` rotation-event envelope. `VerifyChain` now traverses key-rotation receipts: the outgoing key verifies the `key_rotated` receipt, then the inline `new_public_key` takes over for all subsequent receipts. Fingerprint mismatches and unsupported algorithms are hard errors. New helpers: `FingerprintFromPublicKey`, `PublicKeyFromMultibase`, and `VerifyRotationEvent` (for standalone use). Cross-SDK wire vectors verified against the shared spec test fixture.
- **Transcript-derived model and token usage on `Runtime`** ([#779](https://github.com/agent-receipts/obsigna/pull/779)) — `receipt.Runtime` gains `Model string`, `Usage json.RawMessage` (token-usage object stored verbatim as the runtime reported it), and `CaptureMethod string` alongside the existing `Extra` open map. The emitter `Event` gains the same three fields; the daemon stamps them into `issuer.runtime` on any receipt (including root-chain receipts) where observability data is present. Additive: no existing wire fields, hashing, or signing changes.
- **New taxonomy action types** ([#780](https://github.com/agent-receipts/obsigna/pull/780), ADR-0027) — five new types registered in `taxonomy.go`: `filesystem.directory.list` (low), `system.code.execute` (high), `system.pty.open` (critical), `system.pty.close` (high), and `network.egress.observed` (medium). Exported `ActionTypePTYOpen` / `ActionTypePTYClose` constants added to the receipt package as the shared source of truth.
- **`ChainVerification.IncompleteSession` advisory** ([#780](https://github.com/agent-receipts/obsigna/pull/780), ADR-0027) — `VerifyChain` now sets `IncompleteSession: true` when the count of `system.pty.open` receipts in a chain does not equal the count of `system.pty.close` receipts (catches both unclosed sessions and orphaned closes). Advisory only: does not affect `Valid`.

### Dependencies

- No new external dependencies.

## [0.17.0] - 2026-06-11

Graduates `0.17.0-alpha.1` after the alpha pass. No source changes since the alpha; see the `0.17.0-alpha.1` entry below for the full surface (`issuer.runtime` open metadata sub-object, `agent_type` forwarding).

## [0.17.0-alpha.1] - 2026-06-09

### Added

- **`issuer.runtime` open metadata sub-object** ([#761](https://github.com/agent-receipts/obsigna/pull/761), ADR-0026) — `receipt.Issuer` gains `Runtime *Runtime`, an open container for runtime/observability metadata (initial members `agent_id` / `agent_type`). Unlike the rest of the receipt struct, `Runtime` preserves unknown keys via an `Extra map[string]json.RawMessage` with custom (un)marshalling, so a key added by a newer SDK survives an older SDK's `HashReceipt`/`Sign` round-trip and stays byte-identical across Go/TS/Python. Receipts emitting `runtime` use protocol version `0.5.0` and JSON-LD context v2. The emitter `Event`/frame gains `agent_type` alongside the existing `agent_id`.

## [0.16.0] - 2026-06-09

Graduates `0.16.0-alpha.1` after the alpha pass. No source changes since the alpha; see the `0.16.0-alpha.1` entry below for the full surface (subagent-chain delegation, issuer/event `agent_id`, and `correlation_id`).

## [0.16.0-alpha.1] - 2026-06-08

### Added

- **`Delegation` struct** ([#753](https://github.com/agent-receipts/obsigna/pull/753)) — new `receipt.Delegation` type with `ParentChainID string`, `ParentReceiptID string`, and `Delegator receipt.Delegator` (carrying `ID string`). Added to `CredentialSubject.Delegation *Delegation` and `CreateInput.Delegation *Delegation`. Enables the daemon to attach a verifiable chain backlink to the first receipt on every subagent chain (one subagent chain per `agent_id`). Cross-SDK canonicalisation vectors added.
- **`Issuer.AgentID`** ([#753](https://github.com/agent-receipts/obsigna/pull/753)) — new optional `AgentID string` field on `receipt.Issuer`; stamped when the emitter supplies an `agent_id`, identifying which subagent issued the receipt.
- **`Event.AgentID` and `frame.agent_id`** ([#753](https://github.com/agent-receipts/obsigna/pull/753)) — new `AgentID string` field on `emitter.Event`; forwarded as `agent_id` on the wire frame. Values must not exceed 256 bytes and must not contain `/` or null bytes (validated at the daemon boundary).
- **`CredentialSubject.CorrelationID`** ([#752](https://github.com/agent-receipts/obsigna/pull/752)) — new optional `CorrelationID string` field on `receipt.CredentialSubject`; also exposed as `CreateInput.CorrelationID` and `emitter.Event.CorrelationID`. Populated by the hook from Claude Code's `tool_use_id` and by the MCP proxy from `_meta["claudecode/toolUseId"]`, allowing the pre-check and post-action receipts for one tool call to be joined by auditors.

### Dependencies

- No new external dependencies.

## [0.15.0] - 2026-06-02

### Added

- **HPKE forensic-key helpers** ([#722](https://github.com/agent-receipts/obsigna/pull/722), ADR-0012, ADR-0015) — new `receipt.ForensicKeyFingerprint(publicKey []byte) (string, error)` returns the ADR-0015 canonical fingerprint (`sha256:<hex>` over the raw 32-byte X25519 public key) used as the recipient `kid` in a `DisclosureEnvelope`. New `receipt.ForensicPublicFromPrivate(privateKey []byte) ([]byte, error)` derives the matching X25519 public key from a 32-byte forensic private key, so a responder or dashboard that only holds the private key can recompute the fingerprint and locate the receipts encrypted to it without a separate key registry. Both helpers are X25519-only and reject any input that is not exactly 32 bytes.

### Dependencies

- No new dependencies; the new helpers reuse the existing `github.com/cloudflare/circl/hpke` import.

## [0.14.0] - 2026-06-01

### Breaking Changes

- **`emitter.Emit` surfaces transport failure by default** ([#599](https://github.com/agent-receipts/obsigna/issues/599), ADR-0025). When the daemon socket cannot be dialled or a write fails, `Emit` now returns a non-nil error wrapping the new sentinel `emitter.ErrTransport` instead of silently returning nil. Use `errors.Is(err, emitter.ErrTransport)` to distinguish a transport failure (recoverable; a retry or WAL wrapper may help) from a caller-bug error (invalid event, closed emitter) that a retry cannot fix. The `WithStrictErrors()` option is **removed** — surfacing is now the default; pass the new `WithBestEffort()` option to opt back into loss-tolerant emission (`Emit` returns nil on transport failure).

### Added

- **`chain.ReceiptChain`** ([#488](https://github.com/agent-receipts/obsigna/issues/488), ADR-0020) — new `chain` package providing a stateful, serialised builder for a single hash-linked chain. It owns the chain head (`Sequence` + `PreviousReceiptHash`) and runs build → sign → hash → link → deliver under a mutex, so concurrent `Emit` calls are sequenced at the receipt layer even when the tool calls that triggered them ran in parallel. The first overlapping call logs a one-shot warning via the configured `slog.Logger`. Construct with `chain.New(chain.Options{...})` and emit per action with `Emit(ctx, chain.EmitInput{...})`; the head advances before delivery so a transient emitter failure cannot fork or stall the chain. Parallel sub-chains remain out of scope for v1.
- **`taxonomy.DiagnosticRoundtripActionType`** ([#539](https://github.com/agent-receipts/obsigna/issues/539)) — new built-in low-risk action type (`doctor.agent-receipts-doctor.roundtrip`) classifying the synthetic round-trip event the `agent-receipts doctor` health check emits. Registered in `AllActions()`; exempt from the spec cross-check since diagnostic self-checks are not part of the agent-action taxonomy the spec enumerates.

## [0.13.0] - 2026-05-24

### Breaking Changes

- **`PeerCredential.UID` and `PeerCredential.GID` are now `*uint32`** ([#511](https://github.com/agent-receipts/obsigna/issues/511)). The previous `uint32` with `omitempty` silently dropped UID=0 / GID=0 (root), making a root-emitted receipt indistinguishable from a Windows receipt where UIDs have no meaning. A nil pointer now means "no POSIX UID concept"; a non-nil pointer to zero correctly serialises as `"uid":0`. Cross-SDK test vector `peerCredentialRootReceipt` added to `v030_vectors.json` to pin the zero-value wire form. Callers that read these fields directly must dereference the pointer and guard against `nil`.

### Added

- **`action.IdempotencyKey` field** ([#565](https://github.com/agent-receipts/obsigna/pull/565)) — optional string that ties a retried tool call to its logical operation. Part of spec v0.4.0 (ADR-0019 §S5). Chain verifiers surface duplicate `idempotency_key` values as non-fatal warnings on `ChainVerification.Warnings` (retries are legitimate; only a human reviewer can decide intent). `Version` constant bumped from `"0.3.0"` to `"0.4.0"`.
- **Write-ahead log for at-least-once delivery** ([#567](https://github.com/agent-receipts/obsigna/pull/567)) — new `emitters.WalEmitter` wraps any `Emitter`, records each receipt in a WAL before delivery, and clears the entry only on collector acknowledgement (201/409). Ships two backends: a durable file-backed WAL for long-lived compute (replayed on restart) and an in-memory WAL for ephemeral compute (drained on shutdown via a deadline-bounded flush). Implements ADR-0020 at-least-once guarantee.
- **AWS KMS adapter** ([#578](https://github.com/agent-receipts/obsigna/pull/578)) — new `sdk/go/aws` module provides `KMSSigner`, an `ADR-0018 Signer` backed by AWS KMS. Signing delegates to `kms:Sign`; the signer never holds private key material. The public key is fetched once via `kms:GetPublicKey` and cached. Uses `SigningAlgorithm=ED25519_SHA_512` with `MessageType=RAW` (pure Ed25519 per RFC 8032), matching AWS's ECC_NIST_EDWARDS25519 key type added in November 2025.
- **`store.Exists(id string) (bool, error)`** ([#583](https://github.com/agent-receipts/obsigna/pull/583)) — cheap presence check backed by `SELECT 1 … LIMIT 1`, avoiding the full `receipt_json` decode that `GetByID` pays. Use this on hot paths (e.g., collector duplicate detection) where only a boolean answer is needed.

### Security

- **Safe socket path enforcement** ([#579](https://github.com/agent-receipts/obsigna/pull/579), closes [#538](https://github.com/agent-receipts/obsigna/issues/538)) — `emitter.New()` now validates the socket path before connecting. TCP addresses are rejected unconditionally (ADR-0010 § IPC transport). Paths are canonicalised with `filepath.EvalSymlinks` before comparison so a symlink escaping the safe set is judged by its real target.

## [0.12.1] - 2026-05-23

### Added

- **`emitters` package** ([#548](https://github.com/agent-receipts/obsigna/pull/548)) — new package implements ADR-0020 Step 1: an `Emitter` interface that takes a signed `AgentReceipt` and delivers it to a remote endpoint, plus four implementations: `HttpEmitter` (posts to a collector URL), `CompositeEmitter` (fan-out), `BufferingEmitter` (batches with a flush interval), and `InMemoryEmitter` (test double).
- **`store.InsertRaw(r, rawJSON, hash)`** ([#537](https://github.com/agent-receipts/obsigna/pull/537)) — persists a receipt using the verbatim wire bytes. The struct fields populate the indexed columns; `rawJSON` is stored verbatim in `receipt_json` so an auditor can re-canonicalise and verify the agent's signature against the exact bytes the agent signed over. Intended for HTTP collectors and other external receipt receivers. `Insert` (the existing hot-path used by the daemon) is unchanged.

### Changed

- **`emitter.DefaultSocketPath()` macOS default is now HOME-based** ([#545](https://github.com/agent-receipts/obsigna/issues/545)). macOS resolves to `$XDG_DATA_HOME/agent-receipts/events.sock` (defaulting to `~/.local/share/agent-receipts/events.sock`) instead of `$TMPDIR/agentreceipts/events.sock`. TMPDIR is not inherited by GUI-spawned subprocesses (e.g., MCP servers launched by Claude Desktop), which broke the daemon ↔ emitter handshake silently. HOME is preserved across every supported spawn context. Linux defaults are unchanged. `AGENTRECEIPTS_SOCKET` continues to take precedence.
- **Platform-specific socket resolution split into build-tagged files** (`socketpath_darwin.go`, `socketpath_linux.go`, `socketpath_other.go`). The public `DefaultSocketPath()` API is unchanged.

## [0.11.0] - 2026-05-22

First stable release of the v0.3.0 spec migration (ADR-0012 Phase A). Tracked in [#280](https://github.com/agent-receipts/obsigna/issues/280). Graduates `0.11.0-alpha.1` after the end-to-end alpha pass in [#519](https://github.com/agent-receipts/obsigna/issues/519). No source changes since `0.11.0-alpha.1`; see that entry below for the full v0.3.0 surface.

## [0.11.0-alpha.1] - 2026-05-22

First pre-release of the v0.3.0 spec migration (ADR-0012 Phase A). Tracked in [#280](https://github.com/agent-receipts/obsigna/issues/280).

### Breaking Changes

- **`Action.ParametersDisclosure` type changed** from `map[string]string` to `*DisclosureEnvelope` ([#506](https://github.com/agent-receipts/obsigna/pull/506)). Per ADR-0012 / spec v0.3.0 ([#496](https://github.com/agent-receipts/obsigna/pull/496)), the field now carries the HPKE asymmetric encryption envelope. Downstream code that wrote the legacy flat-map shape will not compile.

### Added

- **`EncryptDisclosure` / `DecryptDisclosure` / `GenerateForensicKeyPair`** ([#468](https://github.com/agent-receipts/obsigna/pull/468)) — RFC 9180 HPKE base-mode helpers (DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM) via `cloudflare/circl`.
- **`Action.PeerCredential` struct** — typed OS-attested peer process metadata. Field widths match POSIX (`int32` for PID, `uint32` for UID/GID; amended to `*uint32` in [0.13.0] — see [#511](https://github.com/agent-receipts/obsigna/issues/511)).
- **`Action.EmitterMetadata` struct** — daemon-observed emitter-side metadata, currently `DropCount`.
- **Cross-SDK live-emit invariant test** ([#515](https://github.com/agent-receipts/obsigna/pull/515)).

### Changed

- **`Version` constant bumped from `"0.2.0"` to `"0.3.0"`** ([#515](https://github.com/agent-receipts/obsigna/pull/515)).
- Legacy v0.2.x flat-map `parameters_disclosure` receipts no longer round-trip through `receipt.AgentReceipt`. Verifiers ingesting legacy receipts must use `map[string]any` — pattern in `sdk/go/receipt/canonicalization_vectors_test.go::TestParametersDisclosureReceipt`.

## [0.10.0] - 2026-05-19

### Added

- **Issuer/operator identity fields on emitted frames** ([#461](https://github.com/agent-receipts/obsigna/pull/461)):
  New `Identity` type and `WithIdentity()` constructor option let callers stamp
  `issuer_name`, `issuer_model`, `operator_id`, and `operator_name` on every
  emitted frame. Per-event fields on `Event` take precedence over the
  emitter-level defaults set via `WithIdentity`. The emitter validates identity
  fields before marshalling: `operator_name` requires `operator_id`, and each
  field is capped at 256 bytes (`MaxIdentityFieldLen`), mirroring the daemon's
  enforcement so violations surface at the emitter rather than being silently
  rejected after the write.

## [0.9.0] - 2026-05-16

### Added

- **`emitter.WithStrictErrors()` option** ([#415](https://github.com/agent-receipts/obsigna/pull/415)):
  When set, `Emitter.Emit()` returns errors on dial and write failures instead
  of calling `logDrop` and returning nil. Callers that do not opt in keep
  fire-and-forget semantics unchanged. Used by `agent-receipts-hook` to surface
  daemon-unreachable as a visible exit-1 failure.

## [0.8.0] - 2026-05-15

### Changed

- No SDK code changes. Version bump to maintain lockstep with the coordinated v0.8.0 release.

## [0.8.0-alpha.2] - 2026-05-10

### Changed

- No SDK code changes; version bump to maintain lockstep across the coordinated
  release (daemon process separation cutover). Releases as part of the daemon
  refactor work (ADR-0010, [#236](https://github.com/agent-receipts/obsigna/issues/236)).

## [0.8.0-alpha.1] - 2026-05-09

### Added

- Fire-and-forget emitter (`emitter/emitter.go`) for forwarding tool-call events
  to the `agent-receipts-daemon` Unix socket (ADR-0010, [#236](https://github.com/agent-receipts/obsigna/issues/236)).
  No crypto, no canonicalisation — the daemon handles those operations.

### Dependencies

- Bump `daemon` dependency to `v0.8.0-alpha.1` (initial daemon release).

## [0.6.0] - 2026-05-01

### Features

- Add `ParametersDisclosure map[string]string` field to the `Action` struct,
  matching the spec change in [ADR-0012](https://github.com/agent-receipts/obsigna/blob/main/docs/adr/0012-payload-disclosure-policy.md)
  (commit `3d51d44`). Operator-controlled, additive map of field name →
  stringified value that sits alongside `ParametersHash`. The hash continues
  to cover the full parameter set; `ParametersDisclosure` exists for
  human/auditor display only.

  **Safety invariant.** Receipts are signed and durable — any value placed in
  `ParametersDisclosure` is permanent and visible to anyone who can read the
  receipt. Callers MUST restrict keys to an explicit operator-managed
  allowlist and MUST NOT populate this field from raw tool arguments.

### Bug Fixes

- Surface `HashReceipt` errors in `VerifyChain` instead of silently returning
  `HashLinkValid: false` (indistinguishable from tampering). On hash-compute
  failure, `ChainVerification.Error` is now populated with the failing index
  and reason, and the function returns early — mirroring the existing
  signature-error pattern
  ([#173](https://github.com/agent-receipts/obsigna/issues/173), commits `675e8f4`,
  `2b5a1ce`).
- Spec: align `proofValue` encoding to base64url throughout, tighten the
  schema pattern, fix inline placeholders, and use 86-char base64url
  placeholder values in all examples (commits `fa0db6b`, `79f7301`,
  `0839e81`).

### Tests

- Add `parameters_disclosure` cross-language test vector in
  `cross-sdk-tests/` (commit `60bbe51`).
- Add `TestVerifyChainSurfacesHashError` covering the new hash-error branch
  in `VerifyChain` (commit `675e8f4`).
