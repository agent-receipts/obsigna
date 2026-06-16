# Changelog

All notable changes to `obsigna` (Python SDK, formerly `agent-receipts`) are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.5.0; earlier releases are recorded only in git history.
A repo-wide effort to auto-generate changelogs from Conventional Commits is
tracked in [#253](https://github.com/agent-receipts/obsigna/issues/253).

## [Unreleased]

## [0.13.0] - 2026-06-12

Graduates `0.13.0a2` after the alpha pass. No source changes since the alpha; see the `0.13.0a2` and `0.13.0a1` entries below for the full surface (`obsigna` rename, `KeyRotation` dataclass and chain-verifier traversal).

## [0.13.0a2] - 2026-06-12

First release under the **`obsigna`** distribution name (no functional change
over `0.13.0a1`; the bump exists because the `sdk-py-v0.13.0a1` tag was already
consumed by the final `agent-receipts` release).

### Changed

- **Package renamed to `obsigna`** (was `agent-receipts`), and the import module
  renamed `agent_receipts` → `obsigna`. The public API is otherwise unchanged.
  The legacy `agent-receipts` distribution remains published and gains a final
  redirect release: a shim that depends on `obsigna`, re-exports it, and emits a
  `DeprecationWarning` on `import agent_receipts`. Existing installs keep working.
  Migrate with `pip install obsigna` and update imports to `obsigna`.

## [0.13.0a1] - 2026-06-11

### Added

- **`KeyRotation` dataclass and chain-verifier traversal** ([#778](https://github.com/agent-receipts/obsigna/pull/778), ADR-0015 Phase A) — new `KeyRotation` frozen dataclass in `agent_receipts.receipt.types`; added to `CredentialSubject.key_rotation: KeyRotation | None = None`. `verify_chain` now traverses key-rotation receipts: the outgoing key verifies the `key_rotated` receipt, then the inline `new_public_key` takes over for all subsequent receipts. Fingerprint mismatches and unsupported algorithms are hard errors. Cross-SDK wire vector verified.

### Dependencies

- No new external dependencies.

## [0.12.0] - 2026-06-09

Graduates `0.12.0a1` after the alpha pass. No source changes since the alpha; see the `0.12.0a1` entry below for the full surface (`Delegation` dataclass and `correlation_id`).

## [0.12.0a1] - 2026-06-08

### Added

- **`Delegation` dataclass** ([#753](https://github.com/agent-receipts/obsigna/pull/753)) — new `Delegator` and `Delegation` frozen dataclasses in `agent_receipts.receipt.types`. `Delegation` carries `parent_chain_id: str`, `parent_receipt_id: str`, and `delegator: Delegator`. Added to `CredentialSubject.delegation: Delegation | None = None` and `CreateInput.delegation: Delegation | None = None`. Cross-SDK canonicalisation vectors added.
- **`CredentialSubject.correlation_id`** ([#752](https://github.com/agent-receipts/obsigna/pull/752)) — new optional `correlation_id: str | None = None` field linking the pre-check and post-action receipts for a single tool invocation.

## [0.11.1] - 2026-06-03

### Added

- **`DAEMON_PROTOCOL_RANGE` re-export** ([#655](https://github.com/agent-receipts/obsigna/pull/655), Gate #8). Exposes the SDK's declared daemon-protocol version range (`DaemonProtocolRange(min=1, max=1)`) at the package root so the release-time daemon ↔ SDK compatibility check (`scripts/daemon_protocol/check.py`) can read it. The constant was added in source for 0.11.0 but merged to main after the 0.11.0 tag was cut, so the published 0.11.0 package did not include it — this release publishes the export.

## [0.11.0] - 2026-06-02

### Breaking Changes

- **`DaemonEmitter.emit` surfaces transport failure by default** ([#599](https://github.com/agent-receipts/obsigna/issues/599), ADR-0025). When the daemon is unreachable or a write fails, `emit()` now raises `EmitTransportError` (exported from the package root) instead of returning `None`. It is distinct from the `ValueError` / `RuntimeError` raised for caller bugs, so callers can `except EmitTransportError` to retry only transport failures. Pass `best_effort=True` to the constructor to opt back into loss-tolerant emission (`emit()` returns `None` on transport failure).

### Added

- **`ReceiptChain`** ([#488](https://github.com/agent-receipts/obsigna/issues/488), ADR-0020). Stateful, serialised builder for a single hash-linked chain, exported from the package root alongside its per-receipt input model `ChainEmitInput`. It owns the chain head (`sequence` + `previous_receipt_hash`) and runs build → sign → hash → link → deliver under a lock, so concurrent `emit()` calls from multiple threads are sequenced at the receipt layer even when the tool calls that triggered them ran in parallel. The first overlapping call logs a one-shot warning via the `agent_receipts.receipt_chain` logger. The head advances before delivery so a transient emitter failure cannot fork or stall the chain. Parallel sub-chains remain out of scope for v1.

## [0.10.0] - 2026-05-24

### Breaking Changes

- **`PeerCredential.uid` and `PeerCredential.gid` are now `Optional[int]`** ([#580](https://github.com/agent-receipts/obsigna/pull/580)). Previously typed as `int` (defaulting to `0` when absent), they are now `int | None` to align with the Go SDK's `*uint32`. This disambiguates UID/GID 0 (root) from "platform does not report UIDs" — callers that relied on a zero default must update to explicit `None` checks.
- **Top-level `Emitter` is now the delivery Protocol, not the daemon socket client** ([#548](https://github.com/agent-receipts/obsigna/pull/548)). The pre-0.10 Unix-socket emitter is now `DaemonEmitter`; `agent_receipts.Emitter` is a `runtime_checkable` Protocol and cannot be instantiated. Code that did `from agent_receipts import Emitter` / `Emitter(socket_path=...)` now raises `TypeError: Protocols cannot be instantiated`. Migration: use `from agent_receipts import DaemonEmitter` and `DaemonEmitter(socket_path=...)`.

### Added

- **`Emitter` protocol and implementations** ([#548](https://github.com/agent-receipts/obsigna/pull/548)). New `agent_receipts.emitters` package (ADR-0020 step 1) exposing:
  - `Emitter` — a `runtime_checkable` Protocol for signed-receipt delivery.
  - `HttpEmitter` — synchronous and fire-and-forget HTTPS delivery with exponential-backoff retry, configurable auth (`BearerAuth`, `ApiKeyAuth`, `MtlsAuth`, `NoAuth`), and `cancel_event` support for graceful shutdown.
  - `CompositeEmitter` — fan-out to multiple emitters; always attempts every child, collects failures into `CompositeEmitError`.
  - `BufferingEmitter` — batches receipts and flushes on size or explicit call; raises `BufferingFlushError` for partial failures.
  - `InMemoryEmitter` — in-process accumulator for testing.
- **`WalEmitter` (WAL for at-least-once delivery)** ([#567](https://github.com/agent-receipts/obsigna/pull/567)). Wraps any `Emitter`; records each receipt in a write-ahead log before delivery and clears the entry on acknowledgement. Two backends:
  - `FileWal` — durable file-backed WAL for long-lived compute; atomic writes (fsync + rename), survives process restart.
  - `MemoryWal` — in-process WAL for ephemeral compute (Lambda, Cloud Run, Fargate).
  - `WalEmitter.replay()` drains a crash backlog at startup; `WalEmitter.flush(deadline_ms)` drains on graceful shutdown.
- **`Action.idempotency_key`** (`Optional[str]`, min length 1) ([#565](https://github.com/agent-receipts/obsigna/pull/565)). Stable identifier for a logical operation so auditors can distinguish legitimate retries from duplicate emissions. Spec v0.4.0 field (see spec §7.3.6 and ADR-0019 §S5). `RECEIPT_VERSION` constant updated to `"0.4.0"`.

### Changed

- **`default_socket_path()` macOS default is now HOME-based** ([#545](https://github.com/agent-receipts/obsigna/issues/545)). macOS resolves to `$XDG_DATA_HOME/agent-receipts/events.sock` (defaulting to `~/.local/share/agent-receipts/events.sock`) instead of `$TMPDIR/agentreceipts/events.sock`. TMPDIR is not inherited by GUI-spawned Python processes (e.g., MCP servers launched by Claude Desktop), which broke the daemon ↔ emitter handshake silently. The Go and TypeScript SDKs ship the same resolution so every emitter and the daemon agree on a single path per user. `AGENTRECEIPTS_SOCKET` continues to take precedence; users who relied on TMPDIR redirection should switch to it.

### Fixed

- **`EmitterMetadata()` with no arguments now raises `ValueError`** ([#509](https://github.com/agent-receipts/obsigna/issues/509)). All-`None` construction was silently accepted; the empty object serialised to `{}` and perturbed the receipt hash. The model now validates that at least one field is set.

### Tests

- Strip null optionals in the v0.2.0 cross-language verify path ([#584](https://github.com/agent-receipts/obsigna/pull/584)). Test-only; no API change.

## [0.9.0] - 2026-05-22

First stable release of the v0.3.0 spec migration (ADR-0012 Phase A). Tracked in [#280](https://github.com/agent-receipts/obsigna/issues/280). Graduates `0.9.0a3` after the end-to-end alpha pass in [#519](https://github.com/agent-receipts/obsigna/issues/519). No source changes since `0.9.0a3`; see the `0.9.0a1` entry below for the full v0.3.0 surface.

## [0.9.0a3] - 2026-05-22

Re-cut as a diagnostic test of [#518](https://github.com/agent-receipts/obsigna/pull/518); no source changes vs `0.9.0a2`. Verifies whether the `prereleased` event-type fix is sufficient to fire `publish-py.yml`, or whether the deeper `GITHUB_TOKEN` workflow-suppression issue tracked in [#521](https://github.com/agent-receipts/obsigna/issues/521) still blocks publication.

## [0.9.0a2] - 2026-05-22

Re-cut of the v0.3.0 pre-release after fixing the `publish-py.yml`
event-type filter ([#518](https://github.com/agent-receipts/obsigna/pull/518)).
No source changes vs `0.9.0a1`; `0.9.0a1` was tagged but never reached
PyPI because the publish workflow only listened on
`release.types: [published]` and prereleases fire `prereleased`.

Skip `0.9.0a1` — install `agent-receipts==0.9.0a2`.

## [0.9.0a1] - 2026-05-22

First pre-release of the v0.3.0 spec migration (ADR-0012 Phase A). Tracked in [#280](https://github.com/agent-receipts/obsigna/issues/280).

### Breaking Changes

- **`Action.parameters_disclosure` shape changed** to the HPKE asymmetric encryption envelope. Was `dict[str, str] | None`, now `DisclosureEnvelope | None`. Downstream code that constructed the legacy flat-map will fail Pydantic validation. See [#505](https://github.com/agent-receipts/obsigna/pull/505).

### Added

- **`encrypt_disclosure` / `decrypt_disclosure` / `generate_forensic_key_pair`** ([#494](https://github.com/agent-receipts/obsigna/pull/494)) — RFC 9180 HPKE base-mode helpers (DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM) for the v1 disclosure envelope. Hand-rolled on `pyca/cryptography` (no new top-level deps).
- **`Action.peer_credential`** — typed OS-attested peer process metadata (`platform`, `pid`, optional `uid`/`gid`/`exe_path`).
- **`Action.emitter_metadata`** — daemon-observed emitter-side metadata, currently `drop_count`.
- **Cross-SDK live-emit invariant test** ([#515](https://github.com/agent-receipts/obsigna/pull/515)).
- **`typing_extensions.TypedDict` migration** ([#505](https://github.com/agent-receipts/obsigna/pull/505)) — Pydantic v2 cannot introspect stdlib `typing.TypedDict` on Python < 3.12.

### Changed

- **`VERSION` constant is `"0.3.0"`** — receipts emitted via `create_receipt()` now stamp the v0.3.0 schema label.
- The typed `AgentReceipt` model only accepts the envelope shape on `parameters_disclosure`. Legacy v0.2.x flat-map receipts will fail `AgentReceipt(**raw_json)` — verifiers ingesting legacy receipts must use `hash_receipt(raw_dict)` and inline signature verification.

## [0.8.0] - 2026-05-15

### Changed

- No SDK code changes. Version bump to maintain lockstep with the coordinated v0.8.0 release.

## [0.8.0a2] - 2026-05-10

### Changed

- No SDK code changes; version bump to maintain lockstep across the coordinated
  release (daemon process separation cutover). Releases as part of the daemon
  refactor work (ADR-0010, [#236](https://github.com/agent-receipts/obsigna/issues/236)).

### Improved

- `VERSION` now derived from package metadata at import time via
  `importlib.metadata.version()`, making `pyproject.toml` the single source
  of truth and eliminating version drift (closes [#345](https://github.com/agent-receipts/obsigna/issues/345)).

## [0.8.0a1] - 2026-05-09

### Added

- Fire-and-forget emitter for forwarding tool-call events to the
  `agent-receipts-daemon` Unix socket (ADR-0010, [#236](https://github.com/agent-receipts/obsigna/issues/236)).
  No crypto, no canonicalisation — the daemon handles those operations.

## [0.5.0] - 2026-05-01

### Hash compatibility note

This release contains a canonicalization fix that changes the SHA-256 receipt
hash for receipts whose JSON exercises the affected edge cases (non-BMP UTF-16
sort keys, numbers near the ES6 fixed/exp boundaries, optional `null`
fields). Receipts created with v0.4.0 will still verify their own signatures,
but their stored hash may not match a freshly recomputed hash under v0.5.0.
Re-hash existing chains if you store hashes outside the receipt payload. See
ADR-0009 for the canonicalization profile.

### Features

- Add `parameters_disclosure: dict[str, str] | None` to the `Action` model,
  matching the spec change in [ADR-0012](https://github.com/agent-receipts/obsigna/blob/main/docs/adr/0012-payload-disclosure-policy.md)
  (commits `8caaba0`, `9fde2d5`). Operator-controlled, additive map of field
  name → stringified value that sits alongside `parameters_hash`. The hash
  continues to cover the full parameter set; `parameters_disclosure` exists
  for human/auditor display only.

  **Safety invariant.** Receipts are signed and durable — any value placed in
  `parameters_disclosure` is permanent and visible to anyone who can read the
  receipt. Callers MUST restrict keys to an explicit operator-managed
  allowlist and MUST NOT populate this field from raw tool arguments. The SDK
  does not auto-populate or validate this field; enforcement lives outside
  the SDK today (typically at the proxy/operator layer). Treat it the same
  way you would treat a log line that ships to long-term storage: never
  include secrets, credentials, tokens, PII, or any field whose value you
  have not deliberately classified as safe to retain.

### Bug Fixes

- **Canonicalization (ADR-0009):** fix UTF-16 sort key to use 16-bit code
  units (was sorting little-endian bytes), rewrite `_canonicalize_number` to
  match ES6 fixed/exp notation boundaries (1e-6 / 1e21) without `repr()`
  rounding drift, and uniformly strip optional `null` fields while preserving
  required-nullable `previous_receipt_hash`
  ([#86](https://github.com/agent-receipts/obsigna/issues/86), commit `70426b7`).
  See the **Hash compatibility note** above.
- Use `setdefault` so `previous_receipt_hash` is actually attached when
  building a chained receipt (commit `532b7f7`).
- Cover `-0.0` in number canonicalization, fix encoding/E501, drop dead code
  (commit `d252ad6`).
- Surface `verify_receipt` errors in `ChainVerification.error` instead of
  swallowing them ([#295](https://github.com/agent-receipts/obsigna/pull/295)).
- Surface `hash_receipt` errors in `ChainVerification.error` (commit
  `0b87ef4`).
- Spec: align `proofValue` encoding to base64url throughout, tighten the
  schema pattern, fix inline placeholders, and use 86-char base64url
  placeholder values in all examples (commits `fa0db6b`, `79f7301`,
  `0839e81`).

### Internal

- Narrow `Any` types in `_strip_optional_nulls` to satisfy pyright (commit
  `fd4c3d1`).

### Tests

- Add cross-SDK canonicalization vector test runner and populate
  `cross-sdk-tests/canonicalization_vectors.json` (commit `70426b7`).
- Cover `expected_final_hash` hash-error branch and fix docstring (commit
  `8c80fc5`).
- Add `parameters_disclosure` cross-language test vector (commit `60bbe51`).

### Documentation

- ADR-0009: canonicalisation profile + `issuanceDate` commitment (commits
  `dbb88fb`, `1511551`, `0d88ec7`, `ea24c49`).

### Dependencies

- Bump the `uv` group in `sdk/py/` (4 updates, commit `92cfeb7`).
