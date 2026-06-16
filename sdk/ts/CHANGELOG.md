# Changelog

All notable changes to `@obsigna/sdk-ts` (formerly `@agnt-rcpt/sdk-ts`) are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.5.0; earlier releases are recorded only in git history.
A repo-wide effort to auto-generate changelogs from Conventional Commits is
tracked in [#253](https://github.com/agent-receipts/obsigna/issues/253).

## [Unreleased]

## [0.14.1] - 2026-06-16

### Added

- **`@obsigna/sdk-ts/emitter` subpath export** — exposes `DaemonEmitter` and its frame types (`EmitEvent`, `EmitTool`, `DaemonEmitterOptions`, `EmitTransportError`, `defaultSocketPath`, …) from `daemon-emitter.js` directly, without pulling in the package barrel. The barrel re-exports the SQLite-backed store (`node:sqlite`) and the HTTP/WAL emitters (`undici`); importing it forces those into a consumer's bundle even when only the daemon emitter is used. Emitter-only consumers that bundle for restricted runtimes — notably the OpenCode plugin, whose loader could not resolve `node:sqlite` — should import from `@obsigna/sdk-ts/emitter`. Additive; the main entry point is unchanged.

## [0.14.0] - 2026-06-16

### Added

- **`EmitEvent.actionType`** — new optional field on the `DaemonEmitter` frame, forwarded to the daemon as `action_type`. When set, the daemon uses it verbatim as `action.type` and resolves `risk_level` from the taxonomy, rather than falling back to the synthetic `"<channel>.<tool>"` type (which defaults risk to medium). Lets emitters that already know the taxonomic action type — such as the OpenCode plugin — make risk-based controls effective. The daemon already accepted this frame field; this exposes it through the TS emitter. Additive and backwards-compatible: omitting it preserves the previous behaviour.

## [0.13.0] - 2026-06-12

Graduates `0.13.0-alpha.1` after the alpha pass. The `@obsigna/sdk-ts` rename ships with this stable release (no source changes since the alpha); see the `0.13.0-alpha.1` entry below for the `KeyRotation` surface.

### Changed

- **Package renamed to `@obsigna/sdk-ts`** (was `@agnt-rcpt/sdk-ts`). The import
  surface, exports, and subpath entry points are unchanged — only the package
  name moves to the `@obsigna` scope. The legacy `@agnt-rcpt/sdk-ts` package
  remains published and is deprecated on npm pointing at the new name; existing
  installs keep working. Update imports to `@obsigna/sdk-ts`.

## [0.13.0-alpha.1] - 2026-06-11

### Added

- **`KeyRotation` type and chain-verifier traversal** ([#778](https://github.com/agent-receipts/obsigna/pull/778), ADR-0015 Phase A) — new `KeyRotation` interface added to `CredentialSubject.keyRotation?: KeyRotation`. `verifyChain` now traverses key-rotation receipts: the outgoing key verifies the `key_rotated` receipt, then the inline `new_public_key` takes over for all subsequent receipts. Fingerprint mismatches and unsupported algorithms are hard errors. Zod schema and TypeScript types updated; cross-SDK wire vector verified.

### Dependencies

- No new external dependencies.
## [0.12.0] - 2026-06-09

Graduates `0.12.0-alpha.1` after the alpha pass. No source changes since the alpha; see the `0.12.0-alpha.1` entry below for the full surface (`Delegation` type and `correlation_id`).

## [0.12.0-alpha.1] - 2026-06-08

### Added

- **`Delegation` type** ([#753](https://github.com/agent-receipts/obsigna/pull/753)) — new `Delegation` interface with `parent_chain_id: string`, `parent_receipt_id: string`, and `delegator: { id: string }`. Added to `CredentialSubject.delegation?: Delegation` and `CreateInput.delegation?: Delegation`. Enables the daemon to attach a verifiable chain backlink to the first receipt on every subagent chain. Zod schema and TypeScript types updated; cross-SDK canonicalisation vectors added.
- **`CredentialSubject.correlation_id`** ([#752](https://github.com/agent-receipts/obsigna/pull/752)) — new optional `correlation_id?: string` field linking the pre-check and post-action receipts for a single tool invocation.

## [0.11.1] - 2026-06-03

### Added

- **`DAEMON_PROTOCOL_RANGE` re-export** ([#655](https://github.com/agent-receipts/obsigna/pull/655), Gate #8). Exposes the SDK's declared daemon-protocol version range (`{ min: 1, max: 1 }`) at the package root so the release-time daemon ↔ SDK compatibility check (`scripts/daemon_protocol/check.py`) can read it. The constant was added in source for 0.11.0 but merged to main after the 0.11.0 tag was cut, so the published 0.11.0 package did not include it — this release publishes the export.

## [0.11.0] - 2026-06-02

### Breaking Changes

- **`DaemonEmitter.emit` surfaces transport failure by default** ([#599](https://github.com/agent-receipts/obsigna/issues/599), ADR-0025). When the daemon is unreachable or a write fails, `emit()` now resolves with the new `EmitTransportError` (a subclass of `Error`, exported from the package root) instead of `null`. Check `err instanceof EmitTransportError` to distinguish it from the plain `Error` returned for caller bugs. Pass `bestEffort: true` to the constructor to opt back into loss-tolerant emission (`emit()` resolves with `null` on transport failure).

### Added

- **`ReceiptChain`** ([#488](https://github.com/agent-receipts/obsigna/issues/488), ADR-0020). Stateful, serialised builder for a single hash-linked chain, exported from the package root with its options (`ReceiptChainOptions`) and per-receipt input type (`ReceiptChainEmitInput`). It owns the chain head (`sequence` + `previous_receipt_hash`) and runs build → sign → hash → link → deliver through an internal promise queue, so concurrent `emit()` calls are sequenced at the receipt layer even when the tool calls that triggered them ran in parallel. The first overlapping call fires a one-shot warning (`console.warn` by default; override via `onConcurrentEmit`). The head advances before delivery so a transient emitter failure cannot fork or stall the chain. Parallel sub-chains remain out of scope for v1.

### Changed

- **Dropped the `@hpke/core` runtime dependency** ([#473](https://github.com/agent-receipts/obsigna/issues/473)). The HPKE disclosure envelope (`encryptDisclosure` / `decryptDisclosure` / `generateForensicKeyPair`) now uses an in-tree RFC 9180 base-mode implementation built on `node:crypto` (`src/receipt/hpke.ts`), removing a third-party crypto dependency from a cryptographic protocol's supply chain. The public API and the on-the-wire envelope are unchanged — the deterministic cross-SDK test vectors still pass byte-for-byte.

## [0.10.0] - 2026-05-24

Implements spec v0.4.0 (`action.idempotency_key`), the ADR-0020 emitter interface redesign (WAL, HTTP, composite, in-memory), and aligns `peer_credential` uid/gid types with the Go SDK. Two breaking changes.

### Breaking Changes

- **`Emitter` class renamed to `DaemonEmitter`** ([#548](https://github.com/agent-receipts/obsigna/pull/548)). The existing `Emitter` class (Unix-socket fire-and-forget emitter) is now exported as `DaemonEmitter`. The name `Emitter` is now the new interface (see Added). Update all import sites: `import { DaemonEmitter } from "@agnt-rcpt/sdk-ts"`.
- **`peer_credential.uid` and `peer_credential.gid` are now `number | undefined`** ([#580](https://github.com/agent-receipts/obsigna/pull/580)). Previously typed as `number`, they are now optional to align with the Go SDK's `*uint32` — UID=0 (root) is a valid identity and must be distinguishable from "no UID concept on this platform". Code that assumed these fields are always present must add a presence check.

### Added

- **`Emitter` interface** ([#548](https://github.com/agent-receipts/obsigna/pull/548)) — new top-level interface accepted by all emitter consumers. Takes a signed `AgentReceipt` and returns `Promise<void>`. Implement it to supply custom delivery backends.
- **`HttpEmitter`** ([#548](https://github.com/agent-receipts/obsigna/pull/548)) — posts receipts to an HTTP endpoint. Implements `Emitter`.
- **`CompositeEmitter`** ([#548](https://github.com/agent-receipts/obsigna/pull/548)) — fans out to multiple `Emitter` instances sequentially; always attempts every child and collects failures. Implements `Emitter`.
- **`BufferingEmitter`** ([#548](https://github.com/agent-receipts/obsigna/pull/548)) — accumulates receipts and flushes in configurable batches. Implements `Emitter`.
- **`InMemoryEmitter`** ([#548](https://github.com/agent-receipts/obsigna/pull/548)) — holds receipts in memory; useful for testing. Implements `Emitter`.
- **`WalEmitter`** ([#567](https://github.com/agent-receipts/obsigna/pull/567)) — wraps any `Emitter` and records each receipt in a write-ahead log before delivery, providing at-least-once delivery guarantees. Supports file-backed (durable) and in-memory backends (ADR-0020).
- **`Action.idempotency_key`** ([#565](https://github.com/agent-receipts/obsigna/pull/565)) — optional string field for deduplication. Chain verifiers surface duplicate values as non-fatal warnings. Part of spec v0.4.0.

### Changed

- **`VERSION` constant bumped to `"0.4.0"`** ([#565](https://github.com/agent-receipts/obsigna/pull/565)) — receipts emitted via `createReceipt()` now stamp the v0.4.0 schema label.
- **`defaultSocketPath()` macOS default is now HOME-based** ([#545](https://github.com/agent-receipts/obsigna/issues/545)). macOS resolves to `$XDG_DATA_HOME/agent-receipts/events.sock` (defaulting to `~/.local/share/agent-receipts/events.sock`) instead of `$TMPDIR/agentreceipts/events.sock`. TMPDIR is not inherited by GUI-spawned Node processes (e.g., MCP servers launched by Claude Desktop), which broke the daemon ↔ emitter handshake silently. The Go and Python SDKs ship the same resolution so every emitter and the daemon agree on a single path per user. AGENTRECEIPTS_SOCKET continues to take precedence; users who relied on TMPDIR redirection should switch to it.

## [0.9.0] - 2026-05-22

First stable release of the v0.3.0 spec migration (ADR-0012 Phase A). Tracked in [#280](https://github.com/agent-receipts/obsigna/issues/280). Graduates `0.9.0-alpha.1` after the end-to-end alpha pass in [#519](https://github.com/agent-receipts/obsigna/issues/519).

### Added

- **Forensic disclosure API re-exported from package root** ([#526](https://github.com/agent-receipts/obsigna/issues/526)) — `encryptDisclosure`, `decryptDisclosure`, `generateForensicKeyPair`, `DisclosureEnvelope`, `DisclosureRecipient`, and `ForensicKeyPair` are now importable from `@agnt-rcpt/sdk-ts` directly, not just from `@agnt-rcpt/sdk-ts/receipt`. Brings the headline v0.3.0 forensic-disclosure API in line with the other top-level re-exports (`createReceipt`, `signReceipt`, `verifyReceipt`, etc.).

No source changes since `0.9.0-alpha.1` other than the root re-export above. See the `0.9.0-alpha.1` entry below for the full v0.3.0 surface.

## [0.9.0-alpha.1] - 2026-05-22

First pre-release of the v0.3.0 spec migration (ADR-0012 Phase A). Tracked in [#280](https://github.com/agent-receipts/obsigna/issues/280).

### Breaking Changes

- **`Action.parameters_disclosure` shape changed** to the HPKE asymmetric encryption envelope. Was `Record<string, string>` (legacy flat-map), now `DisclosureEnvelope | undefined`. Downstream code that constructed the legacy flat-map will not type-check. See [#503](https://github.com/agent-receipts/obsigna/pull/503).

### Added

- **`encryptDisclosure` / `decryptDisclosure` / `generateForensicKeyPair`** ([#472](https://github.com/agent-receipts/obsigna/pull/472)) — RFC 9180 HPKE base-mode helpers (DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM) for the v1 disclosure envelope. Currently uses `@hpke/core`; full removal tracked in [#473](https://github.com/agent-receipts/obsigna/issues/473).
- **`Action.peer_credential`** — typed OS-attested peer process metadata (`platform`, `pid`, optional `uid`/`gid`/`exe_path`). Populated by the daemon at the SDK↔daemon boundary.
- **`Action.emitter_metadata`** — daemon-observed emitter-side metadata, currently `drop_count` for synthetic `events_dropped` receipts.
- **Stricter zod validation** on `parameters_disclosure` envelope — `enc` must be exactly 43 unpadded base64url chars; `ct` must match the unpadded base64url alphabet AND have decodable length (`len % 4 !== 1`).
- **Cross-SDK live-emit invariant test** ([#515](https://github.com/agent-receipts/obsigna/pull/515)).

### Changed

- **`VERSION` constant bumped from `"0.2.0"` to `"0.3.0"`** ([#515](https://github.com/agent-receipts/obsigna/pull/515)) — receipts emitted via `createReceipt()` now stamp the v0.3.0 schema label.
- The Zod `agentReceiptSchema` now strictly requires the envelope shape on `parameters_disclosure`. Legacy v0.2.x flat-map receipts will fail `agentReceiptSchema.parse()` — including every `ReceiptStore` load method (`getById`, `getChain`, `query`, `verifyStoredChain`) which validates via this schema internally. Verifiers ingesting legacy receipts must use raw spec-schema validation instead.

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

- Fire-and-forget emitter for forwarding tool-call events to the
  `agent-receipts-daemon` Unix socket (ADR-0010, [#236](https://github.com/agent-receipts/obsigna/issues/236)).
  No crypto, no canonicalisation — the daemon handles those operations.

## [0.6.0] - 2026-05-01

### Breaking Changes

- **Renamed `parameters_preview` → `parameters_disclosure`** on the `Action`
  interface and its Zod schema. Per
  [ADR-0012](https://github.com/agent-receipts/obsigna/blob/main/docs/adr/0012-payload-disclosure-policy.md),
  "preview" misdescribed a permanent, signed field — receipts are durable, so
  any value placed there is a deliberate disclosure rather than a transient
  preview. The shape is unchanged (`Record<string, string>`); only the field
  name moved. **No deprecation alias is provided. Update all call sites
  before upgrading.** Pre-1.0 adoption is low and the rename is intentionally
  a clean break. Tracking issue:
  [#283](https://github.com/agent-receipts/obsigna/issues/283).

  Migration: rename every read/write of `action.parameters_preview` to
  `action.parameters_disclosure`. Previously written receipts that carry the
  old key under `.passthrough()` will still load, but new receipts MUST use
  the new key to round-trip through this SDK's typed surface.

### Features

- Add `parameters_disclosure` to the `Action` schema in the protocol spec
  (commits `2fd1837`, `5ef9d9a`, `e43cd06`).

### Bug Fixes

- Surface `verifyReceipt` errors in `ChainVerification.error` instead of
  swallowing them ([#294](https://github.com/agent-receipts/obsigna/pull/294)).
- Surface `hashReceipt` errors in `ChainVerification.error`
  ([#270](https://github.com/agent-receipts/obsigna/issues/270), commits `6a97840`,
  `bf030de`).
- Validate receipt schema on load from store, preserve unknown fields, tighten
  validator types, preserve `Error.cause`, and render the root path on parse
  failures ([#170](https://github.com/agent-receipts/obsigna/issues/170), commits
  `2db99c6`, `b273e50`, `01f5745`).
- Spec: align `proofValue` encoding to base64url throughout, tighten the
  schema pattern, fix inline placeholders, and use 86-char base64url
  placeholder values in all examples (commits `fa0db6b`, `79f7301`,
  `0839e81`).

### Tests

- Add `parameters_disclosure` cross-language test vector in
  `cross-sdk-tests/` (commit `60bbe51`).

## [0.5.0] - 2026-04-27

### Added

- `parameters_preview?: Record<string, string>` field on the `Action` interface.
  An operator-controlled, additive map of field name → stringified value that
  sits alongside the existing `parameters_hash`. The hash continues to cover
  the full parameter set; the preview exists for human/auditor display only.

  **Safety invariant.** Receipts are signed and durable — any value placed in
  `parameters_preview` is permanent and visible to anyone who can read the
  receipt. Callers MUST restrict keys to an explicit operator-managed allowlist
  and MUST NOT populate this field from raw tool arguments. The SDK does not
  auto-populate or validate this field; enforcement lives outside the SDK
  today (typically at the proxy/operator layer). Taxonomy-level allowlist
  support is tracked in
  [#258](https://github.com/agent-receipts/obsigna/issues/258).
  Treat it the same way you would treat a log line that ships to long-term
  storage: never include secrets, credentials, tokens, PII, or any field
  whose value you have not deliberately classified as safe to retain.
