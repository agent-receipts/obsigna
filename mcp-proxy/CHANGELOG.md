# Changelog

All notable changes to mcp-proxy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.6.2; earlier releases are recorded only in git history.
A repo-wide effort to auto-generate changelogs from Conventional Commits is
tracked in [#253](https://github.com/agent-receipts/obsigna/issues/253).

## [Unreleased]

> **This train has merged into the unified `obsigna` release train (ADR-0034, PR 2).**
> mcp-proxy no longer releases on `mcp-proxy/v*`. `obsigna-mcp` and the `mcp-proxy`
> deprecation shim now ship in the `obsigna_<ver>_<os>_<arch>.tar.gz` archive and the
> `obsigna` Homebrew formula, versioned with the rest of the Go toolset. The `mcp-proxy`
> and `mcp-proxy-alpha` formulae migrate to `obsigna`/`obsigna-alpha` via the tap's
> `tap_migrations.json`. New entries are recorded in `daemon/CHANGELOG.md` (the obsigna
> train changelog) from here on; the per-module CI (Gate A + PR-side Gate B) still runs
> on changes here.

## [0.15.0-alpha.2] - 2026-06-13

### Fixed

- **Pin `sdk/go` to a published version that matches the code (v0.15.0 → v0.17.0).** The
  proxy uses `emitter.Event.CorrelationID` (added to `sdk/go` in v0.16.0), but `go.mod`
  still pinned v0.15.0. Prior releases built against the in-tree workspace `sdk/go` (via
  `go.work`), masking the stale pin; once the release build was switched to published deps
  (`GOWORK=off`, ADR-0033 Gate B), it failed to compile. Bumping the pin makes the proxy
  genuinely buildable from its declared published dependencies. (Supersedes the
  `0.15.0-alpha.1` tag, which failed to release for this reason.)

### Changed

- **Binary renamed `mcp-proxy` → `obsigna-mcp` (ADR-0033).** The proxy is now its own
  minimal binary, `obsigna-mcp`, launched in production via `obsigna mcp run` (ADR-0030),
  which `syscall.Exec`s straight into it. **Breaking for installers and MCP client configs
  that invoke the binary by an absolute path to a renamed file.** A thin `mcp-proxy`
  deprecation shim ships alongside `obsigna-mcp` and exec-forwards to it, so the common
  `$(which mcp-proxy)` invocation and existing configs keep working — update them to
  `obsigna-mcp` (or `obsigna mcp run`) when convenient; the shim will be removed in a
  future release. The Homebrew formula names (`mcp-proxy`, `mcp-proxy-alpha`) are unchanged;
  both binaries are installed.

### Added

- **Gate A — thin-emitter import graph (ADR-0033).** A CI-enforced test asserts
  `obsigna-mcp`'s production import graph never reaches the receipt store, a SQLite driver,
  receipt signing, or the daemon library, making ADR-0010's "daemon is the sole writer"
  boundary structural.
- **Gate B — reproducible builds (ADR-0033).** `obsigna-mcp` is now built with `-trimpath`,
  `-buildvcs=false`, `mod_timestamp`, and a patch-pinned toolchain; CI proves byte-identical
  rebuilds across paths on every PR and attests the released binary against an independent
  rebuild on release.

## [0.14.0] - 2026-06-09

Graduates `0.14.0-alpha.1` after the alpha pass. No source changes since the alpha; see the `0.14.0-alpha.1` entry below for the full surface (`correlation_id` and `agent_id` forwarding, delegation receipts).

## [0.14.0-alpha.1] - 2026-06-09

### Added

- **`correlation_id` forwarded from Claude Code hook payloads** ([#752](https://github.com/agent-receipts/obsigna/pull/752)) — the proxy now extracts `_meta["claudecode/toolUseId"]` from `tools/call` params and stamps it as `correlation_id` on the emitted receipt, linking the proxy post-action receipt to the hook pre-check receipt for the same tool call.
- **`agent_id` forwarding and delegation receipts** ([#753](https://github.com/agent-receipts/obsigna/pull/753)) — the proxy forwards `agent_id` from hook payloads; subagent chains carry `delegation.parent_chain_id`, `delegation.parent_receipt_id`, and `delegation.delegator.id` on their first receipt, enabling full attribution trees across orchestrator and subagent sessions.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.15.0` (HPKE parameter disclosure, correlation_id and agent_id types).
- Bump `github.com/agent-receipts/ar/daemon` to `v0.16.0`.

## [0.13.0] - 2026-06-01

### Added

- **Graceful shutdown on SIGINT/SIGTERM** ([#690](https://github.com/agent-receipts/obsigna/pull/690)) — the proxy now handles signals and shuts down cleanly, draining in-flight tool calls before exiting.
- **Fail fast when approval server dies mid-session** ([#693](https://github.com/agent-receipts/obsigna/pull/693)) — if the HTTP approval listener dies unexpectedly, the proxy now surfaces the error immediately rather than hanging on the next pause rule.
- **Warn on world-accessible `~/.agent-receipts`** ([#682](https://github.com/agent-receipts/obsigna/pull/682)) — logs a warning at startup if the receipt directory has permissions broader than 0700.
- **Env-marker secondary host detection** ([#674](https://github.com/agent-receipts/obsigna/pull/674)) — secondary host environment detection for issuer identity stamping, driven by env-var markers.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.14.0` (emit failure contract, GeneratingKeyProvider production guard, ReceiptChain).
- Bump `github.com/agent-receipts/ar/daemon` to `v0.13.0`.

## [0.12.0] - 2026-05-24

### Added

- **Daemon enforces safe socket paths** ([#579](https://github.com/agent-receipts/obsigna/pull/579), closes [#538](https://github.com/agent-receipts/obsigna/issues/538)) — daemon v0.13.0 now rejects socket path overrides outside the per-platform safe set at startup (requires `--unsafe-socket-path` to override) and unconditionally rejects TCP addresses. If the proxy's `--socket` / `AGENTRECEIPTS_SOCKET` setting violates these rules, the daemon will refuse to start and the proxy will be unable to deliver receipts.
- **`action.idempotency_key` forwarded from JSON-RPC request id** ([#565](https://github.com/agent-receipts/obsigna/pull/565)) — the proxy now forwards the `id` field of the wrapped JSON-RPC request as `idempotency_key` in the emitter frame. The daemon enforces a 256-byte limit. Requires daemon v0.13.0 and spec v0.4.0.

### Changed

- **macOS `--socket` default moved off `$TMPDIR`** ([#545](https://github.com/agent-receipts/obsigna/issues/545)) — the default is now `$XDG_DATA_HOME/agent-receipts/events.sock` (defaulting to `~/.local/share/agent-receipts/events.sock`), inherited from the SDK's updated `emitter.DefaultSocketPath`. The previous TMPDIR-based default produced a silent receipt-loss mismatch when the proxy was spawned without TMPDIR (typical for MCP servers launched by GUI hosts such as Claude Desktop). Operators upgrading on macOS must restart both the proxy and daemon; anyone relying on TMPDIR redirection should switch to `AGENTRECEIPTS_SOCKET=…`.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.13.0`.
- Bump `github.com/agent-receipts/ar/daemon` to `v0.13.0`.

## [0.11.1] - 2026-05-23

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.12.1` (HttpEmitter + Emitter interface; changes default `--socket` path on macOS — no proxy code changes).

## [0.11.0] - 2026-05-22

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.11.0` and `github.com/agent-receipts/ar/daemon` to `v0.12.0` (v0.3.0 spec migration: HPKE disclosure envelope, PeerCredential, EmitterMetadata — no proxy code changes).

## [0.10.0] - 2026-05-19

### Added

- **Issuer/operator identity on receipts**: auto-detect the host that launched the proxy (Claude Code, Codex, Cursor, Windsurf) from the parent process name on Linux, and stamp `receipt.Issuer.Name`, `receipt.Issuer.Model`, and `receipt.Issuer.Operator` on every emitted receipt. Override or supplement auto-detection with `--issuer-name`, `--issuer-model`, `--operator-id`, `--operator-name` flags (or the matching `AGENTRECEIPTS_*` env vars).

## [0.9.0] - 2026-05-18

### Removed (breaking)

- **Local `audit.db` and parallel redaction/encryption layer**
  ([#453](https://github.com/agent-receipts/obsigna/issues/453)). Finishes the
  thin-emitter migration started in
  [#421](https://github.com/agent-receipts/obsigna/pull/421): the proxy no longer
  maintains its own SQLite store and no longer redacts or encrypts at rest.
  The daemon is the sole writer and the sole redactor.
  - Deleted packages: `internal/audit/{store,redact,redact_config,encrypt,intent}.go`
    and their tests (~2500 LoC).
  - Deleted CLI subcommand stubs (already deprecated in v0.8.0):
    `mcp-proxy list/inspect/verify/export/stats/timing/audit-secrets`. Use
    `agent-receipts list/verify` instead.
  - Removed flags: `-db`, `-redact-patterns`. The proxy no longer accepts
    these; passing them now exits with `flag provided but not defined`.
  - Removed env var: `BEACON_ENCRYPTION_KEY` (the proxy had no remaining
    at-rest data to encrypt once `audit.db` went away).
  - Rejected tool calls (policy `block` and approval `deny/timeout`) are
    still audited — the proxy already emits `Decision: "denied"` to the
    daemon for these, so the daemon mints receipts for them.

### Changed

- **Startup nudge for legacy `audit.db`**: if
  `$XDG_DATA_HOME/agent-receipts/audit.db` is present on serve startup, the
  proxy logs one `[INFO]` line stating the file is no longer used and is
  safe to delete. The proxy does NOT remove it — operators may want to
  archive or inspect it first. Receipts going forward live in the daemon's
  store (`agent-receipts list`).

### Migration

Operators upgrading from <0.9.0:
- Remove `-db` / `-redact-patterns` / `BEACON_ENCRYPTION_KEY` from any
  config snippets, systemd units, or wrapper scripts.
- Delete `~/.local/share/agent-receipts/audit.db` (or wherever
  `$XDG_DATA_HOME` resolved) at your leisure — the daemon's store at the
  same directory continues to be authoritative.
- If you were relying on `mcp-proxy list/inspect/verify/export/stats/timing`
  output, switch to the equivalent `agent-receipts` CLI commands shipped
  with the daemon.

## [0.8.0] - 2026-05-15

### Tests

- Improved proxy test coverage from 32.7% to 69.1% and socket handler coverage
  from 50.9% to 81.1%; fixed concurrent test timeout flakiness
  ([#376](https://github.com/agent-receipts/obsigna/issues/376)).

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` from `v0.8.0-alpha.1` to `v0.8.0`.

## [0.8.0-alpha.1] - 2026-05-09

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` from `v0.6.0` to `v0.8.0-alpha.1`.

## [0.7.0] - 2026-05-01

### Features

- **Guided `init` command** (`mcp-proxy init`) walks the operator through
  one-command setup: generates an Ed25519 signing key, writes a starter
  `config.yaml`, and prints the shell snippet to wire it into the MCP client
  config. Key files are written with restrictive permissions (0600) from the
  first write. Detailed `os.Stat` error handling and `ReadFile` error paths
  are covered by tests (commits `d463126`, `64b9f5a`, `46bcd93`, `60e7280`,
  `578ef68`).

- **Restrictive file permissions on signing keys**
  ([#156](https://github.com/agent-receipts/obsigna/issues/156)): `writePrivateKeyFile`
  now creates key files with mode `0600` and rejects existing files whose
  permissions are too open. `Close` errors on write failure are propagated
  rather than silently discarded (commits `3ab4912`, `0927c90`, `8148748`,
  `d323ca9`, `5a1b94e`, `b7725d8`).

- **Expanded secret redaction and `audit-secrets` scan**: the secret redaction
  pattern set is broadened to cover additional token formats; a CI
  `audit-secrets` scan is added to catch regressions (commits `de790cb`,
  `000ae5b`, `89ce066`, `e825d22`).

### Bug Fixes

- Coordinate stdio shutdown to surface upstream server death: the proxy now
  detects when the upstream MCP server exits and propagates the termination
  signal cleanly instead of hanging
  ([#158](https://github.com/agent-receipts/obsigna/issues/158), commit `9a0fd20`).

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` from `v0.5.0` to `v0.6.0`,
  picking up `ParametersDisclosure` on `Action` and the `VerifyChain`
  hash-error surfacing fix.

### Tests

- Guard parallel-test cleanup against double `cmd.Wait` (commit `af58f46`).

[0.7.0]: https://github.com/agent-receipts/obsigna/compare/mcp-proxy/v0.6.2...mcp-proxy/v0.7.0

## [0.6.2] - 2026-04-29

### Changed

- Default of `-http` flag flipped from `127.0.0.1:0` to `none`; the approval
  HTTP listener is now opt-in. Pause rules still load and evaluate; an unwired
  pause fails fast with JSON-RPC code `-32003` ("no approver configured")
  instead of waiting 60s for a timeout. See
  [#266](https://github.com/agent-receipts/obsigna/pull/266) and
  [#262](https://github.com/agent-receipts/obsigna/issues/262).

- Startup banner softened. The default-off case (operator did not pass `-http`)
  now emits an `[INFO]` line with a soft "approver off by default; pass -http
  `<addr>` to enable" hint, instead of a `[WARN]`. Explicit `-http=none` is
  treated as an informed opt-out (no hint, no warn). The `[WARN]` path remains
  for the unusual misconfiguration case.

### Fixed

- Bind failure on `-http <addr>` no longer `log.Fatalf`s with a cryptic
  `bind: address already in use`. Now prints an actionable error naming the
  address and offering both `-http 127.0.0.1:0` (random port) and `-http=none`
  (disable) as remediations, then exits non-zero. Closes
  [#262](https://github.com/agent-receipts/obsigna/issues/262).

[0.8.0]: https://github.com/agent-receipts/obsigna/releases/tag/mcp-proxy%2Fv0.8.0
[0.8.0-alpha.1]: https://github.com/agent-receipts/obsigna/releases/tag/mcp-proxy%2Fv0.8.0-alpha.1
[0.6.2]: https://github.com/agent-receipts/obsigna/compare/mcp-proxy/v0.6.1...mcp-proxy/v0.6.2
