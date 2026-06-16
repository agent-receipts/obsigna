# Changelog

All notable changes to `agent-receipts-hook` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

> **This train has merged into the unified `obsigna` release train (ADR-0034, PR 2).**
> hook no longer releases on `hook/v*`. `obsigna-hook` and the `agent-receipts-hook`
> deprecation shim now ship in the `obsigna_<ver>_<os>_<arch>.tar.gz` archive and the
> `obsigna` Homebrew formula, versioned with the rest of the Go toolset. The hook returns
> to the umbrella formula (ADR-0034 decision 6 — it is non-functional without a co-located
> daemon), so there is no standalone hook formula: `agent-receipts-hook` and
> `agent-receipts-hook-alpha` migrate to `obsigna`/`obsigna-alpha` via the tap's
> `tap_migrations.json`. New entries are recorded in `daemon/CHANGELOG.md` (the obsigna
> train changelog) from here on; the per-module CI (Gate A + PR-side Gate B) still runs on
> changes here.

## [0.18.0] - 2026-06-13

Graduates `0.18.0-alpha.1` after the alpha pass. No code changes since the alpha; the only change is pinning the now-released stable `github.com/agent-receipts/ar/sdk/go` `v0.19.0` (the alpha pinned `v0.19.0-alpha.1`). See the `0.18.0-alpha.1` entry below for the full surface (the `agent-receipts-hook` → `obsigna-hook` binary rename, ADR-0036).

## [0.18.0-alpha.1] - 2026-06-13

### Changed

- **Binary renamed `agent-receipts-hook` → `obsigna-hook`** (ADR-0036) — the hook
  is now its own minimal binary at `cmd/obsigna-hook`, built reproducibly
  (`CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, pinned toolchain,
  commit-timestamped) and guarded by a fail-closed import graph (Gate A) so it
  stays a thin forwarder — the daemon remains the sole receipt writer (ADR-0010).
  The legacy `agent-receipts-hook` binary is now a thin deprecation shim that
  `syscall.Exec`s into `obsigna-hook`, forwarding argv/env unchanged, so **every
  existing runtime hook config keeps working** — update your `PostToolUse`/
  `PreToolUse` `command` to `obsigna-hook` when convenient; the shim will be
  removed in a future release. Unlike the daemon, mcp, and collector binaries,
  the hook gets no `obsigna hook run` launcher: it is a per-tool-call callback,
  and wrapping it would tax every event (ADR-0034 decision 5). Both binaries ship
  in the same archive and Homebrew formula (`agent-receipts-hook`, unchanged for
  now — formula/train consolidation is ADR-0034 PR 2).

## [0.17.0-alpha.1] - 2026-06-12

### Added

- **`action.target.resource` population from tool input** ([#784](https://github.com/agent-receipts/obsigna/pull/784), ADR-0029) — `extractFileTarget` parses `file_path` from Claude Code tool input and forwards `target_system: "filesystem"` + `target_resource: "<path>"` in the emitter frame. Opportunistic heuristic: skip-listed tools (`Bash`, `Agent`, `WebFetch`, `WebSearch`) and MCP-namespaced tools are ignored; all other tools are attempted so new filesystem tools are auto-captured. Known file tools (`Read`, `Write`, `Edit`, `MultiEdit`) emit a stderr warning when `file_path` is absent (schema-drift signal). Whitespace-only paths are treated as absent; malformed JSON is silently skipped.

### Dependencies

- Pin `github.com/agent-receipts/ar/sdk/go` to `v0.19.0-alpha.1` (provides `emitter.Target`, `MaxTargetResourceLen`, and client-side XOR + length validation).

## [0.16.0-alpha.1] - 2026-06-11

### Added

- **Transcript-derived model and token usage** ([#779](https://github.com/agent-receipts/obsigna/pull/779), ADR-0026) — `lookupTranscriptUsage` streams the Claude Code session transcript JSONL and joins on `tool_use_id` to resolve the model name and token counts for each tool call. Best-effort: a missing entry or read error is logged to stderr but never fails the hook. The resolved `model`, `usage` (verbatim JSON), and `capture_method: "transcript"` are forwarded in the emitter frame; the daemon stamps them into `issuer.runtime` on the receipt.

### Dependencies

- Pin `github.com/agent-receipts/ar/sdk/go` to `v0.18.0-alpha.1` (provides the `receipt.Runtime` typed fields).

## [0.15.0] - 2026-06-11

Graduates `0.15.0-alpha.1` after the alpha pass. No code changes since the alpha; the only change is pinning the now-released stable `github.com/agent-receipts/ar/sdk/go` `v0.17.0` (the alpha pinned `v0.17.0-alpha.1`). See the `0.15.0-alpha.1` entry below for the full surface (`agent_type` forwarding).

## [0.15.0-alpha.1] - 2026-06-09

### Added

- **`agent_type` forwarding** ([#761](https://github.com/agent-receipts/obsigna/pull/761), ADR-0026) — the Claude Code hook now parses `agent_type` from the PostToolUse payload and forwards it to the emitter alongside the existing `agent_id`. The daemon nests both under `issuer.runtime`.

### Changed

- Pin `github.com/agent-receipts/ar/sdk/go` to `v0.17.0-alpha.1` (carries the `agent_type` emitter field).

## [0.14.0] - 2026-06-09

Graduates `0.14.0-alpha.1` after the alpha pass. No code changes since the alpha; the only change is pinning the now-released stable `github.com/agent-receipts/ar/sdk/go` `v0.16.0` (the alpha pinned `v0.16.0-alpha.1`). See the `0.14.0-alpha.1` entry below for the full surface (`agent_id` and `correlation_id` forwarding).

## [0.14.0-alpha.1] - 2026-06-08

### Added

- **`agent_id` forwarding** ([#753](https://github.com/agent-receipts/obsigna/pull/753)) — Claude Code sends a distinct `agent_id` per subagent in hook payloads. The hook now parses this field from the `claudeCodeFrame` and sets it on `emitter.Event.AgentID`, enabling the daemon to route subagent frames to per-agent chains and attach delegation backlinks.
- **`correlation_id` forwarding** ([#752](https://github.com/agent-receipts/obsigna/pull/752)) — the hook now reads `tool_use_id` from the Claude Code payload and forwards it as `Event.CorrelationID`. This links every pre-check receipt to the corresponding post-action receipt emitted by the MCP proxy for the same tool invocation.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.16.0-alpha.1`.

## [0.13.0] - 2026-06-01

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.14.0` (response hash, redaction patterns, HPKE forensic key helpers, action-type forwarding).

## [0.12.0] - 2026-05-24

### Changed

- **macOS default socket path moved off `$TMPDIR`** ([#545](https://github.com/agent-receipts/obsigna/issues/545)) — inherited from the SDK's updated `emitter.DefaultSocketPath`: the hook now resolves to `$XDG_DATA_HOME/agent-receipts/events.sock` (defaulting to `~/.local/share/agent-receipts/events.sock`) instead of `$TMPDIR/agentreceipts/events.sock`. Avoids the silent path mismatch when the hook is spawned by a process that does not propagate TMPDIR (e.g., a GUI host). Operators on macOS should restart the daemon so both sides resolve to the same path.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.13.0` (PeerCredential `*uint32`, WalEmitter, AWS KMS adapter, `store.Exists`, safe socket path enforcement, idempotency_key).

## [0.11.1] - 2026-05-23

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.12.1` (HttpEmitter + Emitter interface, macOS socket path default).

## [0.11.0] - 2026-05-22

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.11.0` (v0.3.0 spec migration: HPKE disclosure envelope, PeerCredential, EmitterMetadata — no hook behaviour change).

## [0.10.0] - 2026-05-16

### Added

- **PreToolUse support** ([#415](https://github.com/agent-receipts/obsigna/pull/415)):
  The hook now handles `hook_event_name: "PreToolUse"` payloads in addition to
  `"PostToolUse"`. PreToolUse frames emit a receipt with `decision: "pending"`;
  PostToolUse frames continue to emit `decision: "allowed"`. Configure both in
  `~/.claude/settings.json` to capture full intent + outcome pairs, or use
  either event in isolation.

### Fixed

- **Claude Code runtime detection** ([#411](https://github.com/agent-receipts/obsigna/pull/411)):
  Claude Code does not set `CLAUDE_SESSION_ID` as an environment variable —
  it passes `hook_event_name` in the stdin JSON payload instead. The previous
  detection check looked only at the env var, so every invocation was silently
  dropped as an unknown runtime. Detection now checks the payload for
  `hook_event_name: "PostToolUse"` or `"PreToolUse"` and falls back to the
  env var for forward compatibility.

### Changed

- **Fail hard once runtime is identified** ([#415](https://github.com/agent-receipts/obsigna/pull/415)):
  All error paths after format detection now exit 1 with a message to stderr
  instead of silent exit 0. Affected cases: unsupported format string,
  unparseable payload (schema change), `emitter.New()` failure, and
  `Emit()` failure (daemon unreachable, using `WithStrictErrors()`). The only
  remaining silent exit 0 path is unrecognised runtime — not our concern.

## [0.9.0] - 2026-05-16

### Changed

- **Extracted into its own Go module** ([#405](https://github.com/agent-receipts/obsigna/issues/405),
  [#407](https://github.com/agent-receipts/obsigna/pull/407)):
  `agent-receipts-hook` now lives at `github.com/agent-receipts/ar/hook` and is
  released independently of the daemon. Install path:
  `brew install agent-receipts/tap/agent-receipts-hook` or
  `go install github.com/agent-receipts/ar/hook/cmd/agent-receipts-hook@latest`.
