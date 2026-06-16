# Changelog

All notable changes to `@obsigna/opencode-plugin` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.3] - 2026-06-16

First version OpenCode can actually load (alpha.1/alpha.2 could not — see Fixed).

### Fixed

- **OpenCode can now load the plugin.** Three problems blocked it when installed from npm:
  - **`node:sqlite` in the import graph.** The recorder imported `DaemonEmitter` from the `@obsigna/sdk-ts` barrel, which re-exports the SQLite store (`node:sqlite`) and undici; opencode's loader could not resolve `node:sqlite`. Now imports from the `@obsigna/sdk-ts/emitter` subpath (added in sdk-ts 0.14.1), which pulls only the daemon emitter — no `node:sqlite`/undici. Dependency bumped to `^0.14.1`.
  - **No server entry point.** opencode resolves `server` plugins via `exports["./server"]` (or `main`); the package exposed neither. Added a `./server` export (and `main`) pointing at a dedicated entry.
  - **Entry exported non-function values.** The library barrel exports `DEFAULT_ACTION_MAP`, `ReceiptRecorder`, config helpers, etc.; opencode's legacy loader throws "Plugin export is not a function" on the first such export. The new `src/server.ts` default-exports only `{ server: ObsignaPlugin }` (V1 shape), keeping opencode on the V1 path. The `.` barrel is unchanged for programmatic use.

### Changed

- **Renamed the plugin exports to the Obsigna brand**, matching the `@obsigna` package scope: `createAgentReceiptsPlugin` → `createObsignaPlugin`, the prebuilt `AgentReceiptsPlugin` → `ObsignaPlugin`, and the `AgentReceiptsPluginConfig` type → `ObsignaPluginConfig`. Breaking for the named exports only; the `AGENT_RECEIPTS_*` / `AGENTRECEIPTS_SOCKET` environment variables are unchanged. Update imports from `@obsigna/opencode-plugin`.

## [0.1.0-alpha.2] - 2026-06-16

### Changed

- **Package description** now refers to the **Obsigna daemon** rather than "the agent-receipts daemon", matching the brand split (Agent Receipts = the protocol, Obsigna = the toolset). Metadata-only; no code changes. Supersedes `0.1.0-alpha.1`.

## [0.1.0-alpha.1] - 2026-06-16

### Added

- **Initial release.** OpenCode plugin (`@obsigna/opencode-plugin`) that emits one daemon-signed Agent Receipt per native tool call (`bash`, `edit`, `write`, `webfetch`, …) by hooking `tool.execute.before`/`tool.execute.after` and forwarding each call to `agent-receipts-daemon` via the TS SDK `DaemonEmitter`. Emitter-only by construction — never signs or holds a key (ADR-0010).
  - **Action mapping** from OpenCode tool names to the AR taxonomy (`bash` → `system.command.execute`, `edit`/`write` → `filesystem.file.*`, `webfetch` → `data.api.read`), forwarded to the daemon as `action_type`; overridable via config.
  - **Per-session chain mapping** — each OpenCode `sessionID` gets its own emitter so receipts carry the session id. Per-agent sub-chains with `delegation` (issue #753) are a follow-up; the `tool.execute` hook context does not expose a named-agent identity.
  - **Failure posture (ADR-0025)** — default catch-and-warn never aborts a tool call; `strict` re-throws emit failures.
  - **Config** via environment (`AGENT_RECEIPTS_CHANNEL`, `AGENT_RECEIPTS_STRICT`, `AGENT_RECEIPTS_ALLOW`, `AGENT_RECEIPTS_DENY`) or programmatically via `createAgentReceiptsPlugin(config)`, including tool allow/deny and action-type overrides.
