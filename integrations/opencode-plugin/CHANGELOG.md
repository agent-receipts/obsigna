# Changelog

All notable changes to `@agent-receipts/opencode-plugin` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Initial release.** OpenCode plugin (`@agent-receipts/opencode-plugin`) that emits one daemon-signed Agent Receipt per native tool call (`bash`, `edit`, `write`, `webfetch`, …) by hooking `tool.execute.before`/`tool.execute.after` and forwarding each call to `agent-receipts-daemon` via the TS SDK `DaemonEmitter`. Emitter-only by construction — never signs or holds a key (ADR-0010).
  - **Action mapping** from OpenCode tool names to the AR taxonomy (`bash` → `system.command.execute`, `edit`/`write` → `filesystem.file.*`, `webfetch` → `data.api.read`), forwarded to the daemon as `action_type`; overridable via config.
  - **Per-session chain mapping** — each OpenCode `sessionID` gets its own emitter so receipts carry the session id. Per-agent sub-chains with `delegation` (issue #753) are a follow-up; the `tool.execute` hook context does not expose a named-agent identity.
  - **Failure posture (ADR-0025)** — default catch-and-warn never aborts a tool call; `strict` re-throws emit failures.
  - **Config** via environment (`AGENT_RECEIPTS_CHANNEL`, `AGENT_RECEIPTS_STRICT`, `AGENT_RECEIPTS_ALLOW`, `AGENT_RECEIPTS_DENY`) or programmatically via `createAgentReceiptsPlugin(config)`, including tool allow/deny and action-type overrides.
