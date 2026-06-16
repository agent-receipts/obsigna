# AGENTS.md

OpenCode plugin (`@agent-receipts/opencode-plugin`) that emits one Agent Receipt per native OpenCode tool call. Hooks `tool.execute.before`/`tool.execute.after` from `@opencode-ai/plugin` and forwards each call to `agent-receipts-daemon` via the TS SDK `DaemonEmitter`. The OpenCode analog of the Go [`hook/`](../../hook/) Claude Code integration, for the native-tool channel.

## Trust boundary (load-bearing)

The plugin runs **inside** the OpenCode process → **emitter only**. It MUST emit via `DaemonEmitter` to the out-of-process daemon (ADR-0010 daemon-sole-writer). It NEVER instantiates a signer, signs, or holds a key. This is the execd-side, honest-operator placement — max coverage, **not** adversary-resistant. Code, labels, and docs must not claim the plugin path gives a boundary/adversary-resistant guarantee. The mcp-proxy MCP placement (Tier A) is the adversary-resistant one.

## Getting started

```sh
pnpm install        # @obsigna/sdk-ts is file:-linked from ../../sdk/ts (build it first)
pnpm build          # tsc → dist/
pnpm test           # vitest (unit + round-trip against a fake daemon socket)
pnpm typecheck      # tsc --noEmit
pnpm lint           # biome check
```

`@obsigna/sdk-ts` resolves from a `file:../../sdk/ts` install, so run `pnpm build` in `sdk/ts` before installing/testing here.

## Project structure

```
src/
  actions.ts        # OpenCode tool name → AR taxonomy action type map
  config.ts         # config schema, env resolution, allow/deny filter
  recorder.ts       # framework-agnostic core: tool calls → DaemonEmitter emissions
  plugin.ts         # OpenCode adapter: Plugin export + hooks + session lifecycle
  index.ts          # public exports
  *.test.ts         # colocated vitest tests
  roundtrip.test.ts # real DaemonEmitter against a fake AF_UNIX daemon socket
```

## Conventions

- **ESM-only** (`"type": "module"`, imports use `.js` extensions)
- **Strict TypeScript**, **Biome** (tab indent, double quotes), colocated `.test.ts`
- **No default exports** — named exports throughout
- All signing/canonicalisation/chaining belongs to the daemon — never add crypto here
- `@opencode-ai/plugin` is a `peerDependency` (provided by the OpenCode host) and a devDependency for types

## Design notes

- **Action mapping** — `actions.ts` maps tool names to taxonomy types, forwarded to the daemon as `action_type` (`EmitEvent.actionType`). The daemon re-derives `risk_level` from the type, so mislabelling cannot downgrade risk. Unmapped tools omit `action_type` and the daemon falls back to `"<channel>.<tool>"`.
- **Chain mapping** — each OpenCode `sessionID` gets its own `DaemonEmitter`, so receipts carry that session id. Per-agent sub-chains with `delegation` backlinks (issue #753) are a deliberate follow-up: the `tool.execute` hook context exposes only `{ tool, sessionID, callID }`, not a named-agent identity, so the keying cannot be derived without guessing. `Session.parentID` (from the OpenCode SDK) is the hook the follow-up will use.
- **Failure posture (ADR-0025)** — default catch-and-warn never aborts a tool call; `strict` re-throws from the after-hook. Best-effort ⇒ possible chain gaps ⇒ honest-operator-grade, not a completeness guarantee.

## Testing

- Unit tests inject a capturing `ReceiptEmitter` fake (no socket) to assert mapping, filtering, intent/params bridging, per-session emitters, and the strict/default failure posture.
- `roundtrip.test.ts` drives the real `DaemonEmitter` against a fake length-prefixed AF_UNIX server (mirrors sdk/ts `daemon-emitter.test.ts`) and asserts the wire-frame shape. Signed-chain verification is the daemon's job, covered by the docs `agent-receipts verify` walkthrough.

## CI / Release

CI runs via `.github/workflows/opencode-plugin.yml` (path-filtered on `integrations/opencode-plugin/**` and `sdk/ts/**`): it builds the in-tree `sdk/ts` first (the `file:` dependency), then runs typecheck, lint, build, and test. No release/publish workflow ships yet — publishing (swapping the `file:` link to a versioned `@obsigna/sdk-ts` release) is a follow-up.
