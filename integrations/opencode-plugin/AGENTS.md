# AGENTS.md

OpenCode plugin (`@obsigna/opencode-plugin`) that emits one Agent Receipt per native OpenCode tool call. Hooks `tool.execute.before`/`tool.execute.after` from `@opencode-ai/plugin` and forwards each call to `agent-receipts-daemon` via the TS SDK `DaemonEmitter`. The OpenCode analog of the Go [`hook/`](../../hook/) Claude Code integration, for the native-tool channel.

## Trust boundary (load-bearing)

The plugin runs **inside** the OpenCode process → **emitter only**. It MUST emit via `DaemonEmitter` to the out-of-process daemon (ADR-0010 daemon-sole-writer). It NEVER instantiates a signer, signs, or holds a key. This is the execd-side, honest-operator placement — max coverage, **not** adversary-resistant. Code, labels, and docs must not claim the plugin path gives a boundary/adversary-resistant guarantee. The mcp-proxy MCP placement (Tier A) is the adversary-resistant one.

## Getting started

```sh
pnpm install        # installs @obsigna/sdk-ts from npm (versioned dependency)
pnpm build          # tsc → dist/
pnpm test           # vitest (unit + round-trip against a fake daemon socket)
pnpm typecheck      # tsc --noEmit
pnpm lint           # biome check
```

`@obsigna/sdk-ts` is a versioned dependency resolved from npm, so the SDK does not need to be built locally first. To develop against unreleased SDK changes, publish a pre-release or temporarily `pnpm link` the in-tree `sdk/ts`.

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

CI runs via `.github/workflows/opencode-plugin.yml` (path-filtered on `integrations/opencode-plugin/**`): it installs deps (including the published `@obsigna/sdk-ts`) and runs typecheck, lint, build, and test. The plugin depends on a versioned `@obsigna/sdk-ts` range, so it is tested against exactly what consumers install — a breaking SDK change is opted into by bumping the range, not surfaced automatically.

Releases run via `.github/workflows/release-opencode-plugin.yml` on a `opencode-plugin-v*` tag: it verifies the tag matches `package.json`, runs the check suite, creates a GitHub release (pre-release for `-` versions), and publishes to npm with provenance under a dist-tag derived from the pre-release label (`alpha` for `-alpha.N`, `latest` for stable). The tag must match `package.json` version exactly.

Publishing uses npm **OIDC trusted publishing** (configured on the npm package, no environment), not a long-lived token: the job grants `id-token: write` and deliberately omits setup-node's `registry-url`/`NODE_AUTH_TOKEN`, since a token-based `.npmrc` would take precedence over OIDC. Provenance is signed from the GitHub Actions OIDC identity. Managing dist-tags (`npm dist-tag`) and deprecations is out of band — OIDC covers publish only, so those still need a human-held npm credential.
