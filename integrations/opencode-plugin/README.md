# @obsigna/opencode-plugin

[OpenCode](https://opencode.ai) plugin for [Agent Receipts](https://github.com/agent-receipts/obsigna). Emits one cryptographically signed receipt per **native** tool call (`bash`, `edit`, `write`, `webfetch`, …) by forwarding each call to `agent-receipts-daemon` over a Unix-domain socket. The daemon — not this plugin — holds the key, canonicalises, signs, and chains the receipt.

This is the OpenCode analog of the [`agent-receipts-hook`](../../hook/) Claude Code integration, covering the native-tool channel. MCP tool calls are covered separately by [`mcp-proxy`](../../mcp-proxy/).

## Trust boundary

The plugin runs **inside** the OpenCode process, so it is an **emitter only** — it never instantiates a signer, signs, or holds a key (ADR-0010, daemon-sole-writer). This is the *execd-side*, honest-operator placement: it maximises coverage of native tool calls, but it is **not** adversary-resistant. A compromised OpenCode can omit or misreport calls. For the adversary-resistant MCP placement, point OpenCode's MCP server config at `mcp-proxy` (Tier A — see the docs).

## Install

```sh
npm install @obsigna/opencode-plugin
```

Register it as an OpenCode plugin in `opencode.json`:

```json
{
  "plugin": ["@obsigna/opencode-plugin"]
}
```

Requires `agent-receipts-daemon` to be running. See the [OpenCode docs](https://obsigna.dev/opencode/overview/) for the full Tier A + Tier B walkthrough and an end-to-end `agent-receipts verify` example.

## Configuration

Configure via environment variables (read at plugin load):

| Variable | Default | Meaning |
|---|---|---|
| `AGENTRECEIPTS_SOCKET` | per-OS default | Daemon socket path |
| `AGENT_RECEIPTS_CHANNEL` | `opencode` | Receipt channel label |
| `AGENT_RECEIPTS_STRICT` | `false` | Re-throw on emit failure (ADR-0025) instead of warn |
| `AGENT_RECEIPTS_ALLOW` | — | Comma-separated tool allow-list |
| `AGENT_RECEIPTS_DENY` | — | Comma-separated tool deny-list |

For programmatic configuration (allow/deny, action-type overrides, custom logger), build the plugin with `createAgentReceiptsPlugin(config)` and export it from your own `.opencode/plugin/` file.

## Failure posture (ADR-0025)

Default is catch-and-warn: a tool call is **never** aborted because the daemon is unreachable — the drop is logged loudly. Best-effort emission means a daemon outage produces a **chain gap**, not a completeness guarantee; this is honest-operator-grade auditing. Set `AGENT_RECEIPTS_STRICT=1` to surface emit failures instead.

## Development

```sh
pnpm install   # installs deps, including @obsigna/sdk-ts from npm
pnpm build     # tsc → dist/
pnpm test      # vitest
pnpm typecheck # tsc --noEmit
pnpm lint      # biome check
```

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
