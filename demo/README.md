# obsigna + sbx demo

Two non-overlapping audit layers for an AI agent running inside a Docker sbx microVM:

| Layer | Tool | Question answered |
|-------|------|-------------------|
| Infrastructure | `sbx policy log` | What did the VM's network policy allow or block? |
| Agent actions | `obsigna verify` | What did the agent actually do, in what order, with what inputs? |

Neither log alone tells the full story. sbx sees network packets — not tool semantics. obsigna sees signed receipts for every tool call — not network-level verdicts.

## Running the demo

```
./demo.sh
```

Prerequisites:
- `obsigna-daemon`, `obsigna`, `sbx` (authenticated: `sbx login`), `socat`, `ollama`
- `devstral-small-2:latest` pulled in ollama
- The demo creates `devstral-demo` (a 32K-context variant) automatically on first run

Override the model:
```
./demo.sh openai-compatible/qwen2.5-coder:32b
```

## What happens

1. `obsigna-daemon` starts on your **host** (outside the VM), holding the Ed25519 signing key.
2. A `socat` TCP bridge forwards from `host.docker.internal:3923` to the daemon's Unix socket, because macOS host sockets can't be connected to from inside a Linux container via bind-mount.
3. An sbx sandbox is created with the workspace bind-mounted.
4. `opencode` runs inside sbx. Inside the container, a second `socat` creates a Linux Unix socket that tunnels to the host via TCP. The obsigna plugin connects to that socket and emits one signed receipt per tool call.
5. The agent writes a Python file, runs it, then attempts an outbound `curl`. sbx blocks the curl.

## Reading the output

**`sbx policy log`** — infrastructure view:
```
ALLOWED  localhost:11434   ollama (model inference)
ALLOWED  localhost:3923    obsigna receipt tunnel
BLOCKED  worldtimeapi.org:443   default deny
```

**`obsigna receipt list`** — agent action view:
```
SEQ  TIMESTAMP             CHAIN       TOOL / ACTION TYPE
1    2026-06-16T...        2026-06-16  write   ← fibonacci.py created
2    2026-06-16T...        2026-06-16  bash    ← python3 work/fibonacci.py
3    2026-06-16T...        2026-06-16  bash    ← curl (blocked at network layer)
```

**`obsigna verify`** — chain integrity:
```
Chain 2026-06-16: VALID (3 receipts)
```

The curl shows up in **both** logs — sbx blocked it at the network layer, obsigna receipted it at the agent action layer.

## Architecture

```
your laptop (host)
├── obsigna-daemon          signing key lives here (Ed25519)
│     ↑ Unix socket (/tmp/obsigna-sbx/obsigna.sock)
│     │
│     socat (host)          TCP bridge: port 3923 → Unix socket
│     ↑ TCP :3923
│     │
└── sbx microVM
      ├── socat (container) TCP → Linux Unix socket (/tmp/obsigna.sock)
      │     ↑
      ├── opencode (agent)
      │     └── obsigna plugin ──→ /tmp/obsigna.sock ──→ tunnel ──→ daemon
      └── ollama via host.docker.internal:11434
```

The signing key never enters the VM. Receipts are written to the host's SQLite DB. Even if the agent were compromised, it cannot forge or delete the receipt chain.

## Files

```
demo/
├── demo.sh                  orchestrates the full flow
├── undici-stub.mjs          esbuild stub replacing undici (not available in opencode runtime)
├── kit/spec.yaml            sbx kit spec (mixin)
├── workspace/
│   ├── .opencode/
│   │   ├── opencode.json    provider + model config (ollama via openai-compatible)
│   │   └── plugins/
│   │       └── agent-receipts.js   bundled obsigna plugin (built by demo.sh on first run)
│   └── work/                agent writes output here
└── README.md                this file
```

## Follow-ups

- The plugin (`integrations/opencode-plugin`, PR #766) is not yet published to npm. `demo.sh` builds it from source on first run.
- This demo also serves as the end-to-end acceptance test for PR #766.
- MCP proxy (Tier A) can be layered on top for adversary-resistant receipts — see `mcp-proxy/`.
