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

Prerequisites: `obsigna-daemon`, `obsigna`, `sbx` (authenticated with `sbx login`), `ollama` running locally with `devstral-small-2:latest` pulled.

Override the model:
```
./demo.sh openai-compatible/qwen2.5-coder:32b
```

## What happens

1. `obsigna-daemon` starts on your **host** (outside the VM), holding the Ed25519 signing key. The agent inside sbx cannot reach the key.
2. An sbx sandbox is created with the workspace bind-mounted. The daemon's Unix socket lives inside the mounted workspace directory, so the plugin inside the VM can connect to it — but the daemon process stays on the host.
3. `opencode` runs inside sbx with a local ollama model (`host.docker.internal:11434`). The obsigna plugin (`integrations/opencode-plugin`) hooks `tool.execute.before/after` and emits one receipt per native tool call.
4. The agent writes a Python file, runs it, then attempts an outbound `curl`. sbx blocks the outbound request.

## Reading the output

**`sbx policy log`** — infrastructure view:
```
ALLOWED  host.docker.internal:11434   ollama (model inference)
BLOCKED  worldtimeapi.org:443         default deny — no matching allow rule
```

**`obsigna receipt list`** — agent action view:
```
seq  type                      tool    risk
1    filesystem.file.modify    write   medium   work/fibonacci.py
2    system.command.execute    bash    high     python work/fibonacci.py
3    system.command.execute    bash    high     curl https://worldtimeapi.org/...
```

**`obsigna verify`** — chain integrity:
```
chain verified: 3 receipts, 0 gaps, signatures valid
```

The curl shows up in **both** logs — sbx blocked it at the network layer, obsigna receipted it at the agent action layer. They see the same event from different vantage points.

## Architecture

```
your laptop (host)
├── obsigna-daemon          signing key lives here
│     ↑ Unix socket
│     │ (bind-mounted into sbx at the same path)
│     ↓
└── sbx microVM
      ├── opencode (agent)
      │     └── obsigna plugin  ──→ socket ──→ daemon
      └── ollama via host.docker.internal:11434
```

The signing key never enters the VM. Receipts are stored on the host. Even if the agent were compromised, it cannot forge or delete the receipt chain.

## Files

```
demo/
├── demo.sh                  orchestrates the full flow
├── kit/kit.yaml             sbx kit: injects AGENTRECEIPTS_SOCKET
├── workspace/
│   ├── .opencode/
│   │   ├── opencode.json    ollama model config
│   │   └── plugins/
│   │       └── agent-receipts.js   bundled obsigna plugin (built by demo.sh)
│   └── work/                agent writes output here
└── README.md                this file
```

## Follow-ups

- The plugin (`integrations/opencode-plugin`, PR #766) is not yet published to npm. `demo.sh` builds it from source.
- The `kit/kit.yaml` format is sbx experimental. If the kit `env` key is not yet supported, set `AGENTRECEIPTS_SOCKET` manually via `sbx exec`.
- MCP proxy (Tier A) can be layered on top for adversary-resistant receipts — see `mcp-proxy/` and the opencode Tier A docs in PR #766.
