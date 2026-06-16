# AGENTS.md

Thin MCP proxy: enforces policy on tool calls and forwards completed events to the [agent-receipts daemon](https://github.com/agent-receipts/obsigna/tree/main/daemon) for signing and persistence. The daemon is the sole writer; the proxy holds no SQLite store of its own (since v0.9.0 — see ADR-0010, [#421](https://github.com/agent-receipts/obsigna/pull/421), [#453](https://github.com/agent-receipts/obsigna/issues/453)).

## Getting started

```sh
go build ./...                              # build all
go build -o obsigna-mcp ./cmd/obsigna-mcp   # build the proxy binary
go test ./...                               # run tests
go vet ./...                                # static analysis
```

## Project structure

```
cmd/obsigna-mcp/   # CLI entry point (serve, doctor, init) — the proxy binary (ADR-0033)
cmd/mcp-proxy/     # thin deprecation shim: execs obsigna-mcp (ADR-0033)
internal/
  proxy/           # STDIO proxy, JSON-RPC parsing
  audit/           # Classifier, risk scorer, approval manager (no persistence)
  policy/          # YAML policy engine (pass/flag/pause/block)
  host/            # Parent-process host detection (Claude Code, Codex, Cursor, Windsurf)
configs/           # Default policy rules + bundled taxonomies (embedded into the binary via go:embed)
```

## Architecture

```
MCP Client → stdin/stdout → mcp-proxy → stdin/stdout → MCP Server
                               │
                               ├── JSON-RPC parser
                               ├── Classifier + Risk scorer
                               ├── Policy engine (YAML rules)
                               ├── Approval workflow (HTTP, in-memory)
                               └── Daemon emitter (forwards completed events
                                   to obsigna-daemon over AF_UNIX;
                                   daemon owns redaction, hashing, signing,
                                   chaining, and persistence)
```

## Flags

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `-rules` | — | — | Policy rules YAML file |
| `-name` | — | command basename | Server name for audit trail |
| `-http` | — | `none` | HTTP address for approval listener |
| `-approval-timeout` | — | `60s` | Max wait for HTTP approval |
| `-socket` | `AGENTRECEIPTS_SOCKET` | platform default | Daemon Unix socket path |
| `-issuer-name` | `AGENTRECEIPTS_ISSUER_NAME` | auto-detected | Override detected issuer name |
| `-issuer-model` | `AGENTRECEIPTS_ISSUER_MODEL` | — | AI model identifier |
| `-operator-id` | `AGENTRECEIPTS_OPERATOR_ID` | auto-detected | Operator DID |
| `-operator-name` | `AGENTRECEIPTS_OPERATOR_NAME` | auto-detected | Operator display name |

The proxy auto-detects the host (Claude Code, Codex, Cursor, Windsurf) from the parent process name on Linux. Flags and env vars take precedence over auto-detection.

## Conventions

- All changes go through pull requests
- Run `go vet ./...` before committing
- The proxy must never break the MCP protocol — if parsing fails, forward raw
- Flush stdout after every proxied message
- Redaction and persistence are daemon responsibilities — do not reintroduce a local store
