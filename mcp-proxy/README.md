<div align="center">

# mcp-proxy

### MCP proxy with action receipts, policy engine, and intent tracking

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev/)

**Audit, govern, and sign every AI agent action.**

[SDK](https://github.com/agent-receipts/obsigna/tree/main/sdk/go) &bull; [Spec](https://github.com/agent-receipts/spec) &bull; [agentreceipts.ai](https://agentreceipts.ai)

</div>

---

## What it does

`mcp-proxy` sits between an MCP client (Claude, etc.) and an MCP server, transparently intercepting every tool call. For each call it:

1. **Classifies** the operation (read/write/delete/execute) and scores risk (0-100)
2. **Evaluates policy** rules (pass/flag/pause/block) with approval workflows
3. **Groups** related calls by temporal proximity (intent tracking)
4. **Signs** a cryptographic receipt (Ed25519, hash-chained, W3C Verifiable Credential)
5. **Redacts** sensitive data (JSON-aware + pattern-based) before storage
6. **Stores** everything in a local SQLite audit trail

Single binary. No external dependencies. Drop-in for any MCP server.

## Install

### Homebrew (macOS, Linux)

```sh
brew install agent-receipts/tap/obsigna
```

### Prebuilt binaries

Download the `obsigna_<version>_<os>_<arch>` tarball from the [releases page](https://github.com/agent-receipts/obsigna/releases?q=obsigna) (darwin and linux, amd64 and arm64).

### From source

```sh
go install github.com/agent-receipts/ar/mcp-proxy/cmd/obsigna-mcp@latest
```

### Binary name

The proxy binary is **`obsigna-mcp`** (renamed from `mcp-proxy`; ADR-0033). In a full
Obsigna install it is also launched as **`obsigna mcp run`** (ADR-0030), which execs
straight into `obsigna-mcp`. The legacy **`mcp-proxy`** command still works as a thin
deprecation shim that forwards to `obsigna-mcp`, so existing MCP client configs keep
running — but prefer `obsigna-mcp` in new configs; the shim will be removed in a future
release. The usage examples below use `mcp-proxy` for continuity; substitute `obsigna-mcp`
freely.

## Usage

### As MCP proxy

```sh
# Wrap any MCP server
mcp-proxy node /path/to/mcp-server.js

# With options
mcp-proxy \
  --name github \
  --key private.pem \
  --taxonomy taxonomy.json \
  --rules rules.yaml \
  --issuer did:agent:my-proxy \
  --principal did:user:alice \
  node /path/to/github-mcp-server.js
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "github-audited": {
      "command": "mcp-proxy",
      "args": [
        "--name", "github",
        "node", "/path/to/github-mcp-server.js"
      ]
    }
  }
}
```

### Check version

```sh
mcp-proxy -version
```

### Persistent signing key

By default, mcp-proxy generates an ephemeral key pair on each startup. To use a
persistent key whose receipts can be verified offline, generate one with `init`:

```sh
mcp-proxy init -key ~/.agent-receipts/signing.pem
# writes ~/.agent-receipts/signing.pem     (0600 — owner read/write only)
# writes ~/.agent-receipts/signing.pem.pub (0644 — public, shareable)
```

Pass the key to the proxy:

```sh
mcp-proxy --key ~/.agent-receipts/signing.pem node /path/to/mcp-server.js
```

Enable strict permission enforcement to make loose file permissions a fatal error:

```sh
mcp-proxy --key ~/.agent-receipts/signing.pem --strict-permissions node /path/to/mcp-server.js
```

If you generated a key with another tool (e.g. `openssl genpkey`), restrict
access manually before use:

```sh
chmod 600 private.pem
```

### CLI subcommands

```sh
mcp-proxy init -key <path>              # Generate a persistent Ed25519 key pair
mcp-proxy list                          # Latest 50 receipts, newest first
mcp-proxy list --risk high              # Filter by risk
mcp-proxy inspect <receipt-id>          # Show receipt details
mcp-proxy verify --key pub.pem <chain>  # Verify chain integrity
mcp-proxy export <chain-id>             # Export chain as JSON
mcp-proxy stats                         # Show statistics
mcp-proxy timing                        # Show per-tool timing breakdown
mcp-proxy timing --json                 # JSON output for dashboards
```

## Policy engine

Define rules in YAML:

```yaml
rules:
  - name: block_destructive_ops
    description: Block high-risk delete operations
    enabled: true
    tool_pattern: "delete_*"
    min_risk_score: 70
    action: block

  - name: pause_high_risk
    description: Pause for approval when risk >= 50
    enabled: true
    min_risk_score: 50
    action: pause
```

Actions: `pass` (log only), `flag` (log + highlight), `pause` (wait for approval), `block` (reject).

When a tool call is paused, approve or deny via HTTP. **The listener is off by default** — pass `-http 127.0.0.1:PORT` to enable it (without that flag, paused calls fail fast with JSON-RPC code `-32003`). The approval URL and bearer token are logged to stderr at startup. Copy the token from the startup line and export it before running the curls:

```sh
export APPROVAL_TOKEN=<token-from-stderr>

curl -X POST http://127.0.0.1:PORT/api/tool-calls/{id}/approve \
  -H "Authorization: Bearer $APPROVAL_TOKEN"
curl -X POST http://127.0.0.1:PORT/api/tool-calls/{id}/deny \
  -H "Authorization: Bearer $APPROVAL_TOKEN"
```

Paused calls auto-deny after 60 seconds (fail-safe).

## Encryption

Set `BEACON_ENCRYPTION_KEY` to enable AES-256-GCM encryption at rest for sensitive audit data.

## Secret redaction

The proxy redacts secrets before writing to the audit database in two passes:
1. **JSON-key pass** — any value whose JSON key matches a sensitive name (e.g. `password`, `token`, `api_key`) is replaced with `[REDACTED]`.
2. **Pattern pass** — 12 built-in regular expressions catch common token formats regardless of key name.

Built-in patterns:

| Name | Matches |
|------|---------|
| `github-pat-classic` | `ghp_…` GitHub personal access tokens |
| `github-pat-finegrained` | `github_pat_…` fine-grained PATs |
| `github-oauth` | `gho_…` OAuth tokens |
| `github-app-installation` | `ghs_…` GitHub App installation tokens |
| `github-user-to-server` | `ghu_…` user-to-server tokens |
| `github-installation-legacy` | `v1.<40+ hex chars>` legacy installation tokens |
| `openai-anthropic-key` | `sk-…` OpenAI/Anthropic secret keys |
| `aws-access-key` | `AKIA…` AWS access key IDs |
| `bearer-token` | `Bearer <token>` HTTP Authorization headers |
| `slack-token` | `xoxb-/xoxp-/xoxr-/xoxa-/xoxs-` Slack tokens |
| `pem-private-key` | PEM `-----BEGIN … PRIVATE KEY-----` blocks |
| `url-param-token` | `?token=…`, `?access_token=…`, `?key=…` etc. (key name preserved) |

### Custom patterns

Add organisation-specific patterns with a YAML file:

```yaml
# custom_redact.yaml
patterns:
  - name: slack-webhook
    pattern: 'https://hooks\.slack\.com/services/[A-Z0-9/]+'
  - name: stripe-live
    pattern: 'sk_live_[A-Za-z0-9]{24,}'
```

Pass it at startup:

```sh
mcp-proxy -redact-patterns custom_redact.yaml -- npx -y @modelcontextprotocol/server-filesystem /
```

An example file is at `configs/example_redact_patterns.yaml`.

### Auditing existing databases

The `audit-secrets` subcommand scans an existing audit database for values that match any built-in or custom pattern — useful after upgrading the proxy or adding new patterns:

```sh
mcp-proxy audit-secrets -db ~/.agent-receipts/audit.db
mcp-proxy audit-secrets -db ~/.agent-receipts/audit.db -redact-patterns custom_redact.yaml
```

If the database is encrypted, set `BEACON_ENCRYPTION_KEY` before running.

**Exit codes:** `0` = no matches found; `1` = one or more matches found; `2` = error.

The scanner runs two passes per row:

1. **Regex pass** — checks the value against all built-in and custom named patterns. Output line: `<table> col=<column> row=<id> pattern=<name>`.
2. **JSON-key pass** — parses the value as JSON and reports any value stored under a sensitive key (e.g. `password`, `token`, `api_key`) that is non-empty and not already `[REDACTED]`. Catches leaks that do not match any regex pattern. Output line: `<table> col=<column> row=<id> json-key=<path>`.

If decryption fails for a row (invalid ciphertext), it is reported as `<table> col=<column> row=<id> decrypt-error` and counts as a hit — operators must investigate.

If hits are reported, the raw token values are already in the database. Because the audit log is append-only, the recommended action is to **rotate the secret** and consider the old value compromised. You can then drop or redact the affected rows manually if needed.

## License

Apache 2.0
