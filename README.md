<div align="center">

# Agent Receipts

**Cryptographically signed audit trails for AI agent actions**

[![Go Tests](https://github.com/agent-receipts/obsigna/actions/workflows/sdk-go.yml/badge.svg)](https://github.com/agent-receipts/obsigna/actions/workflows/sdk-go.yml)
[![TS Tests](https://github.com/agent-receipts/obsigna/actions/workflows/sdk-ts.yml/badge.svg)](https://github.com/agent-receipts/obsigna/actions/workflows/sdk-ts.yml)
[![Python Tests](https://github.com/agent-receipts/obsigna/actions/workflows/sdk-py.yml/badge.svg)](https://github.com/agent-receipts/obsigna/actions/workflows/sdk-py.yml)
[![Daemon](https://github.com/agent-receipts/obsigna/actions/workflows/daemon.yml/badge.svg)](https://github.com/agent-receipts/obsigna/actions/workflows/daemon.yml)
[![MCP Proxy](https://github.com/agent-receipts/obsigna/actions/workflows/mcp-proxy.yml/badge.svg)](https://github.com/agent-receipts/obsigna/actions/workflows/mcp-proxy.yml)
[![Hook](https://github.com/agent-receipts/obsigna/actions/workflows/hook.yml/badge.svg)](https://github.com/agent-receipts/obsigna/actions/workflows/hook.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

</div>

| | |
|---|---|
| **Protocol site & spec** | [agentreceipts.ai](https://agentreceipts.ai) |
| **Tooling docs** | [obsigna.dev](https://obsigna.dev) |
| **Daemon setup & migration guide** | [obsigna.dev/getting-started/daemon-setup/](https://obsigna.dev/getting-started/daemon-setup/) |
| **API reference** | [Go](https://obsigna.dev/sdk-go/api-reference/) · [TypeScript](https://obsigna.dev/sdk-ts/api-reference/) · [Python](https://obsigna.dev/sdk-py/api-reference/) |
| **Blog** | [Your AI Agent Just Sent an Email](https://jongerius.solutions/post/your-ai-agent-just-sent-an-email/) · [Every MCP Tool Call My AI Makes Now Gets a Signed Receipt](https://jongerius.solutions/post/auditing-github-mcp-agent-receipts/) |
| **Go** | [sdk/go](https://pkg.go.dev/github.com/agent-receipts/ar/sdk/go) · [mcp-proxy](https://pkg.go.dev/github.com/agent-receipts/ar/mcp-proxy) · [dashboard](https://pkg.go.dev/github.com/agent-receipts/dashboard) |
| **npm** | [@obsigna/sdk-ts](https://www.npmjs.com/package/@obsigna/sdk-ts) |
| **PyPI** | [obsigna](https://pypi.org/project/obsigna/) |

---

## What is this?

**Agent Receipts** is an open protocol for producing cryptographically signed, tamper-evident records of AI agent actions. It defines the receipt format, signing scheme, chain structure, and taxonomy of action types. Anyone can implement it — in any language, in any runtime.

**Obsigna** is the reference toolset that implements the protocol:

| Tool | What it does |
|------|-------------|
| `obsigna-mcp` | MCP stdio proxy — signs every tool call, adds policy hooks |
| `obsigna-daemon` | Out-of-process signing daemon — holds the key, owns the audit chain |
| `obsigna-hook` | PostToolUse hook for Claude Code and other runtimes |
| `obsigna` | CLI for browsing and verifying receipt databases |
| `sdk/go`, `@obsigna/sdk-ts`, `obsigna` (Python) | SDKs for embedding receipt creation in your own code |

<picture>
  <img alt="How it works: Authorize → Act → Sign → Link → Audit" src=".github/how-it-works.svg">
</picture>

## Start here

Both paths below require the daemon — it holds the signing key and owns the audit chain. Install it first:

```bash
brew install agent-receipts/tap/obsigna
obsigna daemon start
```

**Fastest path — PostToolUse hook (Claude Code):** one config snippet and every tool call gets a signed receipt automatically:

```json
{
  "hooks": {
    "PostToolUse": [{ "matcher": "", "hooks": [{ "type": "command", "command": "obsigna-hook" }] }]
  }
}
```

Add that to `~/.claude/settings.json`, then inspect the audit trail:

```bash
obsigna list
obsigna show <seq>
obsigna verify
```

**More control — MCP proxy:** wraps any MCP server and adds policy hooks and risk scoring on top of signed receipts:

- [Claude Desktop setup](https://obsigna.dev/mcp-proxy/claude-desktop/)
- [Claude Code setup](https://obsigna.dev/mcp-proxy/claude-code/)
- [Codex setup](https://obsigna.dev/mcp-proxy/codex/)

## Project layout

| Project | Description |
|---------|-------------|
| [`spec/`](spec/) | Protocol specification, JSON schemas, governance |
| [`sdk/go/`](sdk/go/) | Go SDK |
| [`sdk/ts/`](sdk/ts/) | TypeScript SDK |
| [`sdk/py/`](sdk/py/) | Python SDK |
| [`daemon/`](daemon/) | Signing daemon — out-of-process key custody, shared audit chain |
| [`mcp-proxy/`](mcp-proxy/) | MCP proxy with receipt signing, policy engine, intent tracking |
| [`hook/`](hook/) | PostToolUse hook binary for Claude Code and other runtimes |
| [`cross-sdk-tests/`](cross-sdk-tests/) | Cross-language verification tests |
| [`docs/adr/`](docs/adr/) | Architecture Decision Records |
| [dashboard](https://github.com/agent-receipts/dashboard) | Local web UI for browsing and verifying receipt databases |
| [openclaw](https://github.com/agent-receipts/openclaw) | Agent Receipts plugin for OpenClaw |

## SDK quick start

> **Choose your trust model.** The snippets below keep the signing key inside the
> agent process — a deliberate deployment model where the agent host is trusted
> and tamper-evidence is aimed at downstream parties. In this model, anyone with
> code execution in the agent can forge receipts. To defend against a compromised
> agent, use the
> [daemon-mediated path](https://obsigna.dev/getting-started/daemon-setup/),
> where a separate daemon owns the key and your app only sends events over a
> socket. See the [Trust Model](https://agentreceipts.ai/specification/trust-model/)
> page for the full spectrum (in-process → daemon-isolated → HSM/KMS).

### Go

```bash
go get github.com/agent-receipts/ar/sdk/go
```

```go
import "github.com/agent-receipts/ar/sdk/go/receipt"

keys, _ := receipt.GenerateKeyPair()
unsigned := receipt.Create(receipt.CreateInput{
    Issuer:    receipt.Issuer{ID: "did:agent:my-agent"},
    Principal: receipt.Principal{ID: "did:user:alice"},
    Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
    Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
    Chain:     receipt.Chain{Sequence: 1, ChainID: "chain_1"},
})
signed, _ := receipt.Sign(unsigned, keys.PrivateKey, "did:agent:my-agent#key-1")
```

### TypeScript

```bash
npm install @obsigna/sdk-ts
```

```typescript
import {
  createReceipt,
  generateKeyPair,
  signReceipt,
} from "@obsigna/sdk-ts";

const keys = generateKeyPair();
const unsigned = createReceipt({
  issuer: { id: "did:agent:my-agent" },
  principal: { id: "did:user:alice" },
  action: { type: "filesystem.file.read", risk_level: "low" },
  outcome: { status: "success" },
  chain: { sequence: 1, previous_receipt_hash: null, chain_id: "chain_1" },
});
const signed = signReceipt(unsigned, keys.privateKey, "did:agent:my-agent#key-1");
```

### Python

```bash
pip install obsigna
```

```python
from obsigna import (
    create_receipt, generate_key_pair, sign_receipt,
    CreateReceiptInput, Issuer, Principal, Outcome, Chain,
)
from obsigna.receipt.create import ActionInput

keys = generate_key_pair()
unsigned = create_receipt(CreateReceiptInput(
    issuer=Issuer(id="did:agent:my-agent"),
    principal=Principal(id="did:user:alice"),
    action=ActionInput(type="filesystem.file.read", risk_level="low"),
    outcome=Outcome(status="success"),
    chain=Chain(sequence=1, previous_receipt_hash=None, chain_id="chain_1"),
))
signed = sign_receipt(unsigned, keys.private_key, "did:agent:my-agent#key-1")
```

See the [Python SDK README](sdk/py/README.md) for the full quick start and daemon delivery.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and PR guidelines.

## Security

See [SECURITY.md](SECURITY.md) to report vulnerabilities. The [threat model](docs/threat-model.md) documents trust boundaries, in-scope and out-of-scope threats, and the mitigation roadmap.

## License

Apache License 2.0 -- see [LICENSE](LICENSE).
The protocol specification in `spec/` is licensed under MIT.
