<div align="center">

# Agent Receipts — Documentation Site

### Documentation for the Agent Receipts protocol, SDKs, and OpenClaw plugin

[![Astro](https://img.shields.io/badge/Astro-Starlight-BC52EE?logo=astro&logoColor=white)](https://starlight.astro.build/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Deployed](https://img.shields.io/badge/GitHub_Pages-Live-success)](https://agentreceipts.ai/)

---

**Browse the docs at [agentreceipts.ai](https://agentreceipts.ai/)**

</div>

---

## What's here

The documentation site for the [Agent Receipts](https://github.com/agent-receipts) ecosystem — the protocol specification, TypeScript and Python SDKs, and the OpenClaw plugin.

Covers:

- **Getting Started** — introduction and quick start
- **Specification** — schema, action taxonomy, risk levels, chain verification
- **TypeScript SDK** — overview, installation, API reference
- **Python SDK** — overview, installation, API reference
- **OpenClaw** — plugin overview and installation
- **Reference** — CLI commands, configuration

## Development

```sh
pnpm install
pnpm dev          # local dev server
pnpm build        # production build → dist/
pnpm preview      # preview production build
```

## Adding content

Documentation lives in `src/content/docs/` as `.mdx` files. When adding a new page:

1. Create the `.mdx` file in the appropriate subdirectory
2. Add a sidebar entry in `astro.config.mjs`

Sidebar order is controlled by `astro.config.mjs`, not by file naming.

## Ecosystem

| Repository | Description |
|:---|:---|
| [agent-receipts/spec](https://github.com/agent-receipts/obsigna/tree/main/spec) | Protocol specification, JSON Schemas, canonical taxonomy |
| [agent-receipts/sdk-ts](https://github.com/agent-receipts/obsigna/tree/main/sdk/ts) | TypeScript SDK ([npm](https://www.npmjs.com/package/@obsigna/sdk-ts)) |
| [agent-receipts/sdk-py](https://github.com/agent-receipts/obsigna/tree/main/sdk/py) | Python SDK ([PyPI](https://pypi.org/project/obsigna/)) |
| [ojongerius/attest](https://github.com/ojongerius/attest) | MCP proxy + CLI (reference implementation) |
| **agent-receipts/site** (this repo) | Documentation site |

## License

MIT — see [LICENSE](LICENSE).
