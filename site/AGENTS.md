# AGENTS.md

Documentation site for the Agent Receipts protocol, built with Astro Starlight.

## Stack

- **Astro + Starlight** — static site generator with docs theme
- **pnpm** — package manager (use `pnpm install`, not npm/yarn)
- Deploys to GitHub Pages via `.github/workflows/deploy.yml`

## Development

```sh
pnpm install
pnpm dev       # local dev server
pnpm build     # production build to dist/
pnpm preview   # preview production build
```

## Project structure

- `src/content/docs/` — all documentation pages as `.mdx` files
- `src/pages/index.astro` — custom landing page
- `src/styles/custom.css` — theme overrides
- `astro.config.mjs` — Starlight config including sidebar structure
- `public/llms.txt`, `public/llms-full.txt` — AI-consumable protocol summaries

## Content conventions

- Documentation pages use `.mdx` format with Starlight frontmatter (`title`, `description`)
- Sidebar order is defined in `astro.config.mjs`, not by file naming
- Content is organized by topic: `getting-started/`, `specification/`, `sdk-ts/`, `sdk-py/`, `openclaw/`, `reference/`
- When adding a new page, add a corresponding sidebar entry in `astro.config.mjs`

## Related repos

- [agent-receipts/spec](https://github.com/agent-receipts/obsigna/tree/main/spec) — protocol specification
- [agent-receipts/sdk-ts](https://github.com/agent-receipts/obsigna/tree/main/sdk/ts) — TypeScript SDK
- [agent-receipts/sdk-py](https://github.com/agent-receipts/obsigna/tree/main/sdk/py) — Python SDK
- [agent-receipts/openclaw](https://github.com/agent-receipts/openclaw) — OpenClaw plugin
