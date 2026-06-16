# CLAUDE.md

## Project

Python SDK for [Agent Receipts](https://github.com/agent-receipts/obsigna) — cryptographically signed, hash-chained audit trails for AI agents.

## Commands

```sh
uv sync --all-extras       # install deps
uv run pytest -v           # run tests
uv run ruff check .        # lint
uv run ruff format .       # format
uv run pyright src         # type check (strict mode, must pass)
```

## Architecture

- `src/obsigna/receipt/` — Core: types, create, sign, hash, chain verification
- `src/obsigna/store/` — SQLite persistence: ReceiptStore, query, verify_stored_chain
- `src/obsigna/taxonomy/` — Action type classification, config loading
- `tests/` — Mirrors src structure. Uses conftest.py fixtures for receipt creation.

## Conventions

- `from __future__ import annotations` in every file
- Pydantic v2 for receipt models, frozen dataclasses for simple types
- `TYPE_CHECKING` guards for type-only imports
- Ruff for lint+format (line-length 88), pyright strict mode
- camelCase aliases exported at package level for TypeScript SDK users
- Schema must match TypeScript SDK exactly (cross-language tests verify this)
