# AGENTS.md

Python SDK for the [Agent Receipts protocol](https://github.com/agent-receipts/spec) — create, sign, hash-chain, store, and verify cryptographically signed audit trails for AI agent actions.

## Commands

```sh
uv sync --all-extras       # install deps
uv run pytest -v           # run tests
uv run ruff check .        # lint
uv run ruff format .       # format
uv run pyright src         # type check (pre-existing Pydantic errors are expected)
```

## Architecture

```
src/
  obsigna/
    receipt/
      types.py       # Pydantic v2 models for all receipt types
      create.py      # Receipt creation with auto-generated IDs
      signing.py     # Ed25519 signing and verification
      hash.py        # RFC 8785 canonicalization + SHA-256
      chain.py       # Chain verification
    store/
      store.py       # SQLite persistence (ReceiptStore)
      verify.py      # verify_stored_chain
    taxonomy/
      actions.py     # Action type definitions
      classify.py    # classify_tool_call
      config.py      # Taxonomy config loading
      types.py       # Action models
tests/                 # Mirrors src structure, uses conftest.py fixtures
```

## Conventions

- Prefer `from __future__ import annotations` in new or heavily-typed modules
- Pydantic v2 for receipt models, frozen dataclasses for simple types
- `TYPE_CHECKING` guards for type-only imports
- Ruff for lint + format (line-length 88), pyright strict mode
- camelCase aliases exported at package level for TypeScript SDK users
- Output must be byte-identical to the TypeScript SDK (`tests/test_cross_language.py` verifies this)

## Reference files

- `src/obsigna/receipt/signing.py` — Ed25519 signing with proper type guards, RFC 8785 canonicalization, and cross-SDK compatibility
- `src/obsigna/receipt/hash.py` — RFC 8785 canonical JSON + SHA-256 hashing with detailed spec-compliance comments
- `tests/test_cross_language.py` — cross-language test vectors: how to verify byte-identical output across SDKs

## Testing

- Tests mirror `src/` structure under `tests/`
- Fixtures in `tests/conftest.py` for receipt creation
- Cross-language tests in `tests/test_cross_language.py` use vectors from the TypeScript SDK
- CI runs on Python 3.11, 3.12, and 3.13

## Related repos

- [agent-receipts/spec](https://github.com/agent-receipts/spec) — protocol specification, JSON Schemas, canonical taxonomy
- [agent-receipts/sdk-ts](https://github.com/agent-receipts/obsigna/tree/main/sdk/ts) — TypeScript SDK
- [agent-receipts/site](https://github.com/agent-receipts/site) — documentation site
