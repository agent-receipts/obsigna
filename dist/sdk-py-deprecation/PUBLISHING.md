# Publishing the `agent-receipts` deprecation shim

> Maintainer note — not part of the package's public API.

This directory is the **staged content for the final `agent-receipts` PyPI
release**: a redirect shim that pulls in and re-exports the renamed `obsigna`
package. See [`sdk/PUBLISH.md`](../../sdk/PUBLISH.md) for the full ordered
runbook (publish `obsigna` first, then this shim).

## What this is

- `pyproject.toml` — project name stays `agent-receipts`; depends on `obsigna`.
- `src/agent_receipts/__init__.py` — emits a `DeprecationWarning` and installs a
  meta-path finder that resolves `agent_receipts` and every `agent_receipts.*`
  submodule to the matching `obsigna` module.

## Versioning

The shim version (`0.13.0`) must sort **above every previously published
`agent-receipts` release** so a bare `pip install agent-receipts` resolves to
this redirect instead of the last real release (`0.12.0`). The last real
release stays published and untouched; pinned installs (`agent-receipts==0.12.0`)
still get the original package.

The dependency lower bound `obsigna>=0.13.0a1` names a pre-release, which (per
PEP 440) lets pip install the current `obsigna` alpha. Bump both versions in
lockstep with `obsigna` going forward, or freeze the shim here permanently —
either is fine; it only needs to redirect.

## Publish

Do **not** publish until `obsigna` is live on PyPI (the shim's install resolves
its dependency from the index). Then, from this directory:

```sh
uv build                          # or: python -m build
twine upload dist/*
```

Do not yank or delete any prior `agent-receipts` release. Breaking existing
installs is a failure, not a cleanup.

## Verify

```sh
python -m venv /tmp/ar-verify && . /tmp/ar-verify/bin/activate
pip install agent-receipts        # resolves to the shim, pulls obsigna
python -W error::DeprecationWarning -c "import agent_receipts" \
  && echo "FAIL: no warning" || echo "OK: import warns"
python -c "import agent_receipts, obsigna; \
  assert agent_receipts.create_receipt is obsigna.create_receipt; \
  from agent_receipts.receipt.create import ActionInput; \
  print('OK: re-exports obsigna')"
```
