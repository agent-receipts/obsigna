# SDK publishing runbook — Obsigna rename

This is the ordered, credential-bearing runbook a **maintainer** runs to publish
the renamed SDKs. The repository changes (manifests, shim, docs, CI guard) land
via PR; the registry writes below are **not** automated and **not** run by
agents — they reserve names and publish versions that cannot be cleanly pulled.

Rename summary (see also each package's CHANGELOG):

| Channel | Legacy name | New name |
|---------|-------------|----------|
| npm | `@agnt-rcpt/sdk-ts` | `@obsigna/sdk-ts` |
| npm | `@agnt-rcpt/sdk-ts-aws` | `@obsigna/sdk-ts-aws` |
| PyPI | `agent-receipts` | `obsigna` (import: `agent_receipts` → `obsigna`) |

Reserved targets confirmed available before the rename: the `@obsigna` npm scope
is free for both leaves; the `obsigna` PyPI project is already reserved by the
maintainer (a `0.0.0` placeholder release). `@agnt-rcpt/sdk-ts-aws` was **never
published**, so there is nothing to deprecate for it.

**Never** `npm unpublish`, `pip`/PyPI `yank`, or delete any existing release.
Existing version history under the legacy names stays published. Breaking
existing installs is a failure, not a cleanup.

---

## 0. Preconditions

- You have npm publish rights to the `@obsigna` scope and to the legacy
  `@agnt-rcpt/sdk-ts` package (for the deprecation pointer).
- You have a PyPI API token that owns both `obsigna` and `agent-receipts`.
- The rename PR is merged to `main`. `python3 scripts/legacy_name_guard/check.py`
  passes.
- Versions to publish (inherited from the branch): `@obsigna/sdk-ts@0.13.0-alpha.1`,
  `@obsigna/sdk-ts-aws@0.1.0`, `obsigna 0.13.0a1`.

## 1. npm — publish the renamed packages

```sh
# Core TS SDK
cd sdk/ts
pnpm install
pnpm build
npm publish --access public          # publishes @obsigna/sdk-ts

# AWS KMS signer
cd ../ts-aws
pnpm install
pnpm build
npm publish --access public          # publishes @obsigna/sdk-ts-aws
```

> If the repo's trusted-publisher workflow (`.github/workflows/publish-ts.yml`)
> is used instead of a local `npm publish`, first register `@obsigna/sdk-ts` as
> a trusted publisher on npmjs.com for this repo/workflow.

## 2. PyPI — publish `obsigna` (new package FIRST)

The shim in step 3 depends on `obsigna`, so `obsigna` must exist on the index
first.

```sh
cd sdk/py
rm -rf dist
uv build                             # builds obsigna-0.13.0a1 sdist + wheel
twine upload dist/*
```

## 3. PyPI — publish the `agent-receipts` deprecation shim

Staged content: [`dist/sdk-py-deprecation/`](../dist/sdk-py-deprecation/) (see its
[`PUBLISHING.md`](../dist/sdk-py-deprecation/PUBLISHING.md)). The shim keeps the
legacy `agent-receipts` name installable; it depends on `obsigna`, re-exports it,
and emits a `DeprecationWarning` on import. Its version (`0.13.0`) sorts above the
last real release (`0.12.0`) so a bare `pip install agent-receipts` resolves to
the redirect.

```sh
cd dist/sdk-py-deprecation
rm -rf dist
uv build
twine upload dist/*
```

## 4. npm — deprecate the legacy package

`@agnt-rcpt/sdk-ts` was published; point it at the new name. (There is no
`@agnt-rcpt/sdk-ts-aws` to deprecate — it was never published.)

```sh
npm deprecate "@agnt-rcpt/sdk-ts" "moved to @obsigna/sdk-ts"
```

## 5. Verify (no further decisions)

New names resolve:

```sh
# npm
npm view @obsigna/sdk-ts version
npm view @obsigna/sdk-ts-aws version

# PyPI
python -m venv /tmp/v-new && . /tmp/v-new/bin/activate
pip install obsigna
python -c "import obsigna; print(obsigna.VERSION)"
deactivate
```

Deprecated old names still resolve and redirect:

```sh
# npm: install still works, now shows a deprecation notice
npm view @agnt-rcpt/sdk-ts deprecated      # -> "moved to @obsigna/sdk-ts"

# PyPI: legacy name installs the shim, which pulls obsigna and warns on import
python -m venv /tmp/v-old && . /tmp/v-old/bin/activate
pip install agent-receipts                 # resolves to the 0.13.0 shim
python -W error::DeprecationWarning -c "import agent_receipts" \
  && echo "FAIL: expected a DeprecationWarning" \
  || echo "OK: import warned"
python -c "import agent_receipts, obsigna; \
  assert agent_receipts.create_receipt is obsigna.create_receipt; \
  print('OK: shim re-exports obsigna')"
deactivate
```

Done. Do not yank or unpublish anything.
