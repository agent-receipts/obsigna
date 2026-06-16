<div align="center">

# agent-receipts (deprecated)

### Python SDK for the Agent Receipts protocol

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

</div>

---

> [!WARNING]
> **The `agent-receipts` distribution has been renamed to `obsigna`.**
>
> ```sh
> pip install obsigna
> ```
>
> This package is a thin redirect. It ships no implementation of its own —
> it depends on `obsigna` and re-exports it, so existing installs and imports
> keep working. Importing `agent_receipts` (or any `agent_receipts.*`
> submodule) transparently resolves to the corresponding `obsigna` module and
> emits a `DeprecationWarning`. It receives no further updates, bug fixes, or
> new features.

## Migrate

Replace the dependency:

```diff
- agent-receipts
+ obsigna
```

Replace the imports:

```diff
- from agent_receipts import create_receipt, verify_receipt
+ from obsigna import create_receipt, verify_receipt
```

```diff
- from agent_receipts.receipt.create import ActionInput
+ from obsigna.receipt.create import ActionInput
```

```diff
- from agent_receipts.aws import KMSSigner
+ from obsigna.aws import KMSSigner
```

Then:

```sh
pip install obsigna
```

The exported API of `obsigna` is identical to the final `agent-receipts`
release — only the distribution name and the top-level import package change.

## Where to go

- **Canonical Python SDK:** https://pypi.org/project/obsigna/
- **Source:** https://github.com/agent-receipts/obsigna/tree/main/sdk/py
- **Protocol spec:** https://github.com/agent-receipts/spec
