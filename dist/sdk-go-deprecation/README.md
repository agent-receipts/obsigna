<div align="center">

# sdk-go (deprecated)

### Go SDK for the Agent Receipts protocol

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

</div>

---

> [!WARNING]
> **This module is deprecated and no longer maintained.**
>
> `github.com/agent-receipts/sdk-go` was the historical module path for the Go
> SDK. Development has moved to the monorepo and the canonical module path is now:
>
> ```sh
> go get github.com/agent-receipts/ar/sdk/go
> ```
>
> This standalone module is frozen at its final release. It receives no further
> updates, bug fixes, or new features, and is many versions behind the canonical
> module (it lacks the `emitter`, `emitters`, and AWS KMS adapter packages, among
> others). It remains published only as a redirect target for historical
> references.

## Migrate

Replace the import path:

```diff
- import "github.com/agent-receipts/sdk-go/receipt"
+ import "github.com/agent-receipts/ar/sdk/go/receipt"
```

```diff
- import "github.com/agent-receipts/sdk-go/store"
+ import "github.com/agent-receipts/ar/sdk/go/store"
```

```diff
- import "github.com/agent-receipts/sdk-go/taxonomy"
+ import "github.com/agent-receipts/ar/sdk/go/taxonomy"
```

Then:

```sh
go get github.com/agent-receipts/ar/sdk/go@latest
go mod tidy
```

The exported API of the `receipt`, `store`, and `taxonomy` packages is
source-compatible with the canonical module, so in most cases updating the
import paths is sufficient.

## Where to go

- **Canonical Go SDK:** https://github.com/agent-receipts/obsigna/tree/main/sdk/go
- **Protocol spec:** https://github.com/agent-receipts/spec
- **Monorepo:** https://github.com/agent-receipts/obsigna

## Why

See [ADR-0023: Canonical Go Module Path](https://github.com/agent-receipts/obsigna/blob/main/docs/adr/0023-canonical-go-module-path.md)
for the full rationale.
