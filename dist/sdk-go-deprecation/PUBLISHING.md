# Publishing the final deprecation release

> Maintainer note — not part of the module's public API. Delete or keep at your
> discretion before tagging.

This directory is the **staged content for the final deprecation release** of the
standalone module `github.com/agent-receipts/sdk-go`, per
[ADR-0023 D2](https://github.com/agent-receipts/obsigna/blob/main/docs/adr/0023-canonical-go-module-path.md)
(tracked by agent-receipts/obsigna#637).

## What this is

The standalone `sdk-go` repository is separate from the `agent-receipts/obsigna`
monorepo and is not checked out in the environment where this was prepared. This
directory holds the files to copy into the root of the `sdk-go` repository for its
final release.

It contains the `receipt`, `store`, and `taxonomy` packages — the three packages
the standalone module historically shipped — with:

1. A package-level `// Deprecated:` notice on each package.
2. A `// Deprecated:` notice on every exported symbol, pointing at the canonical
   path `github.com/agent-receipts/ar/sdk/go`.
3. A rewritten `README.md` stating the module is deprecated.

## Provenance

The source was taken from the monorepo's `sdk/go` packages and the internal import
`github.com/agent-receipts/ar/sdk/go/receipt` rewritten to
`github.com/agent-receipts/sdk-go/receipt`. The deprecation notices are the only
behavioural change. Monorepo-coupled test files (which reference `../../../spec`
and `../../../cross-sdk-tests`) were not copied; add tests from the existing
`sdk-go` repo if a test gate is required for the release.

## Publish

1. Copy `go.mod`, `go.sum`, `README.md`, and the `receipt/`, `store/`, `taxonomy/`
   directories into the root of the `github.com/agent-receipts/sdk-go` repo.
2. `go build ./... && go vet ./...` to confirm it compiles cleanly.
3. Commit, then tag the final release:

   ```sh
   git tag v0.1.1
   git push origin v0.1.1
   ```

4. Do not publish further tags on the standalone module after this one.
