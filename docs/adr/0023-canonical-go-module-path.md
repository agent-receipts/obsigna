# ADR-0023: Canonical Go Module Path

## Status

Superseded by ADR-0037 (the canonical path moves to the `obsigna.dev/sdk/go`
vanity import path; the standalone-module deprecation, D2, still stands).

## Context

The Go SDK is currently reachable via two distinct module paths:

1. **`github.com/agent-receipts/ar/sdk/go`** — the monorepo path. This is where the SDK is actively developed (current version `v0.13.0`); the site's installation docs use this path; the collector and other Go components share the same monorepo.
2. **`github.com/agent-receipts/sdk-go`** — a standalone module path. This was the historical canonical path. The last published tag is `v0.1.0`. It contains `receipt`, `store`, and `taxonomy` packages but no `emitters`, no `aws` KMS adapter, no collector — it is 12 versions behind and missing the majority of current functionality. The `sdk/go` README in the monorepo still uses this import path.

A new Go evaluator hitting the project's front door runs `go get github.com/agent-receipts/sdk-go` per the README, resolves the stale module, compiles a hello-world against it, and either gets confused by the missing `emitters` package or assumes that is the complete SDK. The site, meanwhile, uses the monorepo path. The two surfaces disagree.

Compounding: the collector module has no semver tag, so `go install github.com/agent-receipts/ar/collector/cmd/collector@latest` pins `sdk/go` to `v0.12.1` (missing `store.Exists` added at `v0.13.0`) and fails to build. The only way to run a collector today is `git clone` + workspace build. The headline distribution channel for Go tools is broken.

The Go ecosystem's module-path mechanics make this a binary decision: a Go module has one canonical import path, and consumers reaching it via any other path resolve a different module. There is no graceful "both are fine" outcome; the project must pick one.

## Decision

### D1. The canonical Go module path is `github.com/agent-receipts/ar/sdk/go`

All Go consumers of the Agent Receipts SDK use the monorepo import path. The README, the site, every example, every documentation reference, and every SDK release tag use this path going forward.

Reasoning: the monorepo is where development actively happens, where releases are cut from, where the collector and other Go components share build infrastructure, and where the SDK's current version corresponds to the project's overall surface area. The standalone module has been stale for 12 versions; promoting it to canonical now means moving the active development *to* it, which is the opposite of where the project's investment is going.

### D2. `github.com/agent-receipts/sdk-go` is deprecated

The standalone module receives one final release tagged `v0.1.1` (or whatever increment is appropriate) whose sole content is:

1. A package-level `// Deprecated:` notice on every exported symbol, pointing at the canonical monorepo path.
2. A README rewrite stating the module is deprecated and pointing at the monorepo.
3. No code changes beyond the deprecation notices.

After that release, no further tags are published on the standalone module. The repo remains live as a redirect target for historical references but receives no updates.

### D3. The collector module is tagged independently

The collector (`github.com/agent-receipts/ar/collector`) is tagged independently of `sdk/go`. The current state — collector module has no semver tags, so `@latest` pins a stale transitive dependency — is fixed by tagging the collector at its own version (e.g. `collector/v0.13.0`) on the same commit as a corresponding `sdk/go/v0.13.x` tag, with the collector's `go.mod` requiring the matching `sdk/go` version explicitly.

Going forward, every release of `sdk/go` is accompanied by a matching collector tag if collector behaviour or dependencies changed; otherwise the collector tag is incremented independently when collector-only changes ship.

### D4. README and site updates

The `sdk/go/README.md` import paths are updated to the monorepo path. The site's installation docs (already using the monorepo path) remain canonical. Every example file in the repo using the standalone path is updated.

### D5. Release-time verification

After this ADR is implemented, a one-time verification step confirms:

1. `go get github.com/agent-receipts/ar/sdk/go@latest` resolves to the current monorepo version.
2. `go install github.com/agent-receipts/ar/collector/cmd/collector@latest` builds and produces a runnable collector binary against a fresh GOPATH.
3. The hello-world in `sdk/go/README.md` compiles and runs against `@latest`.

This verification is run manually as part of closing the ADR's implementation issue. Whether it graduates to a CI gate is a separate question (covered under the verification-contract ADR #600's gate catalogue).

## Out of scope for this ADR

- Reorganizing the broader `sdk-go` site documentation section. Independent docs work, tracked under Closure 1's Go docs reorganization issues.
- Updating the Go README's hello-world snippet content beyond the import paths. The snippet's correctness as a code snippet is covered by the documented-snippet gate (verification-contract follow-up).
- Migrating users on the standalone module. There likely are no production users on `sdk-go` given its 12-version-stale state, but if any external repos surface, they are handled case-by-case after the deprecation notice ships.

## Consequences

- `go get github.com/agent-receipts/sdk-go` continues to resolve, but emits deprecation warnings, and the docs point users away from it.
- `go get github.com/agent-receipts/ar/sdk/go` becomes the only documented install path. Resolves cleanly to the current version.
- `go install ...collector@latest` builds successfully. The project's Go tooling becomes installable via the headline distribution channel.
- Persona A following the Go README hits a working install on first try. GO-P1, GO-P2, GO-P3 close.
- The two-module-paths confusion that the audit surfaced as the worst Go first-run experience in the project no longer exists.

## Implementation issues spawned by this ADR

Filed as separate issues, blocked on this PR merging. Each is labeled `adr-followup`.

- Update all README and example import paths from `github.com/agent-receipts/sdk-go/...` to `github.com/agent-receipts/ar/sdk/go/...`. (#636)
- Publish the final deprecation release on `github.com/agent-receipts/sdk-go` per D2. (#637)
- Tag the collector module independently per D3; verify `go install ...collector@latest` builds. (#638)
- Run the D5 release-time verification and record results in the closing issue. (#639)

---

*Closes #615 when merged.*
