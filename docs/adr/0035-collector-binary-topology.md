# ADR-0035: Collector Binary Topology — Minimal `obsigna-collector`, `obsigna collector run`

## Status

Accepted (2026-06-13).

## Context

ADR-0030 consolidates the implementation behind a single `obsigna` entrypoint, with
the receipt collector as a verb under it (`obsigna collector run`). ADR-0031 applied
this topology to the daemon, making it its own minimal binary (`obsigna-daemon`)
launched via `syscall.Exec`; ADR-0033 did the same for the MCP proxy
(`obsigna-mcp`). This ADR is the collector's analogue: how it is packaged as a
binary and launched, and which property its import graph must hold.

The collector is a **receipt hub** (ADR-0017, ADR-0020): it receives already-signed
receipts over HTTP at `POST /receipts` and persists them to a SQLite-backed store.
Two facts place it differently from the daemon and the proxy, and together they fix
the shape of its import-graph gate:

1. **It does not hold the signing key.** ADR-0010 makes the daemon the sole receipt
   writer — it owns redaction, hashing, signing, chaining, and persistence of the
   *local* chain. The collector signs nothing, chains nothing, and verifies nothing
   on ingest; it is the "dumb append-only sink" ADR-0020 describes. Its trust story
   (ADR-0020) is precisely that a compromised collector can drop or refuse receipts
   but cannot forge, alter, or reorder them, because every receipt is signed and
   chained client-side before delivery. So the daemon's "blast radius is its import
   graph because it runs next to the private key" argument does not transfer — the
   collector holds no key.

2. **It legitimately holds a store.** Unlike the proxy — a *thin emitter* that
   ADR-0033 keeps free of any persistence (the store, a SQLite driver, receipt
   construction) — persisting receipts is the collector's *entire job*. Its
   production graph legitimately reaches `sdk/go/store`, a SQLite driver
   (`modernc.org/sqlite`), and the receipt type (`sdk/go/receipt`). The proxy's
   fail-closed *allowlist*, which exists to keep persistence *out*, would therefore
   be the wrong tool here: the collector's store is a feature, not a smell, and
   enumerating SQLite's large transitive tree would be brittle besides.

What the collector's graph must enforce is the **converse** of the proxy's: the hub
must never *link the daemon's signing/chaining library* or the operator read-side. If
the collector imported the daemon library, the "one writer" guarantee ADR-0010 rests
on would erode; if it linked the operator verify/show/list/keys tooling, a hub process
would carry an operator surface that has no business in it. Those are the two import
edges to make structural.

Note the limit of an import-graph gate, so it is not over-read: it bounds what the
collector *links*, not which functions it calls within an allowed package.
`sdk/go/receipt` is allowed — the hub needs the `AgentReceipt` type to deserialize and
store — and that package also exposes `Sign`/`Create`, so the gate cannot by itself
prove the collector never signs. That property holds for a *different* reason: the
collector holds no signing key (point 1 above), so it cannot produce a valid signature
regardless of what it links. Gate A's job is narrower and structural — keep the
*daemon's* signing/chaining library and the operator CLI out of the link — not to
police individual function calls.

Separately, the collector ships as a downstream-installable binary that operators
wire into deployment scripts and that SDK `HttpEmitter` clients post to. The rename
from `collector` to `obsigna-collector` would break installers that name the old
binary, so the old entrypoint is preserved as a deprecation shim rather than removed.

## Decision

**The collector is its own minimal binary, `cmd/obsigna-collector`.** It is the
primary entrypoint, carrying the full collector surface (the `--addr`/`--db`/
`--max-body-bytes`/`--drain-timeout`/`--version` flags). It links only what the hub
needs: the `collector` library and its legitimate dependencies — `sdk/go/store`,
`sdk/go/receipt`, and a SQLite driver. It never imports the daemon library or any
operator read-side (`*cli`) package.

**`obsigna collector run` replaces its process image with `obsigna-collector` via
`syscall.Exec`** — the same generic launcher ADR-0031 introduced for `obsigna daemon
run` and ADR-0033 reused for `obsigna mcp run`, reusing the existing launcher table
in `cmd/obsigna` (no new launcher code). `syscall.Exec` (never `exec.Command`) is
deliberate: the collector is a long-running HTTP service, so replacing the image
keeps the same PID and the supervisor as parent, indistinguishable from a service
manager starting `obsigna-collector` directly. In production, the service manager's
start command points straight at `obsigna-collector`; `obsigna collector run` is the
same image resolved beside `obsigna` (else `$PATH`) and exec'd into. The launcher
errors helpfully if the collector formula is not installed.

**The legacy `collector` binary becomes a thin deprecation shim** (`cmd/collector`).
It prints a one-line deprecation notice to stderr and `syscall.Exec`s into
`obsigna-collector`, forwarding argv and the environment unchanged — the collector's
flag surface is identical, so there is no translation. It ships in the same archive
and Homebrew formula as `obsigna-collector`, so existing installers and scripts that
name `collector` keep working through the rename. The shim is slated for removal in a
future release.

**Reproducible builds are part of the contract.** The `obsigna-collector` binary is
built with `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, a patch-pinned toolchain
(`toolchain go1.26.1` in `collector/go.mod`, consumed in CI via `go-version-file`),
and version/stamp inputs that derive only from the tag/commit (`mod_timestamp` uses
`{{ .CommitTimestamp }}`, never wall-clock). This mirrors ADR-0031/ADR-0033 exactly
so an auditor can rebuild `obsigna-collector` and match a published hash. The release
establishes the known-good hash by an independent clean rebuild that must equal the
binary inside the released archive; a mismatch fails the release.

> Note for independent rebuilders: the pinned `toolchain` directive is a *floor*, so
> a builder whose local Go is newer than 1.26.1 must force the exact toolchain with
> `GOTOOLCHAIN=go1.26.1`. The full command is published in each release's notes.

## Gates

Per ADR-0024 (every asserted property has a gate), the claims above are enforced in CI
rather than trusted:

- **Gate A — dumb-sink import graph** (`cmd/obsigna-collector/import_guard_test.go`):
  a Go test runs `go list -deps .` and fails on any production dependency that
  reaches the **daemon library** (`github.com/agent-receipts/ar/daemon…`, the signer)
  or any **operator read-side CLI package** (`internal/*cli` — verify/show/list/
  doctor/keys, keyed on the `cli` suffix so a new operator package is caught
  automatically). This is a **denylist**, the deliberate inverse of ADR-0033's
  fail-closed allowlist: the proxy fails closed because persistence has no naming
  convention and must be kept out, whereas the collector *legitimately* persists
  (`sdk/go/store`, `sdk/go/receipt`, `modernc.org/sqlite` are all allowed), so the
  property to enforce is not "no store" but "never *links* the daemon's signing
  library, never *links* the operator CLI". (The gate bounds the link, not function
  calls within an allowed package — `sdk/go/receipt` is allowed and also exposes
  `Sign`/`Create`; the collector does not sign because it holds no key, not because
  the gate forbids the call.) It runs in the normal test suite and in a dedicated
  `collector.yml` job.
- **Gate B — reproducible build** (`collector.yml` + `release-collector.yml`): both
  rebuilds go through one shared script (`collector/scripts/reproducible-build.sh`)
  so the PR gate and the release attestation can't drift, and it stays in lockstep
  with the goreleaser build flags. On every PR, build `obsigna-collector` twice from
  two working-directory paths of different lengths and assert byte-identical `sha256`
  (this is what proves `-trimpath` took effect). On release, assert an independent
  clean rebuild matches the published artifact and emit the hash; fail the release on
  mismatch.

The launcher exec path and the `collector` → `obsigna-collector` mapping are covered
by the existing `cmd/obsigna` surface tests (`TestLauncherSurface`); the
entrypoint guard (`cmd/obsigna-collector/entrypoint_guard_test.go`) asserts
`obsigna-collector` is the primary build and `collector` appears only as the shim.

## Consequences

- The launcher in `cmd/obsigna` and the `collector` shim are platform-restricted to
  where `syscall.Exec` exists (darwin, linux) — the only release targets, matching
  ADR-0031/ADR-0033.
- `obsigna-collector` and the `collector` shim ship together in the collector archive
  and are both installed by the Homebrew formula. The formula *name* stays `collector`
  (a downstream tap concern); only the installed binary is renamed, plus the shim. A
  formula-name migration is a separate effort (ADR-0034).
- The binary rename is **breaking for any installer that invokes the binary by its
  absolute path** rather than the `collector` name on `$PATH`; the shim covers the
  common `$(which collector)` case but not a hard-coded path to a renamed file.
- `obsigna collector run` only succeeds when both `obsigna` and `obsigna-collector`
  are installed. Until ADR-0034's PR-2 folds the collector into the umbrella
  `obsigna` formula, that means installing the collector formula alongside obsigna;
  the launcher errors helpfully when the sibling binary is absent.
- Reproducibility constrains future build changes: anything that introduces a
  wall-clock stamp, an absolute-path embed, or a floating toolchain will turn Gate B
  red. That is the point.

## Out of scope

- The unified-train consolidation (ADR-0034 PR-2): the collector keeps its own
  `collector/v*` train, `release-collector.yml`, CHANGELOG, and `collector` Homebrew
  formula for now. This ADR delivers the minimal-binary restructure that PR-2
  sequences ahead of; it does **not** pre-consolidate.
- The Homebrew formula-name migration (`collector` → an `obsigna` formula, ADR-0034
  decision 9). No standalone `collector-alpha` track is introduced.
- Collector ingest-side concerns — authentication, multi-tenant isolation, and
  optional signature verification on ingest — are unchanged; the collector remains a
  dumb append-only sink (ADR-0020).
- The daemon, mcp-proxy, and hook restructures (their own ADRs).

## Amends

- **ADR-0031** (Daemon Binary Topology): generalizes its `syscall.Exec` launcher and
  minimal-binary pattern from the daemon to the collector, and reuses its
  reproducible-build contract (Gate B) unchanged.
- **ADR-0033** (mcp-proxy Binary Topology): reuses its `obsigna-<noun>` binary +
  deprecation-shim + sibling-resolution template, but **inverts its Gate A**. The
  proxy uses a fail-closed *allowlist* because it must hold no store; the collector
  uses a *denylist* because it legitimately holds one — the gate forbids the signer
  and the operator CLI instead of forbidding persistence.
- **ADR-0034** (Consolidate the Go Toolset into One obsigna Release Train): supplies
  the `collector` launcher entry (decision 5) and the `obsigna-collector` binary name
  (decision 2). ADR-0034's PR-2 lists this collector restructure as its prerequisite;
  this ADR delivers exactly that restructure while leaving the collector on its own
  train and formula, which PR-2 will later fold into the unified `obsigna` train.
