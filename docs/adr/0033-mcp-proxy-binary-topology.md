# ADR-0033: mcp-proxy Binary Topology — Minimal `obsigna-mcp`, `obsigna mcp run`

## Status

Accepted (2026-06-12).

## Context

ADR-0030 consolidates the implementation behind a single `obsigna` entrypoint, with
the MCP proxy as a verb under it (`obsigna mcp run`). ADR-0031 applied this to the
daemon, making it its own minimal binary (`obsigna-daemon`) launched via `syscall.Exec`.
ADR-0032 settled the proxy's transport — stdio only, one principal per process, HTTP
deferred. This ADR is the proxy's analogue of ADR-0031: how the proxy is packaged as a
binary and launched, and which property its import graph must hold.

The proxy is unlike the daemon in one load-bearing way: **it does not hold the signing
key.** ADR-0010 makes the daemon the sole receipt writer — it owns redaction, hashing,
signing, chaining, and persistence — and the proxy is a *thin emitter* that forwards
completed tool-call events over a Unix-domain socket (`sdk/go/emitter`). So the daemon's
"blast radius is its import graph because it runs next to the private key" argument does
not transfer. The proxy's import graph matters for a different reason:

1. **The proxy must stay a thin emitter.** If the proxy could construct, sign, or store
   receipts in-process, the "one writer" guarantee that ADR-0010 rests on would erode
   silently — two writers with subtly different canonicalization or redaction would
   produce divergent receipts for the same action. Keeping the store, the SQLite driver,
   receipt construction/signing, and the daemon library *out* of the proxy is a property
   we want to *enforce*, not merely intend. This is the same one-responsibility-per-process
   discipline ADR-0032 makes for the proxy's transport (one principal per process); here
   it is one *writer* per pipeline.

2. **The proxy is what an MCP client spawns.** Clients invoke MCP servers per session over
   stdio (ADR-0032). The proxy sits in that stdio pipe between client and server, so the
   way it is launched — and the identity of the process the client spawned — must be
   preserved across any indirection.

Separately, the proxy ships as a downstream-installable binary that users wire into MCP
client configs. The rename from `mcp-proxy` to `obsigna-mcp` would break every existing
config that names the old binary, so the old entrypoint is preserved as a deprecation
shim rather than removed outright.

## Decision

**The proxy is its own minimal binary, `cmd/obsigna-mcp`.** It is the primary entrypoint,
carrying the full proxy surface (`serve`/`doctor`/`init`). It links only what a thin
emitter needs: the proxy's `internal/{audit,host,policy,proxy}` packages and
`sdk/go/emitter`. It never imports the receipt store, a SQLite driver, receipt
construction/signing, or the daemon library.

**`obsigna mcp run` replaces its process image with `obsigna-mcp` via `syscall.Exec`** —
the same generic launcher ADR-0031 introduced for `obsigna daemon run`, reusing the
existing launcher table in `cmd/obsigna` (no new launcher code). `syscall.Exec` (never
`exec.Command`) is deliberate: the proxy is a long-running stdio process pumping bytes
between an MCP client and server. Replacing the image keeps the same PID and inherited
stdin/stdout/stderr, so the proxy a client spawned via `obsigna mcp run` is
indistinguishable from one spawned directly at `obsigna-mcp`, with no extra process in the
pipe. In production, an MCP client's command points straight at `obsigna-mcp` (or
`obsigna mcp run`).

**The legacy `mcp-proxy` binary becomes a thin deprecation shim** (`cmd/mcp-proxy`). It
prints a one-line deprecation notice to stderr and `syscall.Exec`s into `obsigna-mcp`,
forwarding argv and the environment unchanged — the proxy's command surface is identical,
so there is no translation. It ships in the same archive and Homebrew formula as
`obsigna-mcp`, so existing MCP client configs that name `mcp-proxy` keep working through
the rename. The shim is slated for removal in a future release.

**Reproducible builds are part of the contract.** The `obsigna-mcp` binary is built with
`CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, a patch-pinned toolchain
(`toolchain go1.26.1` in `mcp-proxy/go.mod`, consumed in CI via `go-version-file`), and
version/stamp inputs that derive only from the tag/commit (`mod_timestamp` uses
`{{ .CommitTimestamp }}`, never wall-clock). This mirrors ADR-0031 exactly so an auditor
can rebuild `obsigna-mcp` and match a published hash. The release establishes the
known-good hash by an independent clean rebuild that must equal the binary inside the
released archive; a mismatch fails the release.

> Note for independent rebuilders: the pinned `toolchain` directive is a *floor*, so a
> builder whose local Go is newer than 1.26.1 must force the exact toolchain with
> `GOTOOLCHAIN=go1.26.1`. The full command is published in each release's notes.

## Gates

Per ADR-0024 (every asserted property has a gate), the two claims above are enforced in CI
rather than trusted:

- **Gate A — thin-emitter import graph**: a Go test next to the code
  (`cmd/obsigna-mcp/import_guard_test.go`) runs `go list -deps .` and fails on any
  production dependency outside a small **fail-closed allowlist** — stdlib, the proxy's own
  `internal/{audit,host,policy,proxy}` and `cmd/…`, `sdk/go/emitter` (and only the emitter,
  not the rest of `sdk/go`), `google/uuid`, and `gopkg.in/yaml.v3`. An allowlist rather than
  a denylist is deliberate: persistence has no naming convention the daemon's `cli`-suffix
  trick could key on, so listing forbidden packages would miss a store reintroduced under a
  new path (e.g. `go.etcd.io/bbolt`, `dgraph-io/badger`). Failing closed makes *any*
  unreviewed dependency — every DB driver, plus `sdk/go/store`/`sdk/go/receipt`/`ar/daemon`
  by construction — trip the gate; adding a genuine new dependency is a deliberate edit to
  the allowlist. It runs in the normal test suite and in a dedicated `mcp-proxy.yml` job.
  (`database/sql/driver`, an interface-only package pulled in transitively by `google/uuid`,
  is stdlib and so allowed — there is no DB engine behind it.)
- **Gate B — reproducible build** (`mcp-proxy.yml` + `release-mcp-proxy.yml`): both
  rebuilds go through one shared script (`mcp-proxy/scripts/reproducible-build.sh`) so the
  PR gate and the release attestation can't drift, and it stays in lockstep with the
  goreleaser build flags. On every PR, build `obsigna-mcp` twice from two
  working-directory paths of different lengths and assert byte-identical `sha256` (this is
  what proves `-trimpath` took effect). On release, assert an independent clean rebuild
  matches the published artifact and emit the hash; fail the release on mismatch.

The launcher exec path and the `mcp` → `obsigna-mcp` mapping are covered by the existing
`cmd/obsigna` surface tests (`TestLauncherSurface`); the entrypoint guard
(`cmd/obsigna-mcp/entrypoint_guard_test.go`) asserts `obsigna-mcp` is the primary build
and `mcp-proxy` appears only as the shim.

## Consequences

- The launcher in `cmd/obsigna` and the `mcp-proxy` shim are platform-restricted to where
  `syscall.Exec` exists (darwin, linux) — the only release targets, matching ADR-0031.
- `obsigna-mcp` and the `mcp-proxy` shim ship together in the proxy archive and are both
  installed by the Homebrew formula. The formula *names* stay `mcp-proxy`/`mcp-proxy-alpha`
  (a downstream tap concern); only the installed binary is renamed, plus the shim. A
  formula-name migration is a separate effort.
- The binary rename is **breaking for any installer or MCP client config that invokes the
  binary by its absolute path** rather than the `mcp-proxy` name on `$PATH`; the shim
  covers the common `$(which mcp-proxy)` case but not a hard-coded path to a renamed file.
- Reproducibility constrains future build changes: anything that introduces a wall-clock
  stamp, an absolute-path embed, or a floating toolchain will turn Gate B red. That is the
  point.

## Out of scope

- HTTP / multi-tenant transport (ADR-0032).
- The collector restructure (its own future ADR).
- The Homebrew formula-name migration (`mcp-proxy` → an `obsigna-…` formula).
- Rewriting the site's MCP-client-config docs to `obsigna-mcp` — a tracked follow-up; the
  shim keeps the documented `mcp-proxy` invocations working in the meantime.
