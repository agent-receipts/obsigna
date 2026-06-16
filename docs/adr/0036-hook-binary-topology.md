# ADR-0036: Hook Binary Topology — Minimal `obsigna-hook`, no launcher

## Status

Accepted (2026-06-13).

## Context

ADR-0030 consolidates the implementation behind a single `obsigna` entrypoint.
ADR-0031 applied a binary-topology pattern to the daemon — its own minimal
binary (`obsigna-daemon`), launched via `syscall.Exec`, with a lean import graph
(Gate A) and a reproducible build (Gate B). ADR-0033 applied the same pattern to
the MCP proxy (`obsigna-mcp`). This ADR is the hook's analogue: how the hook is
packaged as a binary, and which property its import graph must hold.

The hook is the smallest tool in the set. It is a short-lived process that
**reads a JSON frame from stdin, maps it to an `emitter.Event`, forwards it to
the daemon over an AF_UNIX socket, and exits** (ADR-0013). Two properties of the
hook shape this ADR, and both differ from the daemon and proxy:

1. **The hook must stay a thin forwarder.** ADR-0010 makes the daemon the sole
   receipt writer — it owns redaction, hashing, signing, chaining, and
   persistence — and the hook only forwards completed events (`sdk/go/emitter`).
   If the hook could construct, sign, or store receipts in-process, the "one
   writer" guarantee ADR-0010 rests on would erode silently. Keeping the receipt
   store, a SQLite (or other embedded-DB) driver, receipt construction/signing,
   the daemon library, and operator CLI packages *out* of the hook is a property
   we want to *enforce*, not merely intend — the same discipline ADR-0033 makes
   for the proxy.

2. **The hook is invoked by path, per tool call.** Agent runtimes (Claude Code
   and others) call the hook directly from their settings — a `PostToolUse`
   `"command": "agent-receipts-hook"`, resolved off `$PATH` or a hard-coded path.
   It is neither long-running nor the process an auditor attests. This is what
   makes the hook the one tool that gets **no launcher** — see Decision.

Separately, the hook ships as a downstream-installable binary that users wire
into runtime configs. The rename from `agent-receipts-hook` to `obsigna-hook`
would break every existing config that names the old binary, so the old
entrypoint is preserved as a deprecation shim rather than removed outright.

## Decision

**The hook is its own minimal binary, `cmd/obsigna-hook`.** It is the primary
entrypoint, carrying the full hook surface (stdin read, format detection,
event mapping, emitter dispatch). It links only what a thin forwarder needs: its
own `cmd/…` packages and `sdk/go/emitter` (plus `github.com/google/uuid`, which
the emitter pulls in transitively for session IDs). It never imports the receipt
store, a SQLite driver, receipt construction/signing, the daemon library, or
operator CLI packages.

**The hook gets no noun and no launcher.** There is no `obsigna hook run`, and
the launcher table in `cmd/obsigna` is left untouched. This is the asymmetry
ADR-0034 decision 5 records: the launcher exists to fix the *attestation tuple*
of a long-lived process via `syscall.Exec`, and it pays off all the way down to
**session** granularity (the MCP proxy execs once per MCP session). It does
**not** pay off at the hook's **per-event** tail, where an `obsigna hook run`
wrapper would impose an extra `exec` on every single tool call for no benefit —
the hook is neither long-lived nor the thing auditors attest. The cut is at the
session/per-event boundary.

**The legacy `agent-receipts-hook` binary becomes a thin deprecation shim**
(`cmd/agent-receipts-hook`). It prints a one-line deprecation notice to stderr
and `syscall.Exec`s into `obsigna-hook`, forwarding argv and the environment
unchanged — the hook's flag surface is identical, so there is no translation.
The shim is **load-bearing, not cosmetic**: runtimes invoke the hook by the name
in their settings, so the shim is what keeps every existing configuration
working through the rename. `syscall.Exec` (not `exec.Command`) keeps the shim
transparent — it preserves the inherited stdin/stdout/stderr and the exit status
of `obsigna-hook` and adds no second process per tool call. The shim ships in the
same archive and Homebrew formula as `obsigna-hook`. It introduces a
**transitional per-event extra exec** on the old path; users drop it by pointing
their config at `obsigna-hook`. The shim is slated for removal in a future
release.

**Reproducible builds are part of the contract.** The `obsigna-hook` binary is
built with `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, a patch-pinned
toolchain (the `go` directive in `hook/go.mod`, consumed in CI via
`go-version-file`), and version/stamp inputs that derive only from the tag/commit
(`mod_timestamp` uses `{{ .CommitTimestamp }}`, never wall-clock). This mirrors
ADR-0031/0033 exactly so an auditor can rebuild `obsigna-hook` and match a
published hash. The release establishes the known-good hash by an independent
clean rebuild that must equal the binary inside the released archive; a mismatch
fails the release.

> Note for independent rebuilders: the pinned toolchain directive is a *floor*,
> so a builder whose local Go is newer must force the exact toolchain with
> `GOTOOLCHAIN=…`. The full command is published in each release's notes.

## Gates

Per ADR-0024 (every asserted property has a gate), the claims above are enforced
in CI rather than trusted:

- **Gate A — thin-forwarder import graph**: a Go test next to the code
  (`cmd/obsigna-hook/import_guard_test.go`) runs `go list -deps .` and fails on
  any production dependency outside a small **fail-closed allowlist** — stdlib,
  the hook's own `cmd/…`, `sdk/go/emitter` (and only the emitter, not the rest of
  `sdk/go`), and `github.com/google/uuid`. An allowlist rather than a denylist is
  deliberate, matching ADR-0033: persistence has no naming convention to key on,
  so listing forbidden packages would miss a store reintroduced under a new path
  (e.g. `go.etcd.io/bbolt`, `dgraph-io/badger`). Failing closed makes *any*
  unreviewed dependency — every DB driver, plus `sdk/go/store`/`sdk/go/receipt`/
  `ar/daemon` by construction — trip the gate; adding a genuine new dependency is
  a deliberate edit to the allowlist. It runs in the normal test suite and in a
  dedicated `hook.yml` job.
- **Gate B — reproducible build** (`hook.yml` + `release-hook.yml`): both
  rebuilds go through one shared script (`hook/scripts/reproducible-build.sh`) so
  the PR gate and the release attestation can't drift, and it stays in lockstep
  with the goreleaser build flags. On every PR, build `obsigna-hook` twice from
  two working-directory paths of different lengths and assert byte-identical
  `sha256` (this is what proves `-trimpath` took effect). On release, assert an
  independent clean rebuild matches the published artifact and emit the hash;
  fail the release on mismatch.

The entrypoint guard (`cmd/obsigna-hook/entrypoint_guard_test.go`) asserts
`obsigna-hook` is the primary build and `agent-receipts-hook` appears only as the
shim, and the shim's own test (`cmd/agent-receipts-hook/main_test.go`) proves it
`syscall.Exec`s into `obsigna-hook`, forwards argv/env, and keeps every existing
config working — the property the whole rename hinges on.

## Consequences

- The `agent-receipts-hook` shim is platform-restricted to where `syscall.Exec`
  exists (darwin, linux) — the only release targets, matching ADR-0031/0033.
- `obsigna-hook` and the `agent-receipts-hook` shim ship together in the hook
  archive and are both installed by the Homebrew formula. The formula *name*
  stays `agent-receipts-hook`/`-alpha` for now; folding the hook into the unified
  `obsigna` train and umbrella formula is ADR-0034 PR 2.
- The binary rename is **breaking for any installer or runtime config that
  invokes the binary by its absolute path** rather than the `agent-receipts-hook`
  name on `$PATH`; the shim covers the common `$(which agent-receipts-hook)` case
  but not a hard-coded path to a renamed file.
- Reproducibility constrains future build changes: anything that introduces a
  wall-clock stamp, an absolute-path embed, or a floating toolchain will turn
  Gate B red. That is the point.

## Out of scope

- The unified `obsigna` release train and umbrella Homebrew formula, plus the
  `tap_migrations.json` entry retiring the `agent-receipts-hook` formula
  (ADR-0034 PR 2).
- A launcher noun for the hook — deliberately none (ADR-0034 decision 5).
- Rewriting every downstream config to `obsigna-hook` — the shim keeps the
  documented `agent-receipts-hook` invocations working in the meantime.

## Amends

- **ADR-0013** (claude_code_hook Emission Channel): the hook this ADR repackages
  is the PostToolUse/PreToolUse channel ADR-0013 specifies; the per-tool-call,
  invoked-by-path nature established there is exactly why the hook gets no
  launcher (Decision).
- **ADR-0031** (Daemon Binary Topology): applies its minimal-binary +
  `syscall.Exec` + Gate A/Gate B pattern to the hook, with one deliberate
  difference — the hook gets a deprecation shim but **no launcher**, because the
  launcher's attestation-tuple benefit does not reach per-event granularity.
- **ADR-0033** (mcp-proxy Binary Topology): the closest template; this ADR mirrors
  its thin-emitter Gate A (fail-closed allowlist) and reproducible-build Gate B
  for the hook. Where the proxy keeps its `mcp` launcher, the hook has none.
- **ADR-0034** (Consolidate the Go Toolset): records the no-launcher decision for
  the hook (decision 5) and folds the hook into the unified `obsigna` train in
  PR 2; this ADR is the per-component binary topology that PR 2 then repackages,
  exactly as ADR-0033 was for the proxy.
