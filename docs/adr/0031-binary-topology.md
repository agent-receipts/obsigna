# ADR-0031: Daemon Binary Topology — Dispatcher + Minimal Daemon

## Status

Accepted (2026-06-12).

## Context

ADR-0030 consolidates the implementation behind a single `obsigna` entrypoint. The
daemon is one of the verbs under it (`obsigna daemon run`). But the daemon is unlike the
other verbs: it is the long-running process that owns the Ed25519 signing key and the
SQLite receipt store. Two properties follow from that, and both are load-bearing for the
protocol's trust story:

1. **The daemon is the thing auditors attest.** A relying party who wants to know "what
   binary signed these receipts" inspects the running process: its executable identity
   (`/proc/self/exe`), its supervisor (parent PID — systemd, not a user shell), and its
   start time. Together these are the *attestation tuple*. If `obsigna` (a fat CLI that
   also verifies, lists, rotates keys, and shells out to subcommands) *were* the daemon
   process, the tuple would describe the CLI, not the signer, and the attestation would be
   meaningless.

2. **The daemon's blast radius is its import graph.** Every package linked into the
   signing process is code that runs next to the private key. The operator-facing
   read-side surface (receipt verify/show/list, key rotation tooling, doctor, disclosure)
   has no business in that process. Keeping it out is a property we want to *enforce*, not
   merely intend.

Separately, claim (1) is only true if auditors can independently reproduce the daemon
binary and match a published hash. A build that embeds wall-clock time, absolute
filesystem paths, or a floating toolchain version is not byte-reproducible, so the
"rebuild and compare" attestation is false. Reproducibility is therefore a requirement of
this topology, not a nicety bolted on later.

## Decision

**The daemon is its own minimal binary, `cmd/obsigna-daemon`.** It links only what the
signing process needs: the daemon core plus the shared `internal/{anchor, chain,
keysource, socket, pipeline}` packages and the `sdk/go` crypto/store/canonicalization
libraries. It never imports the operator CLI packages.

**`obsigna daemon run` replaces its process image with `obsigna-daemon` via
`syscall.Exec` — it never forks a child (`exec.Command`).** Forking would make `obsigna`
the daemon's parent, so the daemon's parent PID would point at a launcher that exits
immediately rather than at the supervisor. `syscall.Exec` preserves the PID, the parent
PID, the start time, and the inherited stdio/file descriptors, so a daemon started via
`obsigna daemon run` is indistinguishable from one systemd `ExecStart`'d directly at
`obsigna-daemon`. **In production, systemd's `ExecStart` points straight at
`obsigna-daemon`;** `obsigna daemon run` is a convenience that resolves the same binary
(beside `obsigna`, else on `$PATH`) and execs into it.

**Reproducible builds are part of the contract.** The daemon binary is built with:

- `CGO_ENABLED=0` — no host C toolchain bytes leak in;
- `-trimpath` — no absolute `$GOPATH`/working-directory paths are baked in;
- `-buildvcs=false` — no git VCS stamp is embedded (GoReleaser's `before` hook copies
  LICENSE into `daemon/`, leaving an untracked file that would otherwise flip
  `vcs.modified` and make the released binary differ from a clean rebuild without it);
- a patch-pinned toolchain — `toolchain go1.26.1` in `daemon/go.mod`, consumed in CI via
  `setup-go` with `go-version-file` so it cannot float to the latest 1.26.x;
- version/stamp inputs that derive only from the tag and commit — the version is injected
  via `-ldflags -X main.version`, and GoReleaser's `mod_timestamp` uses
  `{{ .CommitTimestamp }}` (never `{{ .Date }}`/wall-clock).

**The published known-good hash is established by the release.** The release workflow does
an independent clean rebuild of `obsigna-daemon`, asserts its `sha256` equals the binary
inside the released archive, and publishes that hash into the GitHub Release (release
notes plus an `obsigna-daemon-<os>-<arch>.sha256` asset). A mismatch fails the release.
This is the value auditors compare their own rebuild against.

> Note for independent rebuilders: because the pinned `toolchain` directive is a *floor*,
> a builder whose local Go is newer than 1.26.1 must force the exact toolchain with
> `GOTOOLCHAIN=go1.26.1` to reproduce the published bytes. The full command is published
> in each release's notes.

## Gates

Per ADR-0024 (every asserted property has a gate), the two claims above are enforced in
CI rather than trusted:

- **Gate A — lean import graph**: a Go test next to the code
  (`cmd/obsigna-daemon/import_guard_test.go`) runs `go list -deps .` and fails on any
  dependency matching `internal/<name>cli` — the operator read-side packages
  (verifycli, showcli, listcli, verifyeventcli, doctorcli, keyscli, disclosecli, and any
  future sibling). Keying on the `cli` suffix rather than an enumerated list means a newly
  added operator package is denied automatically. It runs in the normal test suite and in
  a dedicated `daemon.yml` job; the daemon's shared crypto/store packages
  (`internal/{anchor,chain,keysource,socket,pipeline}`) and `sdk/go` carry no `cli`
  suffix and are allowed.
- **Gate B — reproducible build** (`daemon.yml` + `release-daemon.yml`): both rebuilds go
  through one shared script (`daemon/scripts/reproducible-build.sh`) so the PR gate and the
  release attestation can't drift, and it stays in lockstep with the goreleaser build
  flags. On every PR, build `obsigna-daemon` twice from two working-directory paths of
  different lengths and assert byte-identical `sha256` (this is what proves `-trimpath`
  took effect). On release, assert an independent clean rebuild matches the published
  artifact and emit the hash; fail the release on mismatch.

The attestation tuple itself is covered by a unit test
(`cmd/obsigna/daemon_test.go`): `obsigna daemon run` is shown to replace its image (the
daemon runs under the launcher's own PID, not as a forked child), keep the launcher's
parent, and resolve to `obsigna-daemon`.

## Consequences

- The launcher in `cmd/obsigna` is platform-restricted to where `syscall.Exec` exists
  (darwin, linux) — the only release targets. This is intentional; a fork-based fallback
  would silently corrupt the attestation tuple, so there is none.
- `obsigna-daemon` ships as its own binary in the daemon archive (alongside `obsigna` and
  the `agent-receipts` deprecation shim) and is installed by the Homebrew formula. The
  formula *names* stay `agent-receipts-daemon`/`-alpha` (a downstream tap concern); only
  the installed binary is renamed.
- Reproducibility constrains future build changes: anything that introduces a wall-clock
  stamp, an absolute-path embed, or a floating toolchain will turn Gate B red. That is the
  point.

## Out of scope

The collector and mcp-proxy restructures, the operator CLI surface (ADR-0030), and the
proxy transport decision are not addressed here.
