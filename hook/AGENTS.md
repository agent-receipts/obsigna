# AGENTS.md

Short-lived PostToolUse hook binary. Currently supports Claude Code; designed to support additional runtimes via the `formats` map in `main.go`. Reads a JSON frame from stdin, maps it to an `emitter.Event`, and forwards it to `obsigna-daemon` over a Unix-domain socket. Exits 0 when the frame is unreadable or the runtime isn't recognised; once a runtime is identified, a failure to record the receipt exits 1 with a stderr message. Never pauses or modifies the tool call. Built on [sdk/go/emitter](../sdk/go/emitter/).

## Getting started

```sh
go build ./cmd/...   # build obsigna-hook + the agent-receipts-hook shim
go test ./...        # run tests (includes integration tests on linux/darwin)
go vet ./...         # static analysis
```

## Project structure

```
cmd/obsigna-hook/          # primary binary (ADR-0036)
  main.go                  # stdin read, format detection, emitter dispatch
  claude_code.go           # Claude Code PostToolUse frame parser
  claude_transcript.go     # transcript-derived model/token-usage lookup
  main_test.go             # unit tests for readClaudeCode and detect
  integration_test.go      # end-to-end tests against a real AF_UNIX listener (linux/darwin)
  import_guard_test.go     # Gate A — fail-closed lean-import allowlist
  entrypoint_guard_test.go # obsigna-hook is primary; agent-receipts-hook only as shim
cmd/agent-receipts-hook/   # deprecation shim — syscall.Execs into obsigna-hook
  main.go
  main_test.go
```

The binary was renamed `agent-receipts-hook` → `obsigna-hook` (ADR-0036). The
shim keeps every existing runtime hook config working through the rename; it
must stay a thin forwarder (its guard test enforces that). The hook gets no
`obsigna hook run` launcher — it is a per-tool-call callback (ADR-0034 decision 5).

## Conventions

- All changes go through pull requests
- Run `go vet ./...` before committing
- The binary must always exit 0 — silent failure is the contract (ADR-0010 §"Failure model")
- No CGO — pure Go only
- Adding a new runtime format: add a `reader` func and register it in `formats` map in `main.go`

## Dependencies

`hook/go.mod` requires only `sdk/go`. `daemon` appears as `// indirect` because `sdk/go`'s
`emitter_test.go` imports it under the `integration && (linux || darwin)` build tag and
Go 1.26's tidy follows that edge. Lazy loading (go 1.17+) ensures daemon is never downloaded
when building or installing the hook binary.

## Testing

- `go test ./...` runs unit tests and integration tests (linux/darwin build tag is satisfied in CI and locally)
- Integration tests spin up an in-process `recordingListener` on a real AF_UNIX socket — no daemon process required
- `TestIntegration_DaemonDown` verifies the fire-and-forget contract: Emit completes in <250ms when the socket is unreachable

## Release

The hook ships in the unified **obsigna** release train (ADR-0034) — it no longer has its own
tag or workflow. Tagging `obsigna/vX.Y.Z` triggers `.github/workflows/release-obsigna.yml`,
which builds `obsigna-hook` plus the `agent-receipts-hook` shim (from the `hook/` module, via a
per-build `dir:`) into the umbrella `obsigna_<ver>_<os>_<arch>.tar.gz` archive and the `obsigna`
Homebrew formula. There is no standalone hook formula — the hook is non-functional without a
co-located daemon, so it ships inside the umbrella (ADR-0034 decision 6).

The release is reproducible-build attested (Gate B, ADR-0036): `release-obsigna.yml`'s
`reproducible-attest` job independently rebuilds `obsigna-hook` and asserts its sha256 matches
the released artifact, publishing the hash. CI (`hook.yml`) also runs the lean-import guard
(Gate A) and a cross-path byte-identity check. The one shared
`scripts/reproducible-build.sh` (used by every module's Gate B and the release attest) is kept
in lockstep with the `obsigna-hook` build flags in `daemon/.goreleaser.yaml`.
