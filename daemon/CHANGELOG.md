# Changelog

All notable changes to `obsigna-daemon` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.26.0] - 2026-06-14

### Changed

- **Receipt principal is derived from the kernel-attested peer uid** instead of always being the `did:user:unknown` sentinel. When an emitter supplies no principal (the common case today), live and `events_dropped` receipts now record `principal.id` as `did:user:<login>`, resolved from the connecting process's uid — the same `LOCAL_PEERCRED`/`SO_PEERCRED` identity the daemon already vouches for in `action.peer_credential`, so the principal inherits that field's tamper-evidence rather than trusting an emitter self-report. The uid is the attested fact; the login name is the daemon's lookup of it on its own host. It falls back to the numeric `did:user:<platform>:<uid>` when the host user database has no entry (containers, directory-only users, deleted accounts), and to `did:user:unknown` on platforms with no POSIX uid and on synthetic chain-interrupted terminator receipts (which have no connecting peer). The derived DID names the OS user, not a configured human or authorization grant; mapping a uid to a named principal or mandate is a higher layer on top of this attested floor. No schema change — `principal.id` was already a free-form DID string.

## [0.25.0] - 2026-06-13

### Changed

- **Go toolset folded into one obsigna release train** (ADR-0034, PR 2) — `mcp-proxy`, `collector`, and `hook` no longer release on their own `mcp-proxy/v*`, `collector/v*`, and `hook/v*` trains. The single obsigna GoReleaser (`daemon/.goreleaser.yaml`) now builds all five primary binaries — `obsigna`, `obsigna-daemon`, `obsigna-mcp`, `obsigna-collector`, `obsigna-hook` — plus their four deprecation shims (`agent-receipts`, `mcp-proxy`, `collector`, `agent-receipts-hook`), each from its own Go module via a per-build `dir:` + `GOWORK=off` so published dependencies still resolve per module (not the in-tree `sdk/go`). All nine binaries ship in one `obsigna_<ver>_<os>_<arch>.tar.gz`. The standalone `release-mcp-proxy.yml`, `release-collector.yml`, and `release-hook.yml` workflows are deleted; their release-side reproducible-build attestations fold into `release-obsigna.yml`, which now rebuilds and publishes a sha256 for each of the five primary binaries from the one archive. Per-module CI (Gate A + the PR-side Gate B two-path byte-identity check) is unchanged.
- **One umbrella Homebrew formula installs the whole toolset** (ADR-0034 decisions 4 & 6) — `brew install agent-receipts/tap/obsigna` now installs all five binaries and four shims. The hook returns to the umbrella, so the formula no longer directs users to a separate `agent-receipts-hook` formula. The retired `mcp-proxy`, `mcp-proxy-alpha`, `collector`, `agent-receipts-hook`, and `agent-receipts-hook-alpha` formulae migrate to `obsigna`/`obsigna-alpha` via the tap's `tap_migrations.json`, so `brew update && brew upgrade` moves existing installs with no manual step.
- **Build tooling de-duplicated** — the now-orphaned per-module `mcp-proxy/.goreleaser.yaml`, `collector/.goreleaser.yaml`, and `hook/.goreleaser.yaml` (whose only consumers were the deleted release workflows) are removed; `daemon/.goreleaser.yaml` is the single GoReleaser config. The four per-module `reproducible-build.sh` scripts collapse into one `scripts/reproducible-build.sh` that takes the main package as an argument, so the determinism flags can no longer drift per module; every module's Gate B and the release attest call it.

This is the unified-version step of ADR-0034 decision 3: every tool now ships at the obsigna train's version even when its bytes are unchanged (byte-identity is still proven by Gate B). The obsigna CLI is now attested too, alongside the four binaries that already were. **Go module paths (`github.com/agent-receipts/ar/...`), the `obsigna mcp`/`obsigna collector` launcher table, and `did:agent-receipts-daemon:` issuer strings are unchanged.**

## [0.24.0] - 2026-06-13

### Changed

- **Release train renamed `daemon` → `obsigna`** (ADR-0034, PR 1) — the GoReleaser project, the release archive (`daemon_<ver>_<os>_<arch>.tar.gz` → `obsigna_<ver>_<os>_<arch>.tar.gz`), the tag scheme (`daemon/v*` → `obsigna/v*`), the release workflow (`release-daemon.yml` → `release-obsigna.yml`), and the Homebrew formulae (`obsigna-daemon` → `obsigna`, `obsigna-daemon-alpha` → `obsigna-alpha`) now carry the Obsigna brand, so `brew install agent-receipts/tap/obsigna` installs the toolset. This is the packaging-identity rename ADR-0031 deferred as a "downstream tap concern"; the next hop (folding `mcp-proxy`/`collector`/`hook` into the train) lands in PR 2. The tap's `tap_migrations.json` maps the retired formula names so `brew update && brew upgrade` moves existing installs with no manual step. **Binary names are unchanged** — the archive still ships `obsigna`, `obsigna-daemon`, and the `agent-receipts` shim, the Go module path stays `github.com/agent-receipts/ar/daemon`, and `did:agent-receipts-daemon:` issuer strings are untouched.
- **Doctor output and error messages now say `obsigna doctor`** (not `agent-receipts doctor`), matching the renamed CLI.

### Fixed

- **Linux `install.sh` extracts the release archive correctly** — the installer passed `tar --strip-components=1`, assuming a wrapping top-level directory, but GoReleaser archives are flat (binaries at the root, as the release attestation gate and `scripts/daemon_protocol/check.py` already assume). The strip dropped every file, so the post-extract smoke-test failed and no binaries were installed. Removed the strip so the curl-pipe installer works.
- **`obsigna doctor` auto-detects the daemon's active chain** — with no `--chain-id`/`AGENTRECEIPTS_CHAIN_ID`, doctor now resolves the chain to inspect from the store's most recently written root chain (via `store.LatestRootChainID`) instead of assuming today's UTC date. The old default produced a spurious `chain head` warn and a `round-trip` **fail** ("did not land … the daemon may not be the sole writer") whenever the daemon's chain id was not literally today's UTC date — i.e. a configured `chain_id`, a daemon running across a UTC-midnight rollover, or a rolled `-N` suffix. The synthetic event was traversing the pipeline correctly all along; doctor was just polling the wrong chain. The bare UTC date remains the fallback only for an empty store.

## [0.23.0] - 2026-06-12

### Changed

- **Homebrew formula renamed `agent-receipts-daemon` → `obsigna-daemon`** (and `agent-receipts-daemon-alpha` → `obsigna-daemon-alpha`) — the final step of the Obsigna rebrand. The installed binary has been `obsigna-daemon` since 0.22.0 (ADR-0031); now the formula itself carries the brand: `brew install agent-receipts/tap/obsigna-daemon`. Existing installs migrate transparently — the tap's `tap_migrations.json` maps the old formula names to the new ones, so `brew update && brew upgrade` moves users with no manual step. The formula's `conflicts_with` (stable ↔ alpha) is updated accordingly. The `obsigna-daemon` binary, the `brew services` integration, data paths (`~/.local/share/agent-receipts/`), the `agentreceipts` OS user, `AGENTRECEIPTS_*` env vars, and `did:agent-receipts-daemon:` issuer strings are all unchanged.

## [0.22.0] - 2026-06-12

Graduates the 0.19.0-alpha.1 … 0.22.0-alpha.1 series to stable. No code changes since 0.22.0-alpha.1; this entry consolidates the CLI rename (ADR-0030) and daemon binary rename (ADR-0031) along with the reproducible-build attestation gates that shipped across those alphas.

### Added

- **`obsigna` CLI** (ADR-0030) — the receipt CLI is renamed `agent-receipts` → `obsigna` with a grouped noun-verb surface: `obsigna receipt {verify,show,list,verify-event}`, `obsigna keys {generate,pubkey,rotate}`, and `obsigna doctor`. Flat aliases `obsigna verify` / `obsigna show` are preserved as a closed set for the verbs that live in existing scripts. `keys generate` and `keys rotate` mirror `agent-receipts-daemon --init` / `--rotate`; `keys pubkey` prints the SPKI public key. A golden surface test freezes the command tree so any drift from ADR-0030 fails CI.

### Changed

- **Daemon binary renamed `agent-receipts-daemon` → `obsigna-daemon`** (ADR-0031) — the daemon process binary is now `obsigna-daemon`, built from `./cmd/obsigna-daemon`. `obsigna daemon run` execs the renamed binary via `syscall.Exec`, preserving the attestation tuple (the daemon's issuer identity and signing key are unchanged — `did:agent-receipts-daemon:` issuer strings are untouched). The Homebrew formulae, `brew services`, and the release archives now install and launch `obsigna-daemon`. **Breaking for operators:** any install script, systemd unit, launchd plist, `brew services` invocation, or wrapper that references the `agent-receipts-daemon` binary by name must be updated to `obsigna-daemon`, and the service restarted after upgrading. The Homebrew formula names are unchanged (`agent-receipts-daemon` / `agent-receipts-daemon-alpha`) — only the installed binary was renamed.

- **`agent-receipts` is now a deprecation shim** — it keeps every historical subcommand working (`verify`, `show`, `list`, `verify-event`, `doctor`) by printing a one-line deprecation notice to **stderr** (never stdout, so piped output stays byte-clean) and forwarding to the equivalent `obsigna` command, exiting with the forwarded status. The Homebrew formula now installs `obsigna` alongside `obsigna-daemon` and the shim.

### Build

- **Reproducible-build attestation gates** (ADR-0031) — two CI gates protect the rename and the build provenance. **Gate A** is a lean import-graph test (`cmd/obsigna-daemon/import_guard_test.go`) that fails if the long-running `obsigna-daemon` signing process links any operator read-side CLI package (`internal/*cli`) — a blast-radius control keyed on the `cli` suffix so new operator packages are denied automatically. **Gate B** is a reproducible-build gate: the `obsigna-daemon` build pins the toolchain (`go.mod` `toolchain`, consumed via `go-version-file` in CI), sets `-trimpath`, `-buildvcs=false`, `CGO_ENABLED=0`, and `mod_timestamp` from the commit timestamp so the binary is a deterministic function of the commit. The PR check rebuilds along two paths and compares; the release side rebuilds and publishes a SHA-256 attestation. Build flags are kept in lockstep between `daemon/.goreleaser.yaml` and `daemon/scripts/reproducible-build.sh`.

- **`action.target.{system,resource}` on signed receipts** ([#784](https://github.com/agent-receipts/obsigna/pull/784), ADR-0029) — `validateFrame` enforces all-or-nothing consistency (both fields must be set together or both absent), caps `target_system` at 256 bytes and `target_resource` at 4096 bytes. `buildAndSign` maps validated frame target fields into `action.target` on the signed receipt.

## [0.22.0-alpha.1] - 2026-06-12

### Changed

- **Daemon binary renamed `agent-receipts-daemon` → `obsigna-daemon`** (ADR-0031) — the daemon process binary is now `obsigna-daemon`, built from `./cmd/obsigna-daemon`. `obsigna daemon run` execs the renamed binary via `syscall.Exec`, preserving the attestation tuple (the daemon's issuer identity and signing key are unchanged — `did:agent-receipts-daemon:` issuer strings are untouched). The Homebrew formulae, `brew services`, and the release archives now install and launch `obsigna-daemon`. **Breaking for operators:** any install script, systemd unit, launchd plist, `brew services` invocation, or wrapper that references the `agent-receipts-daemon` binary by name must be updated to `obsigna-daemon`, and the service restarted after upgrading. The Homebrew formula names are unchanged (`agent-receipts-daemon` / `agent-receipts-daemon-alpha`) — only the installed binary was renamed.

### Build

- **Reproducible-build attestation gates** (ADR-0031) — two CI gates protect the rename and the build provenance. **Gate A** is a lean import-graph test (`cmd/obsigna-daemon/import_guard_test.go`) that fails if the long-running `obsigna-daemon` signing process links any operator read-side CLI package (`internal/*cli`) — a blast-radius control keyed on the `cli` suffix so new operator packages are denied automatically. **Gate B** is a reproducible-build gate: the `obsigna-daemon` build pins the toolchain (`go.mod` `toolchain`, consumed via `go-version-file` in CI), sets `-trimpath`, `-buildvcs=false`, `CGO_ENABLED=0`, and `mod_timestamp` from the commit timestamp so the binary is a deterministic function of the commit. The PR check rebuilds along two paths and compares; the release side rebuilds and publishes a SHA-256 attestation. Build flags are kept in lockstep between `daemon/.goreleaser.yaml` and `daemon/scripts/reproducible-build.sh`.

## [0.21.0-alpha.1] - 2026-06-12

### Added

- **`obsigna` CLI** (ADR-0030) — the receipt CLI is renamed `agent-receipts` → `obsigna` with a grouped noun-verb surface: `obsigna receipt {verify,show,list,verify-event}`, `obsigna keys {generate,pubkey,rotate}`, and `obsigna doctor`. Flat aliases `obsigna verify` / `obsigna show` are preserved as a closed set for the verbs that live in existing scripts. `keys generate` and `keys rotate` mirror `agent-receipts-daemon --init` / `--rotate`; `keys pubkey` prints the SPKI public key. A golden surface test freezes the command tree so any drift from ADR-0030 fails CI. The daemon, collector, and mcp-proxy binaries are unchanged (out of scope for this rename).

### Changed

- **`agent-receipts` is now a deprecation shim** — it keeps every historical subcommand working (`verify`, `show`, `list`, `verify-event`, `doctor`) by printing a one-line deprecation notice to **stderr** (never stdout, so piped output stays byte-clean) and forwarding to the equivalent `obsigna` command, exiting with the forwarded status. The Homebrew formula now installs `obsigna` alongside `agent-receipts-daemon` and the shim.

## [0.20.0-alpha.1] - 2026-06-12

### Added

- **`action.target.{system,resource}` on signed receipts** ([#784](https://github.com/agent-receipts/obsigna/pull/784), ADR-0029) — `validateFrame` enforces XOR consistency (both fields set or both absent), caps `target_system` at 256 bytes and `target_resource` at 4096 bytes (Linux PATH_MAX). `buildAndSign` maps validated frame target fields into `action.target` on the signed receipt. Enables dashboard session attribution to build state-dependency edges and blast-radius annotations.

### Dependencies

- Pin `github.com/agent-receipts/ar/sdk/go` to `v0.19.0-alpha.1`.

## [0.19.0-alpha.1] - 2026-06-11

### Added

- **`--rotate` offline key rotation** ([#778](https://github.com/agent-receipts/obsigna/pull/778), ADR-0015 Phase A) — new `--rotate` flag generates a fresh Ed25519 key pair, emits a `key_rotated` receipt (action type `agent.key.rotate`) signed by the current key, archives the old public key as `signing.key.pub.rotated-<fp>`, and atomically swaps in the new key. The daemon must be stopped first; a live-socket check aborts rotation if the daemon is reachable. Pass `--anchor-log` to write the rotation event to an append-only external witness log before committing. `--verify` and `--doctor` traverse rotation chains and surface `IncompleteSession` when a `system.pty.open` receipt has no matching close.
- **Transcript-derived model and token usage** ([#779](https://github.com/agent-receipts/obsigna/pull/779), ADR-0026) — `issuerFromFrame` now maps the hook-forwarded `model`, `usage` (verbatim JSON), and `capture_method` fields into `issuer.runtime` on all receipts, including root-chain receipts when observability fields are present.
- **`IncompleteSession` advisory** ([#780](https://github.com/agent-receipts/obsigna/pull/780), ADR-0027) — `--verify` prints `Advisory: incomplete session: PTY open/close imbalance` and `--doctor` surfaces the same advisory when a `system.pty.open` receipt has no corresponding `system.pty.close` in the chain. Advisory-only; does not affect `Valid`.

### Dependencies

- Pin `github.com/agent-receipts/ar/sdk/go` to `v0.18.0-alpha.1` (provides `receipt.Runtime` typed fields, `KeyRotation` type, and `ChainVerification.IncompleteSession`).

## [0.18.0] - 2026-06-11

Graduates `0.18.0-alpha.1` after the alpha pass. No code changes since the alpha; the only change is pinning the now-released stable `github.com/agent-receipts/ar/sdk/go` `v0.17.0` (the alpha pinned `v0.17.0-alpha.1`). See the `0.18.0-alpha.1` entry below for the full surface (`issuer.runtime` sub-object, `agent_type` forwarding).

## [0.18.0-alpha.1] - 2026-06-09

### Added

- **`issuer.runtime` on emitted receipts** ([#761](https://github.com/agent-receipts/obsigna/pull/761), ADR-0026) — `issuerFromFrame` now nests the frame's `agent_id` / `agent_type` under `issuer.runtime` (gated on `agent_id`, matching chain routing, so root-chain receipts stay runtime-free). `agent_type` is validated for length like the other proxy-supplied identity fields. Receipts are emitted at protocol version `0.5.0` / JSON-LD context v2.

### Changed

- Pin `github.com/agent-receipts/ar/sdk/go` to `v0.17.0-alpha.1` (provides the `receipt.Runtime` type). The daemon does not compile against `sdk/go v0.16.0`, which predates `Runtime`.

## [0.17.0] - 2026-06-09

Graduates `0.17.0-alpha.1` after the alpha pass. No code changes since the alpha; the only change is pinning the now-released stable `github.com/agent-receipts/ar/sdk/go` `v0.16.0` (the alpha pinned `v0.16.0-alpha.1`). See the `0.17.0-alpha.1` entry below for the full surface (subagent chain delegation, correlation ID).

## [0.17.0-alpha.1] - 2026-06-08

### Added

- **Subagent chain delegation** ([#753](https://github.com/agent-receipts/obsigna/pull/753)) — Claude Code sends a distinct `agent_id` per subagent in hook payloads. The daemon now routes frames with a non-empty `agent_id` to a per-agent chain keyed `<rootChainID>/agent/<agentID>` (the root chain continues to hold root-level receipts). The first receipt on each subagent chain carries a `delegation` object: `parent_chain_id` (the root chain ID), `parent_receipt_id` (the root chain's tail receipt at delegation time), and `delegator.id` (the daemon's issuer ID). This creates a cryptographically verifiable link from every subagent action back to the root session that spawned it. `agent_id` values containing `/` or null bytes are rejected at validation to prevent chain ID injection.
- **Correlation ID** ([#752](https://github.com/agent-receipts/obsigna/pull/752)) — the emitter frame now carries an optional `correlation_id` field; the daemon stamps it on `credentialSubject.correlation_id`. Enables post-hoc joining of a hook pre-check receipt with the MCP proxy post-action receipt for the same tool call without a shared database lookup.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.16.0-alpha.1`.

## [0.16.0] - 2026-06-03

### Added

- **Auto-advance chain ID on terminal tail** ([#735](https://github.com/agent-receipts/obsigna/pull/735)) — instead of refusing to start when the active chain's tail is a terminal receipt (normal shutdown), the daemon now advances to the next chain ID (`foo` → `foo-2` → `foo-3 …`). A `brew services restart` after a normal or interrupted shutdown no longer requires manual config edits.
- **Date-based default chain ID** ([#735](https://github.com/agent-receipts/obsigna/pull/735)) — the default chain ID changes from the static `"default"` string to today's UTC date (`2006-01-02` format). Each calendar day produces a named chain; same-day restarts auto-advance with a counter suffix (`2026-06-03` → `2026-06-03-2`); midnight rolls over to a fresh chain automatically.

## [0.15.0] - 2026-06-02

### Added

- **HPKE parameter disclosure** ([#722](https://github.com/agent-receipts/obsigna/pull/722), ADR-0012, ADR-0015) — receipts now support optionally encrypting sensitive action parameters using HPKE (RFC 9180) v1 with X25519 KEM and AES-256-GCM. A `parameters_disclosure` envelope (alg, ct, recipients[{kid, enc}], v) attaches to receipts when a forensic public key is configured and a disclosure policy permits the action type. Operators can encrypt parameters per action-type risk level (`"high"` for high/critical actions, `true` for all, `false`/default for none, or a comma-separated allowlist like `system.command.execute,file.write`). The envelope `kid` is the ADR-0015 canonical fingerprint of the recipient X25519 public key (`sha256:<hex>` over the raw 32 bytes). Inputs remain hashed in `action.parameters_hash` regardless — the disclosure envelope is opaque without the private key. Encryption failures fall back to hash-only receipts (no audit gaps). See [Parameter Disclosure spec](https://agent-receipts.github.io/specification/parameter-disclosure/) for threat model, GDPR context, and implementation details.
- **Forensic key configuration** — new daemon CLI flag `--forensic-public-key` (path to a file containing 32 raw bytes), environment variable `AGENTRECEIPTS_FORENSIC_PUBLIC_KEY`, and TOML key `forensic_public_key` allow operators to load a forensic public key. The daemon never reads the private key at runtime — it is held offline by the forensic responder. The new `--init-forensic-key` one-shot flag generates an X25519 keypair (private key mode `0600`, public key co-located), prints its fingerprint, and exits; it is not run on first start.
- **Risk-based disclosure policy** ([#722](https://github.com/agent-receipts/obsigna/pull/722)) — the `parameter_disclosure` config accepts `false` (default, no disclosure), `true` (all action types), `"high"` (high/critical risk only, as defined by the taxonomy), or a comma-separated action-type allowlist (e.g. `system.command.execute,file.write`). Supported via `--parameter-disclosure` CLI flag, `AGENTRECEIPTS_PARAMETER_DISCLOSURE` env var, and TOML `parameter_disclosure` key. TOML backwards-compatible unmarshaling accepts bool or string; CLI and env accept string only.
- **Action-type routing in disclosure policy** — the daemon's JSON-RPC frame now carries an optional `action_type` field. When set, the daemon stamps it verbatim as the receipt's `action.type` and resolves risk from the taxonomy; when empty it synthesizes a fallback `<channel>[.<server>].<tool>` type (which rarely matches the taxonomy, so risk defaults to medium). Emitters that know the real taxonomic action type SHOULD set this — it is what makes risk-based controls (e.g. `parameter_disclosure="high"`) effective. The daemon always resolves risk itself, so an emitter cannot downgrade risk to evade disclosure.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.15.0`.

## [0.14.0] - 2026-06-02

### Added

- **`agent-receipts verify-event`** ([#659](https://github.com/agent-receipts/obsigna/pull/659), closes [#540](https://github.com/agent-receipts/obsigna/issues/540)) — read-only CLI subcommand for end-to-end pipeline-provenance evidence. Where `verify` answers "is this chain internally consistent?", `verify-event` answers "was this receipt produced by the documented emitter→daemon→chain pipeline, or written to the store by some other path?" (ADR-0010 § Permissions and trust). Resolves receipts by `--id`, `--chain-head`, or `--since` window and runs six checks per receipt: signature, hash linkage, peer-credential presence, emitter-identity allowlist (warns, never fails), schema-version compatibility, and sequence contiguity. Exit `0` verified + provenance confirmed / `1` check failed / `2` usage error / `3` verifies cryptographically but lacks peer-credential evidence. `--json` for CI. Safe to run against a live daemon's DB or a forensic snapshot — never emits.
- **TOML config file support** ([#441](https://github.com/agent-receipts/obsigna/issues/441)) — the daemon now reads a TOML config file, by default `$XDG_DATA_HOME/agent-receipts/daemon.toml` (falling back to `~/.local/share/agent-receipts/daemon.toml`), co-located with `receipts.db` and the signing key. Override the path with `--config` or `AGENTRECEIPTS_CONFIG`. Keys mirror the flag names (dashes → underscores): `socket`, `db`, `key`, `public_key`, `chain_id`, `issuer_id`, `verification_method`, `parameter_disclosure`, `redact_patterns`, `unsafe_socket_path`, `shutdown_deadline`. Precedence is **file < env < flags** — the file is the lowest-priority layer, so an absent key never clobbers an env var or flag. A missing default-path file is tolerated; a missing `--config` path, malformed TOML, or an unknown key is rejected rather than silently degrading. New `--print-config` prints the fully resolved config (paths only — never key material) in the same shape, so it doubles as a starting `daemon.toml`.
- **`agent-receipts doctor`** ([#539](https://github.com/agent-receipts/obsigna/issues/539)) — read CLI subcommand that diagnoses the whole pipeline (emitter → socket → daemon → SQLite → verify) end-to-end and reports an actionable per-step result. Eight checks: daemon reachability, socket presence/mode, emitter-vs-daemon dial-path agreement, DB permissions (`0640` per ADR-0010 § Read interface), schema readability + public-key fingerprint, OS peer-credential capability, chain-head verification (surfacing the verifier's `unknown` status as a warning per [#475](https://github.com/agent-receipts/obsigna/issues/475)), and a load-bearing **round-trip**: a synthetic event fired through the real socket must land in the DB with a fresh peer credential matching the doctor process. `--json` for CI, `--warn-as-error` for stricter gates, `--no-roundtrip` to skip writing a synthetic event. Exit `0` healthy / `1` unhealthy / `2` usage. The synthetic event is deliberately visible in the chain (channel `doctor`, tool `agent-receipts-doctor.roundtrip`, recorded as `action.type` `doctor.agent-receipts-doctor.roundtrip` — a low-risk diagnostic self-check operators can filter on).

### Changed

- **Boolean environment variables now parse via `strconv.ParseBool`** ([#441](https://github.com/agent-receipts/obsigna/issues/441)) — `AGENTRECEIPTS_PARAMETER_DISCLOSURE` and the new `AGENTRECEIPTS_UNSAFE_SOCKET_PATH` previously treated only the literal `1` as true and silently ignored everything else. They now accept the full `strconv.ParseBool` set (`1`/`0`, `t`/`f`, `true`/`false`, `TRUE`/`FALSE`, …) and **reject** unparseable garbage with a startup error instead of degrading to false. Operators upgrading should know: values like `true`/`false` now take effect as expected, a previously-ignored non-`1` truthy value (e.g. `yes`) will now error rather than silently being treated as false, and `AGENTRECEIPTS_PARAMETER_DISCLOSURE=true` is now honoured.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.14.0`.

## [0.13.0] - 2026-05-24

### Added

- **`agent-receipts show <seq>`** ([#576](https://github.com/agent-receipts/obsigna/pull/576), closes [#552](https://github.com/agent-receipts/obsigna/issues/552)) — read-only CLI subcommand that prints the full fields of the receipt at a given chain sequence number. `--json` for raw receipt output. `--chain-id` required only when the store holds more than one chain; single chains are auto-detected.
- **`chain.status="interrupted"` terminal receipt on SIGTERM/SIGINT** ([#582](https://github.com/agent-receipts/obsigna/pull/582), closes [#500](https://github.com/agent-receipts/obsigna/issues/500)) — after the IPC listener closes and all in-flight frames drain, the daemon now emits a terminal receipt (`chain.terminal=true`, `chain.status="interrupted"`) for every open chain before exiting. Verifiers classify the chain as `"interrupted"` rather than `"unknown"`. Uses `GetChainTailReceipt` to avoid emitting a duplicate if the chain already has a terminal.
- **`action.idempotency_key` auto-populated from JSON-RPC request id** ([#565](https://github.com/agent-receipts/obsigna/pull/565)) — the daemon now stamps `idempotency_key` from the `id` field of the wrapped JSON-RPC request (capped at 256 bytes). Requires sdk/go v0.13.0 and spec v0.4.0.
- **Refuse unsafe socket paths absent `--unsafe-socket-path`** ([#579](https://github.com/agent-receipts/obsigna/pull/579), closes [#538](https://github.com/agent-receipts/obsigna/issues/538)) — at startup the daemon rejects a `--socket` / `AGENTRECEIPTS_SOCKET` override that resolves outside the per-platform safe set (Linux: `$XDG_RUNTIME_DIR`, `/run`, `/var/run`; macOS: `$TMPDIR`, `/var/run`, `$XDG_DATA_HOME/agent-receipts`) unless `--unsafe-socket-path` is also passed. With the flag the daemon starts, logs a `level=warn` line naming the path, and re-emits the warning every 60s. Paths are canonicalized with `filepath.EvalSymlinks`; TCP addresses are rejected unconditionally.

### Changed

- **macOS default socket path moved off `$TMPDIR`** ([#545](https://github.com/agent-receipts/obsigna/issues/545)) — the macOS default is now `$XDG_DATA_HOME/agent-receipts/events.sock` (defaulting to `~/.local/share/agent-receipts/events.sock`). The previous TMPDIR-based path was not inherited by GUI-spawned subprocesses (e.g., MCP servers launched by Claude Desktop), causing silent receipt-loss mismatches. Linux defaults are unchanged. Operators upgrading on macOS must restart both the daemon and any emitter; anyone relying on TMPDIR redirection should switch to `AGENTRECEIPTS_SOCKET`.
- **`daemon.DefaultSocketPath` now delegates to `emitter.DefaultSocketPath`** — eliminates the duplicate resolver that could drift. Library consumers of `daemon.DefaultSocketPath` now also pick up `AGENTRECEIPTS_SOCKET` directly.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.13.0`.

## [0.12.1] - 2026-05-23

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.12.1` (HttpEmitter + Emitter interface, macOS socket path default — no daemon behaviour change).

## [0.12.0] - 2026-05-22

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.11.0` (v0.3.0 spec migration: HPKE disclosure envelope, PeerCredential, EmitterMetadata — no daemon behaviour change beyond what was already shipped in v0.11.0).

## [0.11.0] - 2026-05-19

### Added

- **Issuer/operator metadata in receipts**: the daemon now stamps `receipt.Issuer.Name`, `receipt.Issuer.Model`, and `receipt.Issuer.Operator` from the proxy-supplied wire fields (`issuer_name`, `issuer_model`, `operator_id`, `operator_name`). Old proxies that omit these fields produce receipts with empty Name/Operator, preserving backwards compatibility.

### Fixed

- **MCP tool-level failures now record `outcome.status: "failure"`**:
  When an MCP tool call returned a `CallToolResult` envelope with
  `"isError": true`, the JSON-RPC call still succeeded (no `Error` on the
  emitter frame), so the daemon stamped the receipt with
  `outcome.status: "success"`. The pipeline now inspects the result body for
  the MCP `isError` flag on `channel == "mcp"` frames and maps it to
  `failure`. Other channels are unaffected — a top-level `isError` outside
  the MCP envelope is not reinterpreted.

## [0.10.1] - 2026-05-18

### Security

- **Redact bare JWT tokens in receipts** ([#451](https://github.com/agent-receipts/obsigna/pull/451),
  closes [#450](https://github.com/agent-receipts/obsigna/issues/450)):
  The pipeline redactor missed JWTs that were not prefixed with `Bearer ` and
  not embedded in a URL query string. Concretely, `cat ~/.npmrc` from a Claude
  Code `Bash` tool call produced a receipt with the npm `_authToken=eyJ…` value
  in cleartext. Added a `jwt` built-in pattern (`eyJ…\.eyJ…\.…`) anchored on
  the base64url-encoded `{"` prefix of the header and payload segments, which
  keeps the pattern specific to real JWTs and avoids matching arbitrary dotted
  base64 strings. The signature segment may be empty (covers unsigned
  `alg=none` tokens).

## [0.10.0] - 2026-05-17

### Added

- **Receipt pipeline redaction** ([#426](https://github.com/agent-receipts/obsigna/pull/426),
  closes [#423](https://github.com/agent-receipts/obsigna/issues/423)):
  The daemon now redacts secrets from receipt body fields before persistence.
  Built-in patterns cover GitHub PATs, OpenAI/Anthropic keys, AWS access key IDs,
  bearer tokens, Slack tokens, PEM private keys, and URL query-string tokens.
  JSON-aware key redaction additionally covers `password`, `token`, `api_key`,
  `secret`, `authorization`, `private_key`, `jwt`, and 20+ other sensitive key names.
  Redaction runs after hashing — `parameters_hash` and `response_hash` commit to
  the raw canonical bytes; only the stored text fields (`outcome.error`,
  `parameters_disclosure` when enabled) are sanitised.
  Custom patterns can be added via `--redact-patterns <file.yaml>`
  (env: `AGENTRECEIPTS_REDACT_PATTERNS`).

- **`agent-receipts list` companion CLI command** ([#420](https://github.com/agent-receipts/obsigna/pull/420),
  closes [#410](https://github.com/agent-receipts/obsigna/issues/410)):
  `agent-receipts list` prints recent receipts from the daemon store in tabular
  or JSON form. Flags: `--limit N` (default 50), `--json`, `--db`/`AGENTRECEIPTS_DB`.
  Newest-first by default.

### Changed

- **mcp-proxy is now a thin emitter** ([#421](https://github.com/agent-receipts/obsigna/pull/421),
  closes [#416](https://github.com/agent-receipts/obsigna/issues/416)):
  The mcp-proxy no longer maintains its own `receipts.db` or signs receipts.
  It forwards raw tool-call events to the daemon over the Unix socket
  (the same pattern as `agent-receipts-hook`). The daemon is the sole receipt
  writer. **Breaking change for mcp-proxy:** the `-receipt-db`, `-key`, `-chain`,
  `-issuer*`, `-operator*`, `-principal`, `-taxonomy`, and `-bundled-taxonomies`
  flags have been removed. The `mcp-proxy list`, `inspect`, `verify`, `export`,
  and `stats` subcommands now print a deprecation notice pointing to
  `agent-receipts list` / `agent-receipts verify`.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.9.1`
  (DESC ordering and no silent 10k row cap in `QueryReceipts`).

## [0.9.1] - 2026-05-16

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.9.0`
  (`emitter.WithStrictErrors()` option added; no daemon behaviour change).

## [0.9.0] - 2026-05-16

### Changed

- **`agent-receipts-hook` extracted into its own module** ([#405](https://github.com/agent-receipts/obsigna/issues/405),
  [#407](https://github.com/agent-receipts/obsigna/pull/407)):
  The hook binary is no longer bundled in this formula or release tarball.
  Install it separately: `brew install agent-receipts/tap/agent-receipts-hook`
  or `go install github.com/agent-receipts/ar/hook/cmd/agent-receipts-hook@latest`.

## [0.8.1] - 2026-05-15

### Added

- **`agent-receipts-hook` binary** ([#403](https://github.com/agent-receipts/obsigna/pull/403),
  closes [#364](https://github.com/agent-receipts/obsigna/issues/364)):
  Short-lived PostToolUse hook for Claude Code (and future agent runtimes) that
  captures native host tool calls — `Bash`, `Write`, `Edit`, `Read`, `WebFetch`,
  `WebSearch` — and forwards them to `agent-receipts-daemon` over the Unix socket.
  Fills the audit gap left by `mcp-proxy`, which only covers MCP tool calls.
  Always exits 0 (fire-and-forget, per ADR-0010). Format-dispatch model makes
  adding new runtimes a single function + map entry.
  Shipped in the same Homebrew formula and release tarball as `agent-receipts-daemon`.

## [0.8.0] - 2026-05-15

### Added

- **Phase 2 integration tests**: concurrent mcp-proxy sessions, RFC8785-canonical
  hash verification, socket handler coverage improved from 50.9% to 81.1%
  ([#362](https://github.com/agent-receipts/obsigna/issues/362),
  [#365](https://github.com/agent-receipts/obsigna/issues/365)).
- **macOS `brew services` integration**: `brew services start agent-receipts-daemon`
  now works — `service do` block added to the Homebrew formula via GoReleaser
  template ([#375](https://github.com/agent-receipts/obsigna/issues/375)).
- **Binary release pipeline**: GoReleaser-backed CI workflow publishes signed
  archives and updates the Homebrew tap on each `daemon/v*` tag.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` from `v0.8.0-alpha.2` to `v0.8.0`.

## [0.8.0-alpha.2] - 2026-05-10

### Added

- **XDG-compliant default paths** ([#332](https://github.com/agent-receipts/obsigna/issues/332)):
  SQLite store and signing key now default to `$XDG_DATA_HOME/agent-receipts/`
  (typically `~/.local/share/agent-receipts/`) instead of `~/.agent-receipts/`.
  Consistent across Linux and macOS, follows Unix conventions, and plays well
  with standard tooling (commits `b8f9a3a`, `1f0dd21`, `081cd3e`).

- **Explicit `--init` flag for key generation** ([#348](https://github.com/agent-receipts/obsigna/issues/348)):
  New `agent-receipts-daemon --init` to create the signing key pair on fresh
  install. The daemon refuses to start without an existing key and never silently
  regenerates one. Prevents the footgun of accidentally replacing a deleted key
  and orphaning all previously-signed receipts (commits `1f0dd21`, `7f7231c`).

- **`--version` flag** ([#349](https://github.com/agent-receipts/obsigna/issues/349)):
  `agent-receipts-daemon --version` returns the build version from three sources
  in priority order: `-ldflags` injection (release pipeline), `debug.ReadBuildInfo()`
  module version (set by `go install`), or literal `"dev"` (local `go build`).
  Improves operational visibility during soaks and deployments (commit `b7589b5`).

### Security

- **TOCTOU-safe key generation** (commit `7f7231c`):
  Replaced `os.Stat` + `os.WriteFile` pattern with `O_CREATE|O_EXCL|O_NOFOLLOW + fchmod`
  to prevent symlink-based key redirection attacks during initial key write.
  Consistent with the existing `publishPublicKey` pattern.

### Tests

- 19 new tests covering XDG path defaults, environment variable overrides,
  and TOCTOU-safe key generation. Full integration suite passes including
  chain continuity across daemon restart (issue #348).

## [0.8.0-alpha.1] - 2026-05-09

### Added (ADR-0010: Daemon Process Separation)

- **New `agent-receipts-daemon` process** separates cryptographic operations
  (signing, canonicalisation, chain management) from individual SDKs/proxies
  into a dedicated daemon. SDKs emit fire-and-forget events to the daemon's
  Unix socket; the daemon produces signed, chained receipts persisted to SQLite.
  See [ADR-0010](https://github.com/agent-receipts/obsigna/blob/main/docs/adr/0010-daemon-process-separation.md).

- **SQLite receipt store** with persistent chain state, verification CLI
  (`agent-receipts-verify`), query support, and stats. Receipts are stored
  as canonical JSON and indexed by session/timestamp.

- **Ed25519 signing** with hierarchical key structure: one long-lived signing key
  pair per daemon instance, discoverable public key at a well-known path for
  out-of-band verification. Private keys stored with restrictive permissions (0600).

- **Unix socket IPC** for receipt events. Wire protocol: 4-byte big-endian length
  prefix + UTF-8 JSON body, matching `pipeline.SupportedFrameVersion = "1"`.

- **Session-scoped chaining** ([ADR-0010 OQ4](https://github.com/agent-receipts/obsigna/blob/main/docs/adr/0010-daemon-process-separation.md)):
  All receipts in a session form a cryptographic chain. Each receipt includes
  the hash of the prior receipt, enabling detection of tampering and enforcing
  causality across a session (even across daemon restarts if the key is preserved).

### Documentation

- Comprehensive suite of integration tests covering socket communication,
  chain continuity, key generation, and verification workflows.

[0.22.0]: https://github.com/agent-receipts/obsigna/releases/tag/daemon%2Fv0.22.0
[0.8.1]: https://github.com/agent-receipts/obsigna/releases/tag/daemon%2Fv0.8.1
[0.8.0]: https://github.com/agent-receipts/obsigna/releases/tag/daemon%2Fv0.8.0
[0.8.0-alpha.2]: https://github.com/agent-receipts/obsigna/releases/tag/daemon%2Fv0.8.0-alpha.2
[0.8.0-alpha.1]: https://github.com/agent-receipts/obsigna/releases/tag/daemon%2Fv0.8.0-alpha.1
