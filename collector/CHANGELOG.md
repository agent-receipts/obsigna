# Changelog

All notable changes to the collector are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at the `obsigna-collector` rename; earlier releases are recorded
only in git history. A repo-wide effort to auto-generate changelogs from
Conventional Commits is tracked in
[#253](https://github.com/agent-receipts/obsigna/issues/253).

## [Unreleased]

> **This train has merged into the unified `obsigna` release train (ADR-0034, PR 2).**
> collector no longer releases on `collector/v*`. `obsigna-collector` and the `collector`
> deprecation shim now ship in the `obsigna_<ver>_<os>_<arch>.tar.gz` archive and the
> `obsigna` Homebrew formula, versioned with the rest of the Go toolset. The `collector`
> formula migrates to `obsigna` via the tap's `tap_migrations.json`. New entries are
> recorded in `daemon/CHANGELOG.md` (the obsigna train changelog) from here on; the
> per-module CI (Gate A + PR-side Gate B) still runs on changes here.

## [0.14.0] - 2026-06-13

### Changed

- **Binary renamed `collector` → `obsigna-collector` (ADR-0035).** The collector is
  now its own minimal binary, `obsigna-collector`, launched in production via
  `obsigna collector run` (ADR-0030, ADR-0034), which `syscall.Exec`s straight into
  it. **Breaking for installers that invoke the binary by an absolute path to a
  renamed file.** A thin `collector` deprecation shim ships alongside
  `obsigna-collector` and exec-forwards to it, so the common `$(which collector)`
  invocation and existing scripts keep working — update them to `obsigna-collector`
  (or `obsigna collector run`) when convenient; the shim will be removed in a future
  release. The Homebrew formula name (`collector`) is unchanged; both binaries are
  installed.

### Added

- **Gate A — dumb-sink import graph (ADR-0035).** A CI-enforced test asserts the
  `obsigna-collector` production graph never reaches the daemon library (the signer,
  ADR-0010) or any operator read-side (`*cli`) package. Unlike the proxy's
  fail-closed allowlist (ADR-0033), this is a denylist: the collector *legitimately*
  persists receipts (`sdk/go/store`, `sdk/go/receipt`, a SQLite driver), so the
  property enforced is "never the signer, never the operator CLI" rather than "no
  store".
- **Gate B — reproducible build (ADR-0035).** `obsigna-collector` is built with
  `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, a patch-pinned toolchain
  (`toolchain go1.26.1`), and a commit-derived `mod_timestamp`. The PR gate builds it
  twice from two working-directory paths and asserts byte-identical `sha256`; the
  release independently rebuilds it, asserts a match against the published archive,
  and publishes the known-good hash. Both rebuilds share
  `collector/scripts/reproducible-build.sh` so they cannot drift.
