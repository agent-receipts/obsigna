# ADR-0034: Consolidate the Go Toolset into One obsigna Release Train

## Status

Accepted (2026-06-12).

## Context

This repo carries roughly eight independent release trains across its
modules: `sdk/go`, `sdk/ts`, `sdk/py` (and `sdk/ts-aws`), plus `daemon`,
`mcp-proxy`, `hook`, and `collector`. Each has its own tag scheme, its own
release workflow, its own changelog, and — for the Go tools — its own Homebrew
formula. A ninth, the dashboard, lives in a *second* repository (a POC; see
decision 8), so the full release surface spans two repos. Cutting a coordinated release means driving N trains in lockstep by
hand, and a single cross-cutting fix (a shared-library bump, a protocol nudge)
fans out into N tag-and-publish dances. Releasing is painful out of proportion
to the size of most changes.

The pain has a sharp, visible edge in the daemon train. ADR-0030 consolidated
the implementation behind a single `obsigna` entrypoint, and ADR-0031 split the
signer into its own minimal `obsigna-daemon` binary — but the `obsigna` CLI and
the `agent-receipts` deprecation shim both live inside the `daemon/` module, so
the daemon's GoReleaser config owns the whole bundle. The artifacts all carry
*daemon* identity for what is really the obsigna core:

- `project_name: daemon`
- tag scheme `daemon/v*`
- archive `daemon_<version>_<os>_<arch>.tar.gz`
- the (now `obsigna-daemon`) Homebrew formula

So a user runs `brew install agent-receipts/tap/obsigna-daemon` to get the
`obsigna` CLI. The packaging identity is upside down: the daemon is one binary
*inside* the obsigna toolset, but it names the train, the tag, the archive, and
the formula. ADR-0031 already flagged this — it renamed only the installed
binary and left the formula and tag names as "a downstream tap concern." This
ADR resolves that concern, and the broader release-train sprawl, as one
decision.

This is design capture for an already-settled consolidation. It does not
implement anything; it is the durable record that the implementation PRs hang
off (see *Rollout*).

## Decision

### 1. Three artifact classes, three release models

The repo's deliverables fall into three classes, and each gets the release
model that fits it:

- **SDKs** (`sdk/go`, `sdk/ts`, `sdk/py`, `sdk/ts-aws`) stay **independent
  semver libraries, each its own train.** External consumers pin them directly
  (`@obsigna/sdk-ts@x.y.z`, `obsigna==x.y.z`, a Go module version), so their
  versions must move independently and mean what semver says they mean. Folding
  an SDK into a shared train would force unrelated version churn onto downstream
  pins. They stay separate.
- **The Go toolset** (the operator/runtime binaries) becomes **one unified
  train** — the subject of this ADR.
- **Apps** (`site/`) are **deploy-on-push**, not versioned artifacts. There is
  nothing for a consumer to pin; the deployed site *is* the release.

### 2. The toolset is one `obsigna/vX.Y.Z` train

The Go toolset collapses into a single train: **one `obsigna/vX.Y.Z` tag, one
GoReleaser config, one CHANGELOG.** That train builds five binaries plus the
deprecation shim:

- `obsigna` — the operator CLI (ADR-0030)
- `obsigna-daemon` — the minimal signer (ADR-0031)
- `obsigna-mcp` — the MCP stdio proxy (ADR-0032)
- `obsigna-collector` — the receipt hub
- `obsigna-hook` — the per-tool-call emission callback
- `agent-receipts` — the deprecation shim that forwards to `obsigna`

This refines ADR-0031's framing. ADR-0031 said "the daemon is its own train";
that was true of the binary's *isolation* but conflated it with *release
packaging*. The corrected statement: the daemon is its own **binary** (lean
import graph, attestable in isolation — unchanged), but the **toolset is one
train**. Binary boundaries and train boundaries are different axes.

### 3. Unified version across all tools

Every tool in the train ships at the same version. A hook-only fix bumps the
version of everything — daemon, mcp, collector, CLI — even though their bytes
did not change. **This is accepted.** A single shared version number is far
cheaper than coordinating N independent trains, and the cost of the "spurious"
bumps is purely cosmetic: a tool whose code is byte-identical across two
versions is still byte-identical, and Gate B (reproducible build, ADR-0031)
still proves it.

The unified version also **simplifies the Gate #8 daemon↔SDK protocol
compatibility check** (ADR-0024). Today that gate reasons about a daemon
version and three SDK versions independently. With one toolset version, the
question collapses to "`obsigna vX` vs `sdk vY`" — one version on the toolset
side of the handshake instead of a per-binary matrix.

### 4. One umbrella Homebrew formula

A single formula, **`obsigna`**, installs the whole toolset. There are **no
per-component formulae** and, specifically, **no standalone `hook` formula**.

- `tap_migrations.json` maps every retired name → `obsigna`:
  `agent-receipts-daemon`, `obsigna-daemon`, `agent-receipts-hook`,
  `mcp-proxy`, and `collector` all migrate to `obsigna`. (Stable and alpha:
  `obsigna-daemon-alpha` → `obsigna-alpha`.)
- An **`obsigna-alpha`** soak track is retained, mirroring today's
  `obsigna-daemon-alpha` (tracks every release including pre-releases).
- **Accepted tradeoff:** `brew install obsigna` pulls *all* binaries — tens of
  MB — even for a user who only wants the CLI. This is the right call for a
  toolset whose components are designed to run co-located (the hook needs the
  daemon; the CLI talks to the daemon). The disk cost is small and the
  install/upgrade story becomes a single formula.
- **The collector is the only future split candidate** — it is a standalone
  HTTP hub (ADR-0017) that needs no local daemon, so it is the one component
  that could plausibly justify its own package for users who run *only* a hub.
  We **do not pre-split it.** If that need materializes, splitting one binary
  out of the umbrella is a localized change; speculatively splitting now buys
  nothing and re-introduces a second train.

### 5. Launcher table gains `mcp` and `collector`; hook gets neither

ADR-0031 established the launcher mechanism: `obsigna <noun> run` replaces its
process image with the sibling binary via `syscall.Exec`, preserving the
attestation tuple. That table holds `daemon` and — as of ADR-0033 — `mcp`. This
ADR adds **`collector`:** `obsigna collector run` execs `obsigna-collector`
beside `obsigna` on disk (else `$PATH`), exactly as `obsigna daemon run` /
`obsigna mcp run` exec their binaries. (`obsigna-mcp` and its launcher already
landed via ADR-0033; what this ADR changes for mcp is the *train*, not the
binary — see decision 2 and PR 2.)

**The hook gets no noun and no launcher.** It is invoked directly by path
(`obsigna-hook`) by the agent runtime as a per-tool-call callback — see
ADR-0013. Wrapping it in `obsigna hook run` would impose an `exec` on every
single tool call for no benefit: the launcher exists to fix the *attestation
tuple* of a long-lived process, and the hook is neither long-lived nor the
thing auditors attest.

The principle is a **lifetime/frequency gradient** — service → session →
per-event:

| Tool | Lifetime | Invocation frequency | Launcher? |
|------|----------|---------------------|-----------|
| `daemon` | service | once (long-running) | yes |
| `collector` | service | once (long-running) | yes |
| `mcp` | session | once per MCP session | yes |
| `hook` | per-event | once per tool call | **no** |

The launcher pays off all the way down to **session** granularity — a
once-per-session `exec` is negligible amortized over the session's lifetime,
and an MCP session is long enough that a clean process identity matters. It
does **not** pay off at the hook's **per-event** tail, where the `exec` would
be pure per-event tax. The cut is at the session/per-event boundary, not at
service/non-service.

### 6. Why the hook has no standalone formula

The hook emits to the daemon over an **AF_UNIX socket** — local-only; the
daemon rejects TCP (ADR-0010 / ADR-0022 trust boundary). It is therefore
**non-functional without a co-located daemon.** A standalone `hook` package
would install a binary that cannot do anything on a machine without the daemon
— dead weight. The hook ships **inside the umbrella formula**, where the daemon
it depends on is always present.

This **re-merges** what an earlier caveat split out: the current daemon formula
caveat tells users "`agent-receipts-hook` is now a separate formula." That
split is reversed here — the hook returns to the umbrella, and
`agent-receipts-hook` migrates to `obsigna` via `tap_migrations.json`.

### 7. Gate A is write-side only

Gate A (the lean import-graph guard from ADR-0031) is a **write-side**
property. It guards the **daemon** — the signer, the process that runs next to
the private key — by failing the build on any import of an operator read-side
(`*cli`) package. It **should also be considered for `mcp`**, which likewise
holds signing-adjacent responsibility (it injects a principal and emits signed
receipts, ADR-0032).

Gate A **explicitly does not apply to read-side binaries.** The `obsigna` CLI —
and the dashboard, if it ever joins the train — are *allowed* to link the
operator/read packages; that is their whole job. Applying Gate A to them would
be a category error. The gate keys on the signing trust boundary, not on
"every binary in the train."

### 8. The dashboard stays out (for now)

The dashboard is a separate-repo POC: a local HTTP Go binary that reads the
SQLite receipt store **directly, read-only.** It stays **out of the train.**

It carries a known architectural debt: an **undeclared dependency on the
store's raw schema across a repo boundary.** It reads the SQLite tables
directly rather than through a versioned read API, so a schema change in the
store can silently break it (silent-drift risk). That is **acceptable for a
POC** and not worth paying down while the thing is throwaway.

**Fold-in trigger:** when the dashboard stops being throwaway, fold it in —
either **subtree-merge** it into this repo so it rides the unified train, or
give it a **versioned read path** (a declared read API instead of raw SQL) so
the cross-boundary schema dependency becomes explicit. Whichever comes first
retires the silent-drift risk; until then the dashboard is deliberately
excluded.

### 9. The identity rename is bundled into this consolidation

The daemon→obsigna identity rename rides along, as a single coherent change:

- `project_name: daemon` → `obsigna`
- tag scheme `daemon/v*` → `obsigna/v*`
- archive `name_template` (`daemon_*` → `obsigna_*`)
- workflow `release-daemon.yml` → `release-obsigna.yml`
- Homebrew formula `obsigna-daemon` → `obsigna` (and `obsigna-daemon-alpha` →
  `obsigna-alpha`)

This is **one more user-visible tap migration.** Users already migrated once
(`agent-receipts-daemon` → `obsigna-daemon`); this takes them one more hop to
`obsigna`. Bundling the rename into the consolidation keeps it to **exactly one
more hop** rather than spreading the churn across two separate migrations. The
`tap_migrations.json` map in decision 4 absorbs it.

### 10. Non-goals / explicitly unchanged

- **Go module paths stay `github.com/agent-receipts/ar/...`** (ADR-0023). The
  module path is a separate concern from packaging identity and is not touched
  here.
- **`did:agent-receipts-daemon:` issuer identities are untouched.** Issuer DIDs
  are a protocol/trust concern, not a packaging concern; renaming the train
  does not rename issuers.
- **Separate Go modules are kept.** Modules ≠ trains. The unified GoReleaser
  builds *across* the existing per-component modules (see *Implementation
  wrinkles*); collapsing the modules into one is a later nicety, not a
  prerequisite for one train.
- **The CLI source may stay in `daemon/cmd/obsigna` for now.** Physically
  relocating it is orthogonal to the train consolidation and can happen later.

## Rollout

The migration lands in two PRs, each independently shippable:

- **PR 1 — daemon train → obsigna train.** The decision-9 identity rename:
  `project_name`, tag scheme, archive `name_template`,
  `release-daemon.yml` → `release-obsigna.yml`, formula `obsigna-daemon` →
  `obsigna` (+ `-alpha`), and the `tap_migrations.json` entries. Ships the
  **current** binary set (`obsigna`, `obsigna-daemon`, `agent-receipts` shim) —
  no new binaries yet. This is the pure rename hop; it makes the train's
  identity correct before anything new folds in.

- **PR 2 — fold `mcp-proxy` + `collector` (+ `hook`) into the obsigna train.**
  ADR-0033 already produced the `obsigna-mcp` binary and its `mcp` launcher on a
  *standalone* `mcp-proxy/v*` train; this PR moves that binary (plus
  `obsigna-collector` and `obsigna-hook`) under the unified GoReleaser, adds the
  remaining `collector` launcher entry (decision 5), extends `tap_migrations.json`
  to cover `mcp-proxy`, `collector`, and `agent-receipts-hook`, and retires the
  standalone `mcp-proxy/v*`, `collector/v*`, and `hook/v*` trains and their
  `release-*.yml` workflows. (The `collector` restructure to a minimal
  `obsigna-collector` binary, ADR-0031-style, is its prerequisite — sequence it
  ahead of or within this PR.)

## Implementation wrinkles

Flagged for the implementation PRs; **not solved here.**

- **Cross-module build.** The unified GoReleaser must build binaries that live
  in **different Go modules** (`daemon/`, `mcp-proxy/`, `collector/`, `hook/`).
  GoReleaser supports this via per-build `dir:` + `main:` so each build resolves
  against its own module — and each must run with **`GOWORK=off`** so it
  resolves published dependency versions from that module's `go.mod`, not the
  in-tree `sdk/go` wired by the repo-root `go.work` (this is exactly why the
  current daemon config sets `GOWORK=off`).
- **Reproducibility and Gate B carry over unchanged.** The per-component
  reproducible-build contract from ADR-0031 — `CGO_ENABLED=0`, `-trimpath`,
  `-buildvcs=false`, the patch-pinned toolchain, and
  `mod_timestamp: {{ .CommitTimestamp }}` — applies per-build in the unified
  config, and **Gate B** (PR-time double-build byte-identity check + release
  attestation) extends to cover the full binary set rather than just
  `obsigna-daemon`. The shared `reproducible-build.sh` stays in lockstep with
  the unified GoReleaser flags.

## Consequences

- One tag, one changelog, one formula, one workflow for the entire Go toolset.
  A coordinated toolset release is a single `obsigna/vX.Y.Z` cut instead of an
  N-train dance.
- The packaging identity is right-side up: `brew install obsigna` installs the
  obsigna toolset, and the daemon is one binary within it rather than the thing
  that names the bundle.
- One unified version means the occasional "spurious" bump (a hook-only fix
  bumping the daemon's version string). Accepted, and cosmetic — byte-identity
  is still proven by Gate B.
- Users take one more tap-migration hop (`obsigna-daemon` → `obsigna`). The
  `tap_migrations.json` map makes the move automatic for `brew upgrade`.
- The SDKs are unaffected — they keep their independent semver trains, as
  external consumers require.

## Amends

- **ADR-0030** (CLI Command Taxonomy): this ADR is the "consolidation ADR" that
  ADR-0030's consequences anticipated — it ships the reserved `daemon`,
  `collector`, and `mcp` nouns into the surface gate and implements the
  `daemon`/`mcp`/`collector` launcher nouns. The `hook` non-noun (decision 5)
  is consistent with ADR-0030's invariant: new functionality receives a grouped
  command only when it warrants one, and the hook warrants none.
- **ADR-0031** (Daemon Binary Topology): generalizes its `syscall.Exec`
  launcher from the daemon to `mcp` and `collector` (decision 5), and refines
  its "the daemon is its own train" into "the daemon is its own *binary*; the
  toolset is one *train*" (decision 2). Gate A's scope is clarified as
  write-side-only (decision 7); Gate B carries over to the unified train
  (*Implementation wrinkles*). Resolves the formula/tag "downstream tap concern"
  ADR-0031 deferred (decision 9).
- **ADR-0032** (mcp-proxy Transport): the `obsigna-mcp` binary this ADR folds
  into the train is the stdio proxy ADR-0032 specifies; decision 7 flags Gate A
  as a candidate guard for it, given its signing-adjacent role.
- **ADR-0033** (mcp-proxy Binary Topology): applied the ADR-0031 pattern to
  mcp-proxy *per-component* — the `obsigna-mcp` binary, its `mcp` launcher, and
  its Gate A/B already shipped on a standalone `mcp-proxy/v*` train. This ADR
  keeps that binary and launcher and supersedes only its *release-train* stance:
  the per-component `mcp-proxy/v*` train folds into the unified `obsigna` train
  (decision 2, PR 2).

## Non-goals

- Implementing any of the above — this PR is design capture only. The GoReleaser
  config, workflows, and `tap_migrations.json` change in the PRs under
  *Rollout*.
- Go module consolidation, CLI source relocation, issuer-DID renames, and module
  paths — all explicitly retained as-is (decision 10).
- Splitting the collector into its own package — deferred unless a hub-only
  deployment need appears (decision 4).
- Folding in the dashboard — deferred until its fold-in trigger fires
  (decision 8).
