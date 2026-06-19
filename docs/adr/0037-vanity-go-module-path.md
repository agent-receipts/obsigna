# ADR-0037: Vanity Go Module Path on `obsigna.dev`

## Status

Accepted (2026-06-14). Supersedes ADR-0023.

## Context

The GitHub repository was renamed `agent-receipts/ar` → `agent-receipts/obsigna`
(the org is unchanged). Every Go module in the tree, however, still declares a
`github.com/agent-receipts/ar/…` module path:

| Module | Current path |
|--------|--------------|
| `sdk/go` | `github.com/agent-receipts/ar/sdk/go` |
| `sdk/go/aws` | `github.com/agent-receipts/ar/sdk/go/aws` |
| `daemon` | `github.com/agent-receipts/ar/daemon` |
| `mcp-proxy` | `github.com/agent-receipts/ar/mcp-proxy` |
| `collector` | `github.com/agent-receipts/ar/collector` |
| `hook` | `github.com/agent-receipts/ar/hook` |
| `cross-sdk-tests` | `github.com/agent-receipts/ar/cross-sdk-tests` |

These paths resolve **only through GitHub's repo-rename redirect.** Two problems
follow, and the second is the load-bearing one for a cryptographic-protocol
project:

1. **Off-brand identity.** The product is Obsigna (ADR-0029, ADR-0030,
   ADR-0034); the binaries are `obsigna-*`; the release train is `obsigna/v*`.
   The module identity every Go consumer types still says `ar`. The packaging
   identity was righted in ADR-0034; the *import* identity was explicitly left
   behind (ADR-0034 decision 10), and now reads as a loose end.

2. **A supply-chain footgun.** A `github.com/OWNER/REPO/…` import path is not an
   abstract name — it is a **fetch instruction.** The Go tool resolves it by
   cloning that exact repository location. `github.com/agent-receipts/ar/sdk/go`
   works today only because GitHub redirects `agent-receipts/ar.git` to
   `agent-receipts/obsigna.git`. **That redirect is conditional: it lasts only
   while the old name stays vacant.** The moment the `agent-receipts` org (or
   an attacker who gains access to it) (re)creates a repository at
   `agent-receipts/ar`, GitHub stops redirecting and Go resolves the import
   against the *new* occupant of that path. For a project whose entire purpose
   is cryptographically trustworthy provenance, leaving the resolution of our
   own module identity hostage to a vacated repository name is unacceptable. The
   org owns the name today, but "we currently control the squatting risk" is not
   the same as "the risk does not exist" — and it is exactly the class of
   dependency-substitution exposure this project exists to make auditable.

The deeper point is the one the rename already taught: **a module path tied to a
GitHub repo name inherits every fragility of that name.** The fix is to stop
deriving module identity from the repo name at all.

This ADR is design capture for an already-locked decision (adopt a vanity import
path on `obsigna.dev`, a domain the maintainer controls). It changes no code; it
is the durable record the implementation PRs hang off (see *Rollout*).

## Decision

### 1. Adopt a vanity import path rooted at `obsigna.dev`

Every Go module migrates off `github.com/agent-receipts/ar/…` to a **bare-domain
vanity path** under `obsigna.dev`, preserving the existing subpath layout:

| Module | New path |
|--------|----------|
| `sdk/go` | `obsigna.dev/sdk/go` |
| `sdk/go/aws` | `obsigna.dev/sdk/go/aws` |
| `daemon` | `obsigna.dev/daemon` |
| `mcp-proxy` | `obsigna.dev/mcp-proxy` |
| `collector` | `obsigna.dev/collector` |
| `hook` | `obsigna.dev/hook` |
| `cross-sdk-tests` | `obsigna.dev/cross-sdk-tests` |

A vanity path **decouples module identity from the GitHub repo name
permanently.** The repo can be renamed, forked, or mirrored again and the import
path never moves; resolution is steered by a meta tag we serve, not by GitHub's
redirect table. This is the precise lesson of the `ar`→`obsigna` rename, applied
structurally instead of patched over.

The module subpaths already mirror the repository's directory layout, so a
**single `go-import` rule maps all seven modules** — there is no per-module
endpoint or per-module DNS to maintain (see decision 3).

### 2. Bare-domain (`obsigna.dev/…`), not a `go.obsigna.dev` subdomain

The realistic alternatives are bare-domain (`obsigna.dev/sdk/go`) and an
isolated subdomain (`go.obsigna.dev/sdk/go`). Both are valid; the trade is
**path cleanliness vs. resolution isolation.**

- **Bare-domain** gives the cleanest, most memorable paths and is
  well-precedented at scale (`tailscale.com/…`, `upspin.io/…`,
  `gopkg.in/…`-style apex hosting). Its one real cost: the `?go-get=1`
  meta-response must be served from the *same host* that serves the marketing
  site, so a careless site rewrite could drop the catch-all and break `go get`
  for everyone.
- **Subdomain** isolates the `go-import` endpoint onto a dedicated minimal host
  that can do nothing but serve meta tags, immune to docs-site churn — at the
  cost of longer paths and a second host/DNS record to own.

We choose **bare-domain**, and we **neutralise its one weakness directly** rather
than buy isolation with uglier paths: the `go-import`/`go-source` response is
implemented as a **permanent, infrastructure-level catch-all** (base-template or
edge handler — decision 3), never as a content page, and its liveness is
**gated** (decision 4) so a site change that breaks module resolution fails CI
instead of shipping. With the failure mode closed off, the subdomain's isolation
advantage no longer justifies the path-cleanliness cost. The honest counterweight
is recorded: if the site host ever proves operationally hostile to a guaranteed
catch-all, `go.obsigna.dev` remains the fallback, and because the *paths
themselves* would change, that reversal would be a second breaking migration —
so the gate in decision 4 is what makes bare-domain safe to commit to.

### 3. Stand up the `go-import` meta endpoint as permanent infrastructure

`obsigna.dev` must answer every `https://obsigna.dev/<subpath>?go-get=1` request
with a document carrying:

```html
<meta name="go-import"
      content="obsigna.dev git https://github.com/agent-receipts/obsigna">
<meta name="go-source"
      content="obsigna.dev
               https://github.com/agent-receipts/obsigna
               https://github.com/agent-receipts/obsigna/tree/main{/dir}
               https://github.com/agent-receipts/obsigna/blob/main{/dir}/{file}#L{line}">
```

- The single `go-import` line uses **import-prefix `obsigna.dev`** mapping to the
  GitHub repo root. Because every module's path suffix (`sdk/go`, `daemon`, …)
  equals its subdirectory in the repo, the Go tool derives each module's location
  from one rule. No per-module entries are required.
- The `go-source` line wires `pkg.go.dev` "jump to source" links to the GitHub
  tree/blob URLs.
- This is served as a **catch-all over the whole `obsigna.dev/*` space**
  (base-template meta or an edge handler), **not** a single hand-maintained page.
  If this endpoint 404s or stops emitting the tag, `go get` breaks for *every*
  consumer of *every* module — so it is treated as load-bearing infrastructure,
  tied to the `site-obsigna/` site move already underway, and it lands **before**
  any module path is flipped (decision 5 / *Rollout*).

### 4. The endpoint's liveness is gated

Per ADR-0024 (every asserted property has a gate), the claim "`obsigna.dev`
resolves our modules" is enforced, not trusted:

- A check fetches `https://obsigna.dev/sdk/go?go-get=1` (and one binary subpath)
  and asserts the response contains the expected `go-import` meta with
  import-prefix `obsigna.dev` and the GitHub repo root. This guards against a
  site deploy silently dropping the catch-all.
- After cutover, a resolution check confirms `go get obsigna.dev/sdk/go@latest`
  (against a clean module cache) resolves to the current published version.

Whether these run as a periodic external probe, a site-CI gate, or both is an
implementation choice for the *Rollout* PRs; the requirement is that the
endpoint cannot regress unobserved.

### 5. Module-path identity is a breaking change with a migration window

A Go module path **is** its identity. Renaming `sdk/go`'s `module` line from
`github.com/agent-receipts/ar/sdk/go` to `obsigna.dev/sdk/go` means:

- **Already-pinned versions keep working.** Tags cut before the rename carry the
  old `module` line in their `go.mod`; a consumer pinned to
  `github.com/agent-receipts/ar/sdk/go@vX.Y.Z` continues to resolve that exact
  version unchanged. We **do not delete or move old tags.**
- **New versions ship only under the new path.** After the rename, fresh tags
  carry `module obsigna.dev/sdk/go`, and
  `go get github.com/agent-receipts/ar/sdk/go@latest` will **no longer find
  them** — the old path is frozen at its last `ar`-era version.
- **There is no alias.** Go has no module-path aliasing; a consumer who wants new
  versions must update their import statements to `obsigna.dev/sdk/go`. This is
  the unavoidable, one-time cost the *Context* footgun forces us to pay.

`sdk/go` (and `sdk/go/aws`) are therefore the **breaking** modules — they have
external importers. The binary modules (`daemon`, `mcp-proxy`, `collector`,
`hook`, `cross-sdk-tests`) have **no external importers**: nobody imports them as
libraries, they are built into binaries by the unified `obsigna` train (ADR-0034)
or run as in-repo tests. Renaming their module paths is **pure internal churn**
with no downstream migration.

## Consequences

- Module identity is **permanently decoupled from the GitHub repo name.** A
  future rename, fork, or mirror cannot break or hijack resolution; the
  squatting vector in *Context* is closed because `agent-receipts/ar` is no
  longer in any resolution path.
- The import identity finally matches the product and packaging identity
  (`obsigna.dev/…`, `obsigna-*`, `obsigna/v*`). The loose end ADR-0034 decision
  10 deliberately left is tied off.
- **One-time breaking cost for external Go consumers of `sdk/go`:** they must
  rewrite imports to `obsigna.dev/sdk/go` to receive new versions. Old pins keep
  building forever (tags are never deleted), so there is no forced-flag-day — but
  there is no aliased "both paths get new versions" either. A migration note
  ships with the cutover (CHANGELOG + README).
- **A new operational dependency:** `obsigna.dev` serving the `go-import` meta is
  now load-bearing for *all* Go builds, including the release train's
  `GOWORK=off` dependency resolution. The catch-all + gate (decisions 3–4) is the
  mitigation; the cost is that the site host can no longer be treated as
  best-effort for the `?go-get=1` path.
- `go.work` is **unaffected** — it lists directories, not module paths — so local
  builds, CI, and `go test ./…` across the workspace keep resolving the in-tree
  `sdk/go` regardless of the path flip. (This is also why the binary path-flips
  can land before `sdk/go` is published under the vanity path; see the *Rollout*
  release-ordering note.)
- `pkg.go.dev` will index the modules under `obsigna.dev/…` with working source
  links once the `go-source` meta is live and a version is published.

## Rollout

Three PRs, sequenced by a hard dependency: **module paths do not resolve until
the meta endpoint is live, so it lands first.**

### PR 1 — stand up the `go-import` / `go-source` meta endpoint (prerequisite)

Serve the decision-3 meta tags as a **permanent catch-all** over `obsigna.dev/*`
(base-template or edge handler), wired into the `site-obsigna/` site move already
underway, with the decision-4 liveness gate. **No module path changes in this
PR.** Nothing downstream can merge until this is live and verified —
`go get` is broken for any flipped module until the endpoint answers.

### PR 2 — flip the internal binary modules (low risk, pure churn)

For `daemon`, `mcp-proxy`, `collector`, `hook`, and `cross-sdk-tests`:

- Flip each `go.mod` `module` line to `obsigna.dev/…`.
- Rewrite all in-repo imports `github.com/agent-receipts/ar/… → obsigna.dev/…`
  via a scripted `gofmt -r` / `sed` pass followed by `goimports`.
- Update each module's `require obsigna.dev/sdk/go` line (the dependency edge).
- `go.work` needs **no change** (directories, not paths).

These modules have no external importers, so this is internal-only. In-tree
builds and CI keep working immediately via `go.work`.

### PR 3 — flip `sdk/go` (+ `sdk/go/aws`): the breaking change

- Flip the `module` line to `obsigna.dev/sdk/go` (and `obsigna.dev/sdk/go/aws`).
- **Keep the old `ar` tags importable** — do not delete or retag; pinned
  consumers must keep resolving.
- Publish the first vanity version (the `sdk/go/vX.Y.Z` tag scheme is
  repo-relative and **unchanged** — only the `module` line moves).
- Ship the **consumer migration note**: CHANGELOG entry + README — "imports move
  to `obsigna.dev/sdk/go`; pin pre-migration versions on the legacy
  `github.com/agent-receipts/ar/sdk/go` path, which is frozen and receives no new
  versions."
- Coordinate with PR 2's `require obsigna.dev/sdk/go` bumps.

**Release-ordering note.** PR 2 and PR 3 *code* can land in either order because
`go.work` resolves the in-tree `sdk/go` for all local and CI builds. But a
**released** binary build runs `GOWORK=off` (ADR-0034) and resolves its
`require obsigna.dev/sdk/go vX.Y.Z` from the module proxy — so the first
*released* `obsigna` toolset build under the vanity paths must follow a
**published** vanity `sdk/go` version. Practically: merge PR 1, then PR 2 + PR 3,
publish the vanity `sdk/go` tag, then cut the next `obsigna/vX.Y.Z` toolset
release.

## Supersedes ADR-0023

ADR-0023 ("Canonical Go Module Path") resolved a different problem — a
two-module-paths split between `github.com/agent-receipts/ar/sdk/go` and a stale
standalone `github.com/agent-receipts/sdk-go` — and its decision **D1** named
`github.com/agent-receipts/ar/sdk/go` canonical. **This ADR supersedes D1:** the
canonical path is now `obsigna.dev/sdk/go`. The reasoning that made the monorepo
path canonical over the standalone one (development, releases, and shared build
infrastructure all live in the monorepo) is unchanged and carries forward — this
ADR only re-homes that canonical path off the GitHub repo name and onto the
vanity domain.

The rest of ADR-0023 is settled or overtaken, not contradicted:

- **D2** (deprecate the standalone `github.com/agent-receipts/sdk-go`) **stands**
  — that module remains deprecated; the canonical target its notices point to is
  simply now the vanity path.
- **D3** (tag the collector module independently) was **already overtaken by
  ADR-0034**, which folds the collector into the unified `obsigna/v*` train.
- **D4/D5** (README/site path updates and release-time resolution verification)
  are **re-instantiated against the new path** by PR 1's gate (decision 4) and
  PR 3's migration note.

ADR-0023 moves to **Superseded by ADR-0037** in its Status header and in the
index.

## Amends

- **ADR-0034** (Consolidate the Go Toolset): reverses its decision-10 non-goal
  "Go module paths stay `github.com/agent-receipts/ar/…` (ADR-0023) … not touched
  here." ADR-0034 correctly scoped *packaging* identity and set *import* identity
  aside; this ADR picks up exactly that deferred concern. The unified train, tag
  scheme (`obsigna/v*`, `sdk/go/v*`), `GOWORK=off` release builds, and umbrella
  formula are **unchanged** — only the `module` lines and in-repo imports move.

## Non-goals / explicitly unchanged

- **The GitHub org and repo** stay `agent-receipts/obsigna`. The vanity path
  points *at* this repo; it does not rename it.
- **Binary names** (`obsigna`, `obsigna-daemon`, `obsigna-mcp`,
  `obsigna-collector`, `obsigna-hook`, `agent-receipts` shim) are untouched —
  module path ≠ binary name.
- **The `obsigna` Homebrew formula** and its `tap_migrations.json` map (ADR-0034)
  are untouched.
- **`did:agent-receipts-daemon:` issuer strings** are untouched — issuer DIDs are
  a protocol/trust concern, not a module-path concern.
- **`AGENTRECEIPTS_*` environment variables** are untouched.
- **The `sdk/go/v*` (and per-module subdir) tag scheme** is untouched — tags are
  repo-relative; only the `module` line changes.
- **No code, `go.mod`, import, or site changes in this PR** — this is design
  capture. The flips happen in the *Rollout* PRs.
