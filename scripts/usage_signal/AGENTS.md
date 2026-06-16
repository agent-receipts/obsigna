# usage_signal

Tells real adopters apart from mirrors, CI, and scanners across the packages
this org publishes (npm, PyPI, Go, and Homebrew-tap binaries).

Tracked by default (edit the `*_PACKAGES` / `GITHUB_REPOS` constants in
`check.py` to add more):

| Project | Channel(s) |
|---------|-----------|
| `agent-receipts` monorepo (`agent-receipts/obsigna`) | npm `@obsigna/sdk-ts`, `@obsigna/sdk-ts-aws`; PyPI `obsigna`; Go `sdk/go`; Homebrew/release binaries (daemon, hook, mcp-proxy, collector) |
| `openclaw` | npm `@agnt-rcpt/openclaw` |
| `dashboard` (`agent-receipts/dashboard`) | Homebrew tap / release binaries |

For a young package the public download counters are misleading. npm folds in,
with no opt-out, every registry mirror, security scanner (Socket, Snyk,
Dependabot, Renovate), proxy cache, and your own release CI. PyPI is the same
minus the mirrors — which it at least lets you subtract. Go publishes no
download count at all. So the raw total says little; you have to read the
*shape* of the traffic.

## Layout

| File | Role |
|------|------|
| `check.py` | Fetches the signals and prints a machine-vs-human verdict per package. |
| `test_check.py` | Unit tests for the pure classifiers (`classify_series`, `classify_versions`, `classify_release_assets`, `verdict`). No network. |

`check.py` and `test_check.py` use only the Python standard library. The
publish-date cross-check additionally calls the `npm` CLI if it is on `PATH`;
it is skipped silently otherwise.

## Run locally

```sh
python3 scripts/usage_signal/test_check.py        # unit tests (no network)
python3 scripts/usage_signal/check.py             # all repo packages, live
python3 scripts/usage_signal/check.py --json      # machine-readable
python3 scripts/usage_signal/check.py --npm @obsigna/sdk-ts --no-pypi --go-off
```

Live mode needs egress to `api.npmjs.org`, `pypistats.org`, `pkg.go.dev`, and
`api.github.com`. A `GITHUB_TOKEN` / `GH_TOKEN` raises the GitHub rate limit but
is not required for a public repo. A source that fails to fetch is reported as
unavailable rather than aborting the run.

## The four signals it reads

1. **Daily-series shape** (npm, PyPI). Real adoption leaves a persistent,
   weekday-skewed baseline that does not hit zero and is not made of one-day
   bursts. Automated traffic is flat across the week (mirrors and scanners
   don't take weekends off) and dominated by same-day spikes that react to your
   own publishes and decay within ~48h. The classifier reports the spike share
   of volume, the weekend/weekday ratio, and the count of zero-download days.

2. **Per-version distribution** (npm). A mirror clones *every* version,
   including abandoned pre-releases nobody installs fresh, so downloads smear
   evenly across the history. A human installs the latest one or two. The
   classifier flags pre-releases still drawing downloads and a low share on the
   top version.

3. **Adoption-by-reference** (PyPI mirror split, Go imported-by, GitHub
   dependents). The strongest signal: someone committed your package to their
   manifest. PyPI's `without_mirrors` series strips mirror noise outright and
   the tool reports the mirror fraction; Go has no counter, so the tool reports
   the `pkg.go.dev` imported-by count and links the GitHub dependents graph.

4. **Homebrew / GitHub Release assets**. The binary modules (`hook`,
   `mcp-proxy`, `daemon`, `collector`) install via a custom Homebrew tap, which
   gets **no** `formulae.brew.sh` analytics — that only covers `homebrew/core`.
   But `brew install` fetches the release tarball straight from GitHub, and the
   per-asset `download_count` is exposed by the API. This is the **cleanest**
   signal of the set: release binaries are not cloned by registry mirrors or
   pulled by package scanners, so almost the only thing that downloads
   `…_darwin_arm64.tar.gz` is a real `brew install`. The tool reads the
   platform split as a human-vs-CI heuristic — desktop (macOS/Windows) downloads
   with little Linux are laptop installs; Linux-dominated downloads are CI or
   containers. Counts are cumulative per release (GitHub exposes no daily
   series), so this signal is about totals and platform mix, not weekday shape.

   It also discounts CI. **Linux downloads are treated as automation** — there
   are no organic Linux users for a Homebrew-tap Mac CLI, and the release gates
   pull Linux builds (e.g. Gate #8, the daemon ↔ SDK protocol check, downloads
   `daemon_<v>_linux_amd64.tar.gz` on ubuntu on every daemon/SDK release). On top
   of that it detects **CI sweeps**: a release-verification or supply-chain job
   fetches the *whole* artifact set (checksums manifest plus Linux builds),
   whereas a human installs one desktop binary via brew and never pulls
   `checksums.txt`. A release with a checksums download alongside a Linux download
   is flagged as swept, and one download per desktop artifact in it is also
   attributed to automation. The reported install-event count therefore discounts
   your own release gates instead of crediting them as adopters.

   Note on the Homebrew tap's own CI: `agent-receipts/homebrew-tap` runs
   `brew audit --strict --online` on `macos-latest`, but online audit does
   URL-liveness HEAD checks, and GitHub increments `download_count` only on a GET
   of the asset — so the macOS audit job does not inflate `darwin_arm64`.

   The headline figure is reported as **install events, not people** — GitHub's
   `download_count` is an undeduplicated event counter, so it multiplies across
   version upgrades, modules, machines, and reinstalls. The tool also reports the
   **peak single (module, version) build** as a distinct-machines proxy (it
   carries no version multiplier), but a true headcount needs server-side logs
   where a client is identifiable, not this counter.

   The Homebrew section prints a **per-module patch-level timeline** (each
   version's human-desktop installs, platform split, and a `⚠ CI sweep` flag) and
   an **install-base estimate**: the peak single build of the *superset* module
   (the daemon — everyone needs it, since the hook forwards to it), with a
   per-module peak ladder showing the others as overlapping subsets of the same
   base. Reading the same ~N across independently-versioned modules is the
   strongest evidence it's one coherent user base rather than separate pockets.

## Reading the verdict

`machine-dominated` is the **expected** baseline for a young package and is not
a failure — it simply means the download number is your own pipeline plus
mirrors and scanners. The tool earns its keep on the day the shape changes: a
sustained, weekday-skewed baseline climbing on the latest version is the
signature of a first real adopter, and it will flip the verdict to
`human-leaning`.

The classifier weighs heuristics; it is a triage aid, not an oracle. Treat a
`human-leaning` flag as "go investigate" (check GitHub dependents, code search,
and docs-site analytics), not as proof on its own.
