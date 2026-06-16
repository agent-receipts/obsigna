#!/usr/bin/env python3
"""Usage-signal check: tell real adopters apart from mirrors, CI, and scanners.

For a young package the public download counters lie. npm's number folds in,
with no opt-out, every registry mirror (Cloudflare, Yarn, regional mirrors that
clone the whole version history), every security scanner (Socket, Snyk,
Dependabot, Renovate), every proxy cache, and your own release CI. PyPI is the
same minus the mirrors, which it at least lets you subtract. Go publishes no
download count at all. So the raw total is close to meaningless on its own — you
have to read the *shape* of the traffic, not its size.

This tool pulls the shape for every package this monorepo ships and prints a
machine-vs-human verdict per ecosystem. The four signals it reads:

1. Daily-series shape (npm, PyPI). Real human adoption leaves a persistent,
   weekday-skewed baseline that does not drop to zero and does not consist of
   one-day bursts. Automated traffic is the opposite: flat across the week
   (mirrors and scanners don't take weekends off) and dominated by same-day
   spikes that react to your own publishes and then decay within ~48h.

2. Per-version distribution (npm). A mirror clones *every* version, including
   abandoned pre-releases nobody would install fresh, so downloads smear evenly
   across the whole history. A human installs the latest one or two.

3. Adoption-by-reference (PyPI mirror split, Go imported-by, GitHub dependents).
   The strongest signal there is: someone committed your package to their
   manifest. PyPI's ``without_mirrors`` series strips mirror noise outright; Go
   has no counter but ``pkg.go.dev`` reports an imported-by count.

4. Homebrew / GitHub Release assets. Binaries installed via a custom Homebrew tap
   are downloaded straight from GitHub Releases, so per-asset download counts are
   a clean install signal (not mirror-amplified). Linux pulls are CI (release
   gates), full-artifact "sweeps" are discounted, and the desktop-platform count
   reads as real installs — reported as events, not people.

The classification core (``classify_series``, ``classify_versions``,
``classify_release_assets``, ``verdict``) is pure and takes no network, so the
unit tests exercise it
directly with synthetic machine- and human-shaped inputs. The fetchers are thin
I/O wrappers, best-effort: a source that fails to fetch is reported as
unavailable rather than aborting the run.

Usage:
    check.py [--npm PKG ...] [--pypi PKG ...] [--go MODULE ...]
             [--github OWNER/REPO ...] [--no-npm] [--no-pypi] [--go-off]
             [--no-github] [--json]

With no package flags it uses this repo's published packages. Network egress to
api.npmjs.org, pypistats.org, and pkg.go.dev is required for live data; the
``npm view`` publish-date lookup additionally needs the npm CLI on PATH.

Exit codes:
    0  ran and printed a report (even if some sources were unavailable)
    2  usage error
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import statistics
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass

# ---------------------------------------------------------------------------
# Defaults for this monorepo

NPM_PACKAGES = ["@obsigna/sdk-ts", "@obsigna/sdk-ts-aws", "@agnt-rcpt/openclaw"]
PYPI_PACKAGES = ["obsigna"]
GO_MODULES = ["github.com/agent-receipts/ar/sdk/go"]
GITHUB_REPO = "agent-receipts/ar"  # repo hosting the Go module (dependents link)
# Repos whose GitHub release assets are scanned for Homebrew-tap install signal:
# the monorepo (daemon/hook/mcp-proxy/collector) plus the dashboard tap.
GITHUB_REPOS = ["agent-receipts/ar", "agent-receipts/dashboard"]

# ---------------------------------------------------------------------------
# Classification thresholds. A "spike" is a publish/mirror reaction day; the
# default threshold is relative to the package's own baseline so it scales from
# a 5/day package to a 5000/day one, with an absolute floor so a near-dead
# package doesn't promote its own noise to "spike".

SPIKE_FACTOR = 10  # a day above SPIKE_FACTOR * median(nonzero) is a spike
SPIKE_FLOOR = 50  # ...but never below this absolute count

# weekend/weekday ratio bands. Humans install at work, so genuine adoption
# skews to weekdays (ratio well below 1). A flat week is a machine week.
FLAT_WEEK_LO, FLAT_WEEK_HI = 0.7, 1.4
HUMAN_WEEKDAY_RATIO = 0.7  # weekend/weekday below this leans human

# Release-asset platform split. CI and containers are Linux; humans installing a
# CLI via Homebrew are on macOS/Windows desktops. A desktop-dominated mix with
# little Linux is a human-laptop signal, not automation.
DESKTOP_FRACTION_HUMAN = 0.6

HTTP_TIMEOUT = 20
USER_AGENT = "agent-receipts-usage-signal/1.0 (+https://github.com/agent-receipts/ar)"


# ---------------------------------------------------------------------------
# Pure classification core (no network)


@dataclass
class SeriesMetrics:
    """Shape metrics for a daily download series over its active window."""

    total: int
    active_days: int
    spike_threshold: int
    spike_days: int
    spike_share: float  # fraction of all downloads landing on spike days
    baseline_median: float  # median of non-spike days
    baseline_mean: float
    zero_days: int  # non-spike days with literally zero downloads
    weekday_per_day: float  # mean baseline downloads on Mon-Fri
    weekend_per_day: float  # mean baseline downloads on Sat-Sun
    weekend_weekday_ratio: float  # weekend_per_day / weekday_per_day, 0 if N/A


def active_window(series: list[tuple[datetime.date, int]]) -> list[tuple[datetime.date, int]]:
    """Trim leading and trailing all-zero runs (pre-launch / future padding)."""
    nz = [i for i, (_, n) in enumerate(series) if n > 0]
    if not nz:
        return []
    return series[nz[0] : nz[-1] + 1]


def spike_threshold_for(values: list[int]) -> int:
    """Threshold above which a day counts as a publish/mirror spike."""
    nonzero = [v for v in values if v > 0]
    if not nonzero:
        return SPIKE_FLOOR
    return max(SPIKE_FLOOR, int(SPIKE_FACTOR * statistics.median(nonzero)))


def classify_series(
    series: list[tuple[datetime.date, int]],
    spike_threshold: int | None = None,
) -> SeriesMetrics | None:
    """Reduce a daily series to shape metrics over its active window.

    Returns ``None`` if the series never had a download (nothing to classify).
    Weekday/weekend means are computed on baseline (non-spike) days only, so a
    burst of mirror traffic on a publish day cannot masquerade as a human floor.
    """
    window = active_window(series)
    if not window:
        return None

    values = [n for _, n in window]
    threshold = spike_threshold if spike_threshold is not None else spike_threshold_for(values)

    baseline = [(d, n) for d, n in window if n < threshold]
    spike = [(d, n) for d, n in window if n >= threshold]
    base_vals = [n for _, n in baseline]

    weekday = [n for d, n in baseline if d.weekday() < 5]
    weekend = [n for d, n in baseline if d.weekday() >= 5]
    weekday_per_day = statistics.mean(weekday) if weekday else 0.0
    weekend_per_day = statistics.mean(weekend) if weekend else 0.0
    ratio = (weekend_per_day / weekday_per_day) if weekday_per_day else 0.0

    return SeriesMetrics(
        total=sum(values),
        active_days=len(window),
        spike_threshold=threshold,
        spike_days=len(spike),
        spike_share=(sum(n for _, n in spike) / sum(values)) if sum(values) else 0.0,
        baseline_median=statistics.median(base_vals) if base_vals else 0.0,
        baseline_mean=statistics.mean(base_vals) if base_vals else 0.0,
        zero_days=sum(1 for n in base_vals if n == 0),
        weekday_per_day=weekday_per_day,
        weekend_per_day=weekend_per_day,
        weekend_weekday_ratio=ratio,
    )


@dataclass
class VersionMetrics:
    """Per-version download distribution shape (npm)."""

    versions_with_downloads: int
    prerelease_versions: int  # pre-releases (X.Y.Z-...) still pulling downloads
    top_version: str
    top_share: float  # fraction of the week's downloads on the single top version


def classify_versions(version_downloads: dict[str, int]) -> VersionMetrics | None:
    """Summarise how downloads spread across published versions.

    Pre-releases drawing steady traffic, and a low share on the top version, are
    mirror fingerprints — no human installs ``X.Y.Z-alpha.1`` once a stable
    release exists.
    """
    active = {v: n for v, n in version_downloads.items() if n > 0}
    if not active:
        return None
    total = sum(active.values())
    top_version, top_n = max(active.items(), key=lambda kv: kv[1])
    return VersionMetrics(
        versions_with_downloads=len(active),
        prerelease_versions=sum(1 for v in active if "-" in v),
        top_version=top_version,
        top_share=top_n / total,
    )


def verdict(
    metrics: SeriesMetrics | None,
    versions: VersionMetrics | None = None,
    mirror_fraction: float | None = None,
) -> tuple[str, list[str]]:
    """Weigh the signals into a machine-vs-human leaning and the reasons why."""
    machine = 0
    human = 0
    notes: list[str] = []

    if metrics is None:
        return "no data", ["no downloads recorded in the window"]

    if metrics.spike_share >= 0.5:
        machine += 1
        notes.append(
            f"{metrics.spike_share:.0%} of traffic is same-day spikes "
            f"(>= {metrics.spike_threshold}/day) — publish/mirror reactions, not steady use"
        )
    if metrics.weekday_per_day == 0:
        # Only weekend baseline days (or none) — there is no weekly rhythm to read.
        notes.append("insufficient weekday baseline to read a weekday/weekend rhythm")
    elif FLAT_WEEK_LO <= metrics.weekend_weekday_ratio <= FLAT_WEEK_HI:
        machine += 1
        notes.append(
            f"flat week: weekend/weekday ratio {metrics.weekend_weekday_ratio:.2f} "
            "(~1.0) — automated traffic ignores weekends"
        )
    elif metrics.weekend_weekday_ratio < HUMAN_WEEKDAY_RATIO:
        # Includes a 0.0 ratio (weekend-silent traffic), the strongest weekday skew.
        human += 1
        notes.append(
            f"weekday-skewed: weekend/weekday ratio {metrics.weekend_weekday_ratio:.2f} "
            "(< 0.7) — consistent with humans installing at work"
        )
    if metrics.zero_days > 0:
        machine += 1
        notes.append(
            f"{metrics.zero_days} zero-download day(s) in the active window — "
            "no persistent human floor across timezones"
        )

    if versions is not None:
        if versions.prerelease_versions > 0:
            machine += 1
            notes.append(
                f"{versions.prerelease_versions} pre-release version(s) still drawing "
                "downloads — mirrors cloning the whole history, not humans"
            )
        if versions.top_share < 0.5:
            machine += 1
            notes.append(
                f"top version only {versions.top_share:.0%} of weekly downloads "
                "(smeared across the version history) — mirror fingerprint"
            )
        else:
            human += 1
            notes.append(
                f"downloads concentrate on {versions.top_version} "
                f"({versions.top_share:.0%}) — installs target the latest release"
            )

    if mirror_fraction is not None:
        if mirror_fraction >= 0.5:
            machine += 1
            notes.append(
                f"{mirror_fraction:.0%} of PyPI downloads are mirror traffic "
                "(stripped from the human analysis above)"
            )
        else:
            notes.append(f"{mirror_fraction:.0%} of PyPI downloads are mirror traffic")

    if machine > human:
        label = "machine-dominated (mirrors / CI / scanners)"
    elif human > machine:
        label = "human-leaning — investigate, this may be a real adopter"
    else:
        label = "mixed / inconclusive"
    return label, notes


@dataclass
class ReleaseMetrics:
    """GitHub Release asset download shape (the Homebrew / binary install path)."""

    total_downloads: int  # binary downloads (checksums/sigs excluded)
    by_platform: dict[str, int]  # darwin / linux / windows
    by_module: dict[str, int]
    ci_sweep_releases: int  # releases whose full artifact set was pulled by automation
    ci_downloads: int  # binary downloads attributed to those sweeps
    install_events: int  # total_downloads - ci_downloads; download events, NOT people
    peak_build: int  # most install events on a single (module, version) build
    peak_build_module: str  # the module that peak belongs to

    @property
    def desktop_downloads(self) -> int:
        """darwin + windows — the human install platforms."""
        return self.by_platform.get("darwin", 0) + self.by_platform.get("windows", 0)

    @property
    def server_downloads(self) -> int:
        """linux — the CI / server platform."""
        return self.by_platform.get("linux", 0)

    @property
    def desktop_fraction(self) -> float:
        return self.desktop_downloads / self.total_downloads if self.total_downloads else 0.0


def parse_asset_platform(name: str) -> str | None:
    """Platform an asset targets, or None for non-binary assets (checksums, sigs)."""
    lowered = name.lower()
    if any(lowered.endswith(ext) for ext in (".txt", ".sig", ".pem", ".sbom", ".json")):
        return None
    if "darwin" in lowered or "macos" in lowered:
        return "darwin"
    if "linux" in lowered:
        return "linux"
    if "windows" in lowered:
        return "windows"
    return None


def _asset_module_version(name: str) -> tuple[str, str]:
    """(module, version) parsed from a GoReleaser asset filename.

    e.g. ``daemon_0.13.0_darwin_arm64.tar.gz`` -> ``("daemon", "0.13.0")``. The
    version is anchored between the module and the platform token and excludes
    ``_``, so a module name that itself embeds ``_<digit>`` (e.g. ``foo_2``) is
    kept whole rather than truncated. Returns ``("", "")`` if the name doesn't
    match the ``module_version_os_arch`` form.
    """
    m = re.match(
        r"^(?P<module>.+)_v?(?P<version>\d[A-Za-z0-9.\-]*)_(?:darwin|linux|windows|macos)_",
        name,
        re.IGNORECASE,
    )
    if not m:
        return "", ""
    return m.group("module"), m.group("version")


def is_ci_sweep(assets: list[tuple[str, int]]) -> bool:
    """True if a release's full artifact set was pulled by automation.

    The fingerprint of a release-verification / supply-chain job (vs a human
    installing via Homebrew) is that it fetches *everything*: the checksums
    manifest plus the Linux server builds. A human is on one desktop platform,
    installs via brew, and never downloads checksums.txt (brew verifies against
    the sha256 pinned in the formula). So: a checksums download together with any
    Linux download marks the release as swept.
    """
    checksums = any(
        count > 0 and parse_asset_platform(name) is None and "checksum" in name.lower()
        for name, count in assets
    )
    linux = any(count > 0 and parse_asset_platform(name) == "linux" for name, count in assets)
    return checksums and linux


@dataclass
class ReleaseSplit:
    """A single release's downloads split into human (desktop) vs CI."""

    module: str
    version: str  # asset-derived version, "" if unparseable
    human: int  # desktop install events, minus any sweep-pulled desktop artifact
    ci: int  # Linux pulls + sweep-pulled desktop artifacts
    swept: bool
    by_platform: dict[str, int]  # gross darwin / linux / windows for this release


def split_release(assets: list[tuple[str, int]]) -> ReleaseSplit:
    """Split one release's assets into human-desktop installs and CI downloads.

    Linux is always CI (no organic users for a Homebrew-tap Mac CLI, and release
    gates like Gate #8 pull the linux_amd64 daemon tarball). In a swept release
    (see ``is_ci_sweep``) the verification job also pulled one of each desktop
    artifact, so one download per desktop artifact is attributed to CI too.
    """
    swept = is_ci_sweep(assets)
    by_platform: dict[str, int] = {}
    human = 0
    ci = 0
    module = ""
    version = ""
    for name, count in assets:
        platform = parse_asset_platform(name)
        if platform is None or count <= 0:
            continue
        by_platform[platform] = by_platform.get(platform, 0) + count
        if not module:
            module, version = _asset_module_version(name)
        if platform == "linux":
            ci += count
        elif swept:
            ci += 1
            human += count - 1
        else:
            human += count
    return ReleaseSplit(
        module=module, version=version, human=human, ci=ci, swept=swept, by_platform=by_platform
    )


def aggregate_releases(splits: list[ReleaseSplit]) -> ReleaseMetrics | None:
    """Aggregate already-split releases into overall metrics.

    Linux pulls and the desktop artifacts of a CI sweep are attributed to
    automation. Returns ``None`` if no binary asset has ever been downloaded.
    """
    by_platform: dict[str, int] = {}
    by_module: dict[str, int] = {}
    ci_sweep_releases = 0
    ci_downloads = 0
    peak_build = 0
    peak_build_module = ""
    for split in splits:
        if split.swept:
            ci_sweep_releases += 1
        ci_downloads += split.ci
        for platform, count in split.by_platform.items():
            by_platform[platform] = by_platform.get(platform, 0) + count
        if split.module:
            by_module[split.module] = by_module.get(split.module, 0) + sum(split.by_platform.values())
        if split.human > peak_build:
            peak_build = split.human
            peak_build_module = split.module

    total = sum(by_platform.values())
    if total == 0:
        return None
    return ReleaseMetrics(
        total_downloads=total,
        by_platform=by_platform,
        by_module=by_module,
        ci_sweep_releases=ci_sweep_releases,
        ci_downloads=ci_downloads,
        install_events=total - ci_downloads,
        peak_build=peak_build,
        peak_build_module=peak_build_module,
    )


def classify_release_assets(releases: list[list[tuple[str, int]]]) -> ReleaseMetrics | None:
    """Split each release's ``(asset_name, download_count)`` list, then aggregate."""
    return aggregate_releases([split_release(assets) for assets in releases])


@dataclass
class ReleaseInfo:
    """One GitHub release: its tag and its (asset_name, download_count) list."""

    tag: str
    assets: list[tuple[str, int]]


def module_version_from_tag(tag: str) -> tuple[str, str]:
    """Split a release tag into (module, version).

    Binary-module tags look like ``hook/v0.12.0`` or ``mcp-proxy/v0.13.0``; SDK
    tags like ``sdk-ts-v0.10.0``; a bare ``v1.2.3`` has no module. Returns
    ``("", "")`` for a tag with no version at all (empty, or a draft
    ``untagged-<sha>``), so callers can fall back to the asset-derived version
    rather than treating the whole tag as a version string.
    """
    m = re.match(r"^(.*?)[/-]v?(\d[\w.\-]*)$", tag)
    if m:
        return m.group(1).rstrip("/-"), m.group(2)
    m = re.match(r"^v?(\d[\w.\-]*)$", tag)  # bare version, no module prefix
    if m:
        return "", m.group(1)
    return "", ""


def _version_key(version: str) -> tuple:
    """Total-orderable sort key for a version string.

    Each segment becomes a uniform ``(kind, int, str)`` triple — numeric segments
    compare numerically, non-numeric ones as strings, and an int never compares
    against a str (which would raise ``TypeError``). A pre-release sorts before
    its release.
    """
    base, _, pre = version.partition("-")
    nums = tuple((0, int(s), "") if s.isdigit() else (1, 0, s) for s in base.split("."))
    return (nums, 0 if pre else 1, pre)


def build_timeline(
    pairs: list[tuple[ReleaseInfo, ReleaseSplit]],
) -> dict[str, list[tuple[str, ReleaseSplit]]]:
    """Group already-split releases into a per-module, version-sorted timeline.

    Releases with no downloaded binary assets drop out (SDK source-only tags).
    Module and version come from the tag when it parses to a clean version,
    falling back to the asset-derived values so an untagged/draft release is
    still placed under its real module rather than an empty bucket.
    """
    timeline: dict[str, list[tuple[str, ReleaseSplit]]] = {}
    for rel, split in pairs:
        if not split.by_platform:
            continue  # no binary downloads for this release
        module, version = module_version_from_tag(rel.tag)
        if not version[:1].isdigit():  # tag carried no clean version
            module, version = split.module, split.version
        module = module or split.module
        version = version or split.version
        timeline.setdefault(module, []).append((version, split))
    for versions in timeline.values():
        versions.sort(key=lambda vs: _version_key(vs[0]))
    return timeline


def release_timeline(releases: list[ReleaseInfo]) -> dict[str, list[tuple[str, ReleaseSplit]]]:
    """Per-module list of (version, ReleaseSplit), version-sorted ascending."""
    return build_timeline([(rel, split_release(rel.assets)) for rel in releases])


def verdict_release(metrics: ReleaseMetrics | None) -> tuple[str, list[str]]:
    """Lean on the desktop-vs-Linux split, discounting detected CI sweeps."""
    if metrics is None:
        return "no data", ["no release binaries downloaded yet"]
    notes = [
        f"{metrics.total_downloads} binary download(s): "
        + ", ".join(f"{p} {n}" for p, n in sorted(metrics.by_platform.items()))
    ]
    if metrics.ci_sweep_releases:
        notes.append(
            f"{metrics.ci_sweep_releases} release(s) show a CI sweep "
            "(checksums + Linux pulled together) — full artifact set fetched by automation"
        )
    if metrics.server_downloads:
        notes.append(
            f"{metrics.server_downloads} Linux download(s) treated as CI (server platform; "
            "release gates such as the daemon ↔ SDK protocol check pull the linux build) "
            f"— {metrics.ci_downloads} download(s) total attributed to automation"
        )
    if metrics.install_events > 0 and metrics.desktop_fraction >= DESKTOP_FRACTION_HUMAN:
        label = "human-leaning — desktop installs (likely Homebrew on laptops)"
        notes.append(
            f"~{metrics.install_events} install events after discounting sweeps, essentially "
            "all desktop (macOS/Windows) with no organic Linux — release binaries aren't "
            "mirror-amplified, so this is real activity, not CI or scanners"
        )
        notes.append(
            "install events are DOWNLOADS, not people: each version upgrade, module, machine "
            f"and reinstall counts separately. Peak single build ({metrics.peak_build_module} "
            f"= {metrics.peak_build}) is the best distinct-machines proxy; a true headcount "
            "needs server-side logs (download_count has no de-duplication)"
        )
    elif metrics.server_downloads > metrics.desktop_downloads:
        label = "Linux-dominated — likely CI / containers"
        notes.append(
            f"{metrics.server_downloads} Linux vs {metrics.desktop_downloads} desktop "
            "downloads — automation territory"
        )
    else:
        label = "mixed / inconclusive"
    return label, notes


# ---------------------------------------------------------------------------
# Fetchers (best-effort I/O)


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # noqa: S310 (https only)
        return resp.read()


def _get_json(url: str) -> dict:
    return json.loads(_get(url))


def _npm_encode(pkg: str) -> str:
    return urllib.parse.quote(pkg, safe="@")


def npm_daily(pkg: str) -> list[tuple[datetime.date, int]]:
    data = _get_json(f"https://api.npmjs.org/downloads/range/last-year/{_npm_encode(pkg)}")
    return [
        (datetime.date.fromisoformat(row["day"]), int(row["downloads"]))
        for row in data.get("downloads", [])
    ]


def npm_versions(pkg: str) -> dict[str, int]:
    data = _get_json(f"https://api.npmjs.org/versions/{_npm_encode(pkg)}/last-week")
    return {v: int(n) for v, n in data.get("downloads", {}).items()}


def npm_publish_dates(pkg: str) -> list[datetime.date]:
    """Publish date of every version, via the npm CLI. Empty if npm is absent."""
    try:
        out = subprocess.run(
            ["npm", "view", pkg, "time", "--json"],
            capture_output=True,
            text=True,
            timeout=HTTP_TIMEOUT,
            check=True,
        ).stdout
    except (FileNotFoundError, subprocess.SubprocessError):
        return []
    times = json.loads(out) if out.strip() else {}
    dates = []
    for key, value in times.items():
        if key in ("created", "modified"):
            continue
        dates.append(datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).date())
    return sorted(dates)


def pypi_overall(pkg: str) -> tuple[list[tuple[datetime.date, int]], float]:
    """Daily ``without_mirrors`` series and the mirror fraction over the window.

    PyPI is the one ecosystem that hands you the mirror split directly, so we
    analyse the human (mirror-free) series and report what fraction was mirrors.
    """
    data = _get_json(f"https://pypistats.org/api/packages/{urllib.parse.quote(pkg)}/overall")
    without: dict[datetime.date, int] = {}
    with_total = 0
    without_total = 0
    for row in data.get("data", []):
        day = datetime.date.fromisoformat(row["date"])
        n = int(row["downloads"])
        if row["category"] == "without_mirrors":
            without[day] = without.get(day, 0) + n
            without_total += n
        elif row["category"] == "with_mirrors":
            with_total += n
    series = sorted(without.items())
    # Clamp: with_mirrors is the superset, but an uneven-date-coverage gap in the
    # API response could otherwise drive the difference negative.
    mirror_fraction = max(0.0, (with_total - without_total) / with_total) if with_total else 0.0
    return series, mirror_fraction


def go_imported_by(module: str) -> int | None:
    """Imported-by count from pkg.go.dev, or None if it can't be parsed."""
    try:
        html = _get(f"https://pkg.go.dev/{module}?tab=importedby").decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError):
        return None
    m = re.search(r"Imported By\s*<[^>]*>\s*([\d,]+)", html)
    if not m:
        m = re.search(r"([\d,]+)\s*packages? import", html)
    return int(m.group(1).replace(",", "")) if m else None


def github_releases(repo: str) -> list[ReleaseInfo]:
    """All releases (tag + asset download counts) for a repo, across all pages.

    Uses the public REST API; a GITHUB_TOKEN / GH_TOKEN in the environment raises
    the rate limit but is not required for a public repo.
    """
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    releases: list[ReleaseInfo] = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{repo}/releases?per_page=100&page={page}"
        req = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
        )
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # noqa: S310
            batch = json.loads(resp.read())
        if not batch:
            break
        for release in batch:
            assets = [(a["name"], int(a["download_count"])) for a in release.get("assets", [])]
            releases.append(ReleaseInfo(tag=release.get("tag_name", ""), assets=assets))
        if len(batch) < 100:
            break
        page += 1
    return releases


# ---------------------------------------------------------------------------
# Reporting


def _print_series_block(metrics: SeriesMetrics) -> None:
    print(
        f"    window {metrics.active_days}d | total {metrics.total} | "
        f"spikes {metrics.spike_days}d = {metrics.spike_share:.0%} of traffic "
        f"(>= {metrics.spike_threshold}/day)"
    )
    print(
        f"    baseline median {metrics.baseline_median:.0f}/day, "
        f"{metrics.zero_days} zero-day(s) | "
        f"weekday {metrics.weekday_per_day:.1f}/day vs weekend "
        f"{metrics.weekend_per_day:.1f}/day (ratio {metrics.weekend_weekday_ratio:.2f})"
    )


def _print_verdict(label: str, notes: list[str]) -> None:
    print(f"    VERDICT: {label}")
    for n in notes:
        print(f"      - {n}")


def report_npm(pkg: str) -> dict:
    print(f"\nnpm  {pkg}")
    try:
        series = npm_daily(pkg)
        versions = npm_versions(pkg)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"    unavailable: {exc}")
        return {"package": pkg, "ecosystem": "npm", "error": str(exc)}

    metrics = classify_series(series)
    vmetrics = classify_versions(versions)
    label, notes = verdict(metrics, vmetrics)

    if metrics:
        _print_series_block(metrics)
    if vmetrics:
        print(
            f"    versions: {vmetrics.versions_with_downloads} drawing downloads, "
            f"{vmetrics.prerelease_versions} pre-release; "
            f"top {vmetrics.top_version} = {vmetrics.top_share:.0%}"
        )
    publishes = npm_publish_dates(pkg)
    if publishes and metrics:
        print(f"    {len(publishes)} published version(s); cross-check spike days against these")
    _print_verdict(label, notes)
    return {
        "package": pkg,
        "ecosystem": "npm",
        "metrics": asdict(metrics) if metrics else None,
        "versions": asdict(vmetrics) if vmetrics else None,
        "verdict": label,
        "notes": notes,
    }


def report_pypi(pkg: str) -> dict:
    print(f"\nPyPI {pkg}")
    try:
        series, mirror_fraction = pypi_overall(pkg)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"    unavailable: {exc}")
        return {"package": pkg, "ecosystem": "pypi", "error": str(exc)}

    metrics = classify_series(series)
    label, notes = verdict(metrics, None, mirror_fraction)
    if metrics:
        _print_series_block(metrics)
    print(f"    mirror traffic: {mirror_fraction:.0%} (excluded from the analysis above)")
    _print_verdict(label, notes)
    return {
        "package": pkg,
        "ecosystem": "pypi",
        "metrics": asdict(metrics) if metrics else None,
        "mirror_fraction": mirror_fraction,
        "verdict": label,
        "notes": notes,
    }


def report_go(module: str) -> dict:
    print(f"\nGo   {module}")
    count = go_imported_by(module)
    if count is None:
        print("    imported-by: unavailable (parse failed or offline)")
    else:
        print(f"    imported-by (pkg.go.dev): {count}")
    print(
        "    Go publishes no download counts; adoption-by-reference only. "
        f"Also check: https://pkg.go.dev/{module}?tab=importedby"
    )
    print(f"    and GitHub dependents: https://github.com/{GITHUB_REPO}/network/dependents")
    return {"module": module, "ecosystem": "go", "imported_by": count}


def _platform_str(by_platform: dict[str, int]) -> str:
    order = ("darwin", "windows", "linux")
    parts = [f"{p}={by_platform[p]}" for p in order if by_platform.get(p)]
    return " ".join(parts) if parts else "-"


def report_github_releases(repo: str) -> dict:
    print(f"\nHomebrew / GitHub Releases  {repo}")
    try:
        releases = github_releases(repo)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"    unavailable: {exc}")
        return {"repo": repo, "ecosystem": "github-releases", "error": str(exc)}

    pairs = [(rel, split_release(rel.assets)) for rel in releases]
    metrics = aggregate_releases([s for _, s in pairs])
    timeline = build_timeline(pairs)
    label, notes = verdict_release(metrics)

    # Install-base anchor: per-module peak human build, and the overall superset.
    per_module_peak = {
        module: max((s.human for _, s in versions), default=0)
        for module, versions in timeline.items()
    }
    if per_module_peak:
        base_module = max(per_module_peak, key=lambda m: per_module_peak[m])
        base = per_module_peak[base_module]
        print(
            f"    install base (distinct Macs ≈ peak single build of the superset "
            f"module): ~{base}  [{base_module}]"
        )
        ladder = ", ".join(
            f"{m} {n}" for m, n in sorted(per_module_peak.items(), key=lambda kv: -kv[1])
        )
        print(f"    per-module peak (overlapping subsets of the same base): {ladder}")

    for module, versions in sorted(timeline.items()):
        print(f"    {module}:")
        for version, split in versions:
            flags = "  ⚠ CI sweep" if split.swept else ""
            human = f"{split.human} human" if split.human else "0 human"
            print(f"      {version:<14} {human:<10} [{_platform_str(split.by_platform)}]{flags}")

    _print_verdict(label, notes)
    print(
        "    note: counts are cumulative per release (no daily series); a custom Homebrew "
        "tap gets no formulae.brew.sh analytics. 'human' = desktop install EVENTS (not "
        "people): version upgrades, machines, and reinstalls each count once."
    )
    return {
        "repo": repo,
        "ecosystem": "github-releases",
        "metrics": asdict(metrics) if metrics else None,
        "install_base_estimate": max(per_module_peak.values(), default=0),
        "per_module_peak": per_module_peak,
        "verdict": label,
        "notes": notes,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--npm", nargs="*", metavar="PKG")
    parser.add_argument("--pypi", nargs="*", metavar="PKG")
    parser.add_argument("--go", nargs="*", metavar="MODULE")
    parser.add_argument(
        "--github", nargs="*", metavar="OWNER/REPO", help="repos for release-asset counts"
    )
    parser.add_argument("--no-npm", action="store_true")
    parser.add_argument("--no-pypi", action="store_true")
    parser.add_argument("--go-off", action="store_true")
    parser.add_argument("--no-github", action="store_true")
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = parser.parse_args(argv)

    npm_pkgs = args.npm if args.npm is not None else NPM_PACKAGES
    pypi_pkgs = args.pypi if args.pypi is not None else PYPI_PACKAGES
    go_mods = args.go if args.go is not None else GO_MODULES
    gh_repos = args.github if args.github is not None else GITHUB_REPOS

    results = []
    if not args.no_npm:
        for pkg in npm_pkgs:
            results.append(report_npm(pkg))
    if not args.no_pypi:
        for pkg in pypi_pkgs:
            results.append(report_pypi(pkg))
    if not args.go_off:
        for mod in go_mods:
            results.append(report_go(mod))
    if not args.no_github:
        for repo in gh_repos:
            results.append(report_github_releases(repo))

    if args.json:
        print("\n" + json.dumps(results, indent=2, default=str))
    print(
        "\nReminder: a 'machine-dominated' verdict is the expected baseline for a "
        "young package. Watch for the shape to change — a sustained, weekday-skewed "
        "baseline climbing on the latest version is your first real adopter."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
