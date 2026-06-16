#!/usr/bin/env python3
"""Gate #8: daemon ↔ SDK protocol compatibility at release time.

ADR-0024 D1 records the property: a release must not ship an SDK/daemon pair
that cannot talk to each other. ADR-0010 (daemon process separation) and
ADR-0022 (daemon-mediated primary deployment) make the daemon the primary path,
so "this SDK works with the daemon" is a compatibility claim the project
asserts — and an asserted property needs a gate.

The protocol surface this gate reads:

- Each SDK declares the inclusive range of emitter-frame schema versions it can
  speak to the daemon — its *declared range* (Go ``emitter.DaemonProtocolMin``/
  ``Max``, TS ``DAEMON_PROTOCOL_RANGE``, Python ``DAEMON_PROTOCOL_RANGE``).
- The daemon declares the inclusive range of frame versions it can interpret —
  its *spoken range* (``obsigna-daemon --protocol-version`` prints
  ``{"frame_version":{"min":N,"max":M}}``).

The gate, against the *published* artifacts:

1. Downloads the released daemon tarball, runs ``--protocol-version`` to read
   the spoken range.
2. Installs the released SDK and runs a tiny driver that prints the declared
   range.
3. Asserts the two ranges intersect (the *static* check). A non-overlapping
   pair turns the release red.
4. Backs the static claim with a *live handshake*: boots the released daemon on
   a throwaway socket/db/key, has the released SDK emit one event, and asserts a
   receipt lands in the store (read back via the daemon's ``agent-receipts list``
   companion). A pair that passes the static check but cannot actually exchange
   a frame still turns the release red.

The pure comparison/parse core (range intersection, semver selection, asset-URL
construction, stdout parsing, receipt counting) takes no network and no
subprocess, so the unit tests exercise it directly; the download/install/boot
drivers are exercised end-to-end by CI at release time.

Usage:
    check.py --sdk-lang {go,ts,py} --sdk-version X.Y.Z|latest
             --daemon-version X.Y.Z|latest
             [--allow-prerelease] [--workdir DIR]

Exit codes:
    0  the SDK's declared range intersects the daemon's spoken range AND the
       live handshake produced a receipt
    1  a download/install/boot/driver step failed, the ranges do not intersect,
       or the handshake produced no receipt
    2  usage error (missing args, unknown lang)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GO_SDK_MODULE = "github.com/agent-receipts/ar/sdk/go"
GO_DAEMON_MODULE = "github.com/agent-receipts/ar/daemon"
TS_PACKAGE = "@obsigna/sdk-ts"
PY_PACKAGE = "obsigna"

REPO = "agent-receipts/obsigna"

# The obsigna GoReleaser archive is named obsigna_<version>_<os>_<arch>.tar.gz
# and uploaded to the GitHub release for the prefixed tag obsigna/v<version>.
# The gate runs on linux/amd64.
DAEMON_ASSET_OS = "linux"
DAEMON_ASSET_ARCH = "amd64"

# Registries occasionally lag a freshly pushed version; retries cover the window
# between "tag pushed" and "version installable".
REGISTRY_RETRIES = 4

# How many pages of the GitHub releases list to scan when resolving the latest
# daemon. This repo cuts releases for several components into one newest-first
# list, so the most recent daemon release can sit below 100 other-component
# releases; scanning a single page would make the gate silently skip. We page
# until daemon releases appear (or this many pages are exhausted) — 10×100 =
# 1000 releases is far more history than "latest daemon" ever needs.
MAX_RELEASE_PAGES = 10

# How long to wait for the booted daemon's socket to appear, and for the emitted
# receipt to land in the store. Generous because CI runners are contended; the
# happy path resolves in well under a second.
SOCKET_WAIT_SECONDS = 15.0
RECEIPT_WAIT_SECONDS = 15.0
_POLL_INTERVAL = 0.1


# ---------------------------------------------------------------------------
# Pure comparison / parse core (shared, unit-tested)
# ---------------------------------------------------------------------------


def ranges_intersect(a: tuple[int, int], b: tuple[int, int]) -> bool:
    """Return True if the inclusive integer ranges *a* and *b* overlap.

    Each range is ``(min, max)`` with ``min <= max``. The intersection is
    non-empty iff ``a.min <= b.max`` and ``b.min <= a.max``.
    """
    a_min, a_max = a
    b_min, b_max = b
    return a_min <= b_max and b_min <= a_max


def parse_spoken_range(stdout: str) -> tuple[int, int]:
    """Pull the daemon's spoken frame-version range out of --protocol-version.

    Expects a line of ``{"frame_version":{"min":N,"max":M}}``. Raises
    ``ValueError`` if no such object is present or it is malformed.
    """
    obj = _last_json_object(stdout)
    fv = obj.get("frame_version")
    if not isinstance(fv, dict):
        raise ValueError(f"daemon --protocol-version output missing frame_version: {obj!r}")
    return _range_from_minmax(fv)


def parse_declared_range(stdout: str) -> tuple[int, int]:
    """Pull an SDK's declared range out of its driver's ``range`` output.

    Expects a line of ``{"min":N,"max":M}``. Raises ``ValueError`` if no such
    object is present or it is malformed.
    """
    return _range_from_minmax(_last_json_object(stdout))


def _range_from_minmax(obj: dict) -> tuple[int, int]:
    try:
        lo = int(obj["min"])
        hi = int(obj["max"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"malformed version range {obj!r}: {exc}") from exc
    if lo > hi:
        raise ValueError(f"inverted version range: min {lo} > max {hi}")
    return lo, hi


def _last_json_object(stdout: str) -> dict:
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError(f"expected a JSON object, got {type(obj).__name__}")
            return obj
    raise ValueError("no JSON object found on stdout")


def count_receipts(list_json_stdout: str) -> int:
    """Return the number of receipts in ``agent-receipts list --json`` output.

    The companion CLI prints a JSON array (``[]`` when empty). Anything that is
    not a JSON array is treated as zero receipts so a transient CLI hiccup reads
    as "not yet landed" rather than crashing the poll loop.
    """
    stripped = list_json_stdout.strip()
    if not stripped:
        return 0
    try:
        arr = json.loads(stripped)
    except json.JSONDecodeError:
        return 0
    return len(arr) if isinstance(arr, list) else 0


def daemon_asset_url(version: str) -> str:
    """Build the GitHub release download URL for the obsigna tarball.

    ``version`` carries no leading ``v``; the tag is ``obsigna/v<version>`` and
    the asset is ``obsigna_<version>_<os>_<arch>.tar.gz``.
    """
    asset = f"obsigna_{version}_{DAEMON_ASSET_OS}_{DAEMON_ASSET_ARCH}.tar.gz"
    # The tag's slash is percent-encoded in the download path.
    return f"https://github.com/{REPO}/releases/download/obsigna%2Fv{version}/{asset}"


class NoStableReleaseError(Exception):
    """No version satisfying the stable/prerelease filter exists among candidates.

    Distinct from a malformed-tag parse error: this is the legitimate "nothing
    to pick" outcome (e.g. only pre-releases exist and they are excluded), which
    callers translate into a skip. A version string that is not dotted-numeric
    semver is *not* this — such tags are ignored individually rather than
    collapsing the whole selection.
    """


def _prerelease_id_key(ident: str) -> tuple:
    """Per-identifier precedence key for a prerelease dot-identifier (SemVer §11).

    Numeric identifiers compare numerically and rank below alphanumeric ones;
    alphanumeric identifiers compare in ASCII order. The leading 0/1 flag keeps
    int and str out of the same comparison slot (Python can't order them).
    """
    if ident.isdigit():
        return (0, int(ident), "")
    return (1, 0, ident)


def _semver_key(version: str) -> tuple:
    """Sort key for an X.Y.Z[-prerelease][+build] version (SemVer precedence).

    A release sorts above any prerelease of the same core (the ``(1,)`` vs
    ``(0, ...)`` tail). Prerelease identifiers are compared per SemVer §11 — so
    ``alpha.2`` sorts *below* ``alpha.10`` (numeric identifiers compared
    numerically, not lexically). Build metadata is ignored (SemVer §10). Raises
    ``ValueError`` if the core is not dotted integers.
    """
    core = version.partition("-")[0].partition("+")[0]
    nums = tuple(int(p) for p in core.split("."))
    pre = version.partition("-")[2].partition("+")[0]
    if not pre:
        return (nums, (1,))
    return (nums, (0,) + tuple(_prerelease_id_key(p) for p in pre.split(".")))


def is_prerelease(version: str) -> bool:
    return "-" in version


def pick_latest(versions: list[str], allow_prerelease: bool) -> str:
    """Return the newest version, excluding prereleases unless allowed.

    A candidate whose string is not dotted-numeric semver is skipped
    individually (so one stray tag like ``vnightly`` cannot break or silently
    disarm resolution). Raises ``NoStableReleaseError`` if no parseable version
    remains after filtering.
    """
    keyed: list[tuple[tuple, str]] = []
    for v in versions:
        if not allow_prerelease and is_prerelease(v):
            continue
        try:
            keyed.append((_semver_key(v), v))
        except ValueError:
            continue  # not dotted-numeric semver — ignore this tag, keep the rest
    if not keyed:
        raise NoStableReleaseError(
            f"no {'' if allow_prerelease else 'stable '}semver version among {versions!r}"
        )
    return max(keyed, key=lambda kv: kv[0])[1]


# ---------------------------------------------------------------------------
# Subprocess / network helpers
# ---------------------------------------------------------------------------


def _run(
    cmd: list[str],
    cwd: str,
    env: dict[str, str] | None = None,
    retries: int = 0,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    full_env = {**os.environ, **(env or {})}
    proc: subprocess.CompletedProcess[str] | None = None
    for attempt in range(retries + 1):
        print(f"  $ {' '.join(cmd)}  (cwd={cwd})", flush=True)
        proc = subprocess.run(
            cmd, cwd=cwd, env=full_env, text=True, capture_output=capture_output
        )
        if proc.returncode == 0 or attempt == retries:
            return proc
        wait = 2 ** (attempt + 1)
        print(f"  command failed (rc={proc.returncode}); retrying in {wait}s", flush=True)
        time.sleep(wait)
    assert proc is not None
    return proc


class NoReleaseError(Exception):
    """Raised when a `latest` counterpart has never been released.

    Distinct from a network/HTTP failure: a release whose counterpart does not
    exist yet (e.g. the first SDK release before any daemon ships) has no pair
    to be incompatible with, so the gate skips rather than failing. A transient
    network error is *not* this — it propagates and fails the gate, because
    skipping on a fetch error would silently disarm the gate.
    """


def _http_json(url: str) -> dict | list:
    req = urllib.request.Request(url, headers={"User-Agent": "ar-gate8"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (trusted hosts)
        return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# Version resolution ("latest")
# ---------------------------------------------------------------------------


def resolve_latest_daemon(allow_prerelease: bool) -> str:
    """Newest released daemon version (no leading v) from the GitHub releases.

    Pages the newest-first releases list until ``obsigna/v*`` tags satisfying the
    stable/prerelease filter appear (or ``MAX_RELEASE_PAGES`` are exhausted), so
    the most recent daemon release is found even when many other-component
    releases sit above it. Raises ``NoReleaseError`` if no such release exists
    (so the gate skips rather than blocking a release with no daemon to pair
    against). A network/HTTP error from the fetch is NOT caught here — it
    propagates and fails the gate, rather than masquerading as "no release".
    """
    versions: list[str] = []
    for page in range(1, MAX_RELEASE_PAGES + 1):
        batch = _http_json(
            f"https://api.github.com/repos/{REPO}/releases?per_page=100&page={page}"
        )
        if not isinstance(batch, list) or not batch:
            break  # ran off the end of the releases list
        for rel in batch:
            tag = rel.get("tag_name", "")
            if tag.startswith("obsigna/v"):
                versions.append(tag[len("obsigna/v") :])
        # Releases are newest-first, so once a daemon version matching the filter
        # has appeared we have the most recent ones — stop rather than page
        # through the entire release history of every other component.
        if any(allow_prerelease or not is_prerelease(v) for v in versions):
            break
    if not versions:
        raise NoReleaseError("no obsigna/v* release found in recent releases")
    try:
        return pick_latest(versions, allow_prerelease)
    except NoStableReleaseError as exc:  # only pre-releases exist, excluded
        raise NoReleaseError(str(exc)) from exc


def resolve_latest_sdk(lang: str) -> str:
    """Newest released version of the given SDK (no leading v) from its registry.

    Raises ``NoReleaseError`` if the registry reports the package does not exist
    (HTTP 404) — the SDK has never been published, so there is no pair to check.
    """
    try:
        if lang == "go":
            info = _http_json(f"https://proxy.golang.org/{GO_SDK_MODULE}/@latest")
            return str(info["Version"]).lstrip("v")  # type: ignore[index]
        if lang == "ts":
            doc = _http_json(f"https://registry.npmjs.org/{TS_PACKAGE}")
            return str(doc["dist-tags"]["latest"])  # type: ignore[index]
        if lang == "py":
            doc = _http_json(f"https://pypi.org/pypi/{PY_PACKAGE}/json")
            return str(doc["info"]["version"])  # type: ignore[index]
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            raise NoReleaseError(f"{lang} SDK has never been published ({exc.code})") from exc
        raise
    raise ValueError(f"unknown lang {lang!r}")


def _resolve(value: str, lang: str, allow_prerelease: bool, *, is_daemon: bool) -> str:
    if value != "latest":
        return value.lstrip("v")
    if is_daemon:
        return resolve_latest_daemon(allow_prerelease)
    return resolve_latest_sdk(lang)


# ---------------------------------------------------------------------------
# Daemon: download the released tarball and read its spoken range
# ---------------------------------------------------------------------------


class DaemonBinaries:
    """Paths to the two binaries unpacked from the daemon release tarball."""

    def __init__(self, daemon: str, cli: str) -> None:
        self.daemon = daemon
        self.cli = cli


def download_daemon(version: str, workdir: str) -> DaemonBinaries:
    """Fetch + extract the released daemon tarball; return the binary paths."""
    url = daemon_asset_url(version)
    tarball = os.path.join(workdir, "daemon.tar.gz")
    print(f"\n--- Downloading the released daemon\n    {url}")
    for attempt in range(REGISTRY_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ar-gate8"})
            with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
                with open(tarball, "wb") as fh:
                    shutil.copyfileobj(resp, fh)
            break
        except urllib.error.URLError as exc:
            if attempt == REGISTRY_RETRIES:
                raise RuntimeError(f"failed to download {url}: {exc}") from exc
            wait = 2 ** (attempt + 1)
            print(f"  download failed ({exc}); retrying in {wait}s", flush=True)
            time.sleep(wait)
    extract_dir = os.path.join(workdir, "daemon-bin")
    os.makedirs(extract_dir, exist_ok=True)
    with tarfile.open(tarball) as tf:
        _safe_extract(tf, extract_dir)
    daemon_bin = os.path.join(extract_dir, "obsigna-daemon")
    # The CLI stays the agent-receipts deprecation shim, which forwards each
    # legacy subcommand (verify/show/list/verify-event/doctor) to its obsigna
    # equivalent — this gate uses `list`. Both binaries ship in the same archive.
    cli_bin = os.path.join(extract_dir, "agent-receipts")
    for path in (daemon_bin, cli_bin):
        if not os.path.exists(path):
            raise RuntimeError(f"expected binary not found in tarball: {path}")
        os.chmod(path, 0o755)
    return DaemonBinaries(daemon_bin, cli_bin)


def _safe_extract(tf: tarfile.TarFile, dest: str) -> None:
    """Extract guarding against path traversal (the tarball is trusted, but a
    defensive extract is cheap and keeps the gate honest)."""
    dest_abs = os.path.abspath(dest)
    for member in tf.getmembers():
        target = os.path.abspath(os.path.join(dest, member.name))
        if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
            raise RuntimeError(f"tar member escapes extract dir: {member.name}")
    tf.extractall(dest)  # noqa: S202 (members validated above)


def read_spoken_range(bins: DaemonBinaries, workdir: str) -> tuple[int, int]:
    print("\n--- Reading the daemon's spoken protocol range")
    result = _run([bins.daemon, "--protocol-version"], cwd=workdir, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"daemon --protocol-version failed:\n{result.stderr}")
    return parse_spoken_range(result.stdout)


# ---------------------------------------------------------------------------
# SDK drivers: print declared range, and emit one event in the live handshake
# ---------------------------------------------------------------------------

_GO_DRIVER = """\
package main

import (
\t"context"
\t"encoding/json"
\t"fmt"
\t"os"

\t"github.com/agent-receipts/ar/sdk/go/emitter"
)

func fail(err error) {
\tfmt.Fprintln(os.Stderr, err)
\tos.Exit(1)
}

func main() {
\tif len(os.Args) < 2 {
\t\tfmt.Fprintln(os.Stderr, "usage: driver range|emit <socket>")
\t\tos.Exit(2)
\t}
\tswitch os.Args[1] {
\tcase "range":
\t\tout, _ := json.Marshal(map[string]int{"min": emitter.DaemonProtocolMin, "max": emitter.DaemonProtocolMax})
\t\tfmt.Println(string(out))
\tcase "emit":
\t\te, err := emitter.NewDaemon(emitter.WithSocketPath(os.Args[2]))
\t\tif err != nil {
\t\t\tfail(err)
\t\t}
\t\tdefer e.Close()
\t\tif err := e.Emit(context.Background(), emitter.Event{
\t\t\tChannel:  "gate8",
\t\t\tTool:     emitter.Tool{Name: "handshake"},
\t\t\tDecision: "allowed",
\t\t\tInput:    json.RawMessage(`{"probe":true}`),
\t\t}); err != nil {
\t\t\tfail(err)
\t\t}
\tdefault:
\t\tos.Exit(2)
\t}
}
"""

_TS_DRIVER = """\
import { DAEMON_PROTOCOL_RANGE, DaemonEmitter } from "@obsigna/sdk-ts";

const mode = process.argv[2];
if (mode === "range") {
  console.log(
    JSON.stringify({ min: DAEMON_PROTOCOL_RANGE.min, max: DAEMON_PROTOCOL_RANGE.max }),
  );
} else if (mode === "emit") {
  const emitter = new DaemonEmitter({ socketPath: process.argv[3] });
  const err = await emitter.emit({
    channel: "gate8",
    tool: { name: "handshake" },
    decision: "allowed",
    input: '{"probe":true}',
  });
  emitter.close();
  if (err) {
    console.error(err);
    process.exit(1);
  }
} else {
  process.exit(2);
}
"""

_PY_DRIVER = """\
import json
import sys

from obsigna import DAEMON_PROTOCOL_RANGE, DaemonEmitter

mode = sys.argv[1]
if mode == "range":
    print(json.dumps({"min": DAEMON_PROTOCOL_RANGE.min, "max": DAEMON_PROTOCOL_RANGE.max}))
elif mode == "emit":
    emitter = DaemonEmitter(socket_path=sys.argv[2])
    try:
        emitter.emit(
            channel="gate8",
            tool_name="handshake",
            decision="allowed",
            input='{"probe":true}',
        )
    finally:
        emitter.close()
else:
    sys.exit(2)
"""


class SDKDriver:
    """An installed published SDK plus a way to run its range/emit driver."""

    def __init__(self, run_driver) -> None:
        self._run_driver = run_driver

    def declared_range(self) -> tuple[int, int]:
        result = self._run_driver(["range"])
        if result.returncode != 0:
            raise RuntimeError(f"SDK range driver failed:\n{result.stderr}")
        return parse_declared_range(result.stdout)

    def emit(self, socket_path: str) -> None:
        result = self._run_driver(["emit", socket_path])
        if result.returncode != 0:
            raise RuntimeError(f"SDK emit driver failed:\n{result.stderr}")


def install_go_sdk(version: str, workdir: str) -> SDKDriver:
    proj = os.path.join(workdir, "go-sdk")
    os.makedirs(proj, exist_ok=True)
    with open(os.path.join(proj, "go.mod"), "w", encoding="utf-8") as fh:
        fh.writelines(
            [
                "module example.com/gate8\n",
                "go 1.26.1\n",
                f"require {GO_SDK_MODULE} v{version}\n",
            ]
        )
    with open(os.path.join(proj, "main.go"), "w", encoding="utf-8") as fh:
        fh.write(_GO_DRIVER)
    env = {"GOFLAGS": "-mod=mod", "GOWORK": "off", "GOPROXY": "https://proxy.golang.org"}
    print(f"\n--- Fetching {GO_SDK_MODULE}@v{version}")
    if _run(["go", "mod", "tidy"], cwd=proj, env=env, retries=REGISTRY_RETRIES).returncode != 0:
        raise RuntimeError(f"go mod tidy for {GO_SDK_MODULE}@v{version} failed")
    # Pre-build so the emit path is not paying a compile under the socket
    # timeout; `go run` would otherwise compile on first invocation.
    if _run(["go", "build", "-o", "driver", "."], cwd=proj, env=env).returncode != 0:
        raise RuntimeError("building the Go SDK driver failed")
    driver = os.path.join(proj, "driver")

    def run_driver(args: list[str]) -> subprocess.CompletedProcess[str]:
        return _run([driver, *args], cwd=proj, env=env, capture_output=True)

    return SDKDriver(run_driver)


def install_ts_sdk(version: str, workdir: str) -> SDKDriver:
    proj = os.path.join(workdir, "ts-sdk")
    os.makedirs(proj, exist_ok=True)
    package_json = {
        "name": "gate8",
        "private": True,
        "type": "module",
        "dependencies": {TS_PACKAGE: version},
    }
    with open(os.path.join(proj, "package.json"), "w", encoding="utf-8") as fh:
        json.dump(package_json, fh, indent=2)
    with open(os.path.join(proj, "driver.ts"), "w", encoding="utf-8") as fh:
        fh.write(_TS_DRIVER)
    print(f"\n--- Installing {TS_PACKAGE}@{version} from npm")
    if _run(["npm", "install", "--no-audit", "--no-fund"], cwd=proj, retries=REGISTRY_RETRIES).returncode != 0:
        raise RuntimeError(f"npm install {TS_PACKAGE}@{version} failed")

    def run_driver(args: list[str]) -> subprocess.CompletedProcess[str]:
        return _run(
            ["node", "--experimental-strip-types", "driver.ts", *args],
            cwd=proj,
            env={"NODE_NO_WARNINGS": "1"},
            capture_output=True,
        )

    return SDKDriver(run_driver)


def install_py_sdk(version: str, workdir: str) -> SDKDriver:
    proj = os.path.join(workdir, "py-sdk")
    os.makedirs(proj, exist_ok=True)
    venv = os.path.join(proj, "venv")
    if _run([sys.executable, "-m", "venv", venv], cwd=proj).returncode != 0:
        raise RuntimeError("creating the Python venv failed")
    py = os.path.join(venv, "bin", "python")
    spec = f"{PY_PACKAGE}=={version}"
    print(f"\n--- Installing {spec} from PyPI")
    if _run([py, "-m", "pip", "install", "--quiet", spec], cwd=proj, retries=REGISTRY_RETRIES).returncode != 0:
        raise RuntimeError(f"failed to install {spec} from PyPI")
    with open(os.path.join(proj, "driver.py"), "w", encoding="utf-8") as fh:
        fh.write(_PY_DRIVER)

    def run_driver(args: list[str]) -> subprocess.CompletedProcess[str]:
        return _run([py, "driver.py", *args], cwd=proj, capture_output=True)

    return SDKDriver(run_driver)


_INSTALLERS = {"go": install_go_sdk, "ts": install_ts_sdk, "py": install_py_sdk}


# ---------------------------------------------------------------------------
# Live handshake: boot the daemon, emit from the SDK, assert a receipt lands
# ---------------------------------------------------------------------------


def _wait_for(predicate, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(_POLL_INTERVAL)
    return predicate()


def live_handshake(bins: DaemonBinaries, sdk: SDKDriver, workdir: str) -> bool:
    """Boot the daemon, emit one event from the SDK, assert a receipt lands."""
    run_dir = os.path.join(workdir, "handshake")
    os.makedirs(run_dir, exist_ok=True)
    socket_path = os.path.join(run_dir, "events.sock")
    db_path = os.path.join(run_dir, "receipts.db")
    key_path = os.path.join(run_dir, "signing.key")
    log_path = os.path.join(run_dir, "daemon.log")

    print("\n--- Live handshake: generating the daemon signing key")
    init = _run([bins.daemon, "--init", "--key", key_path], cwd=run_dir, capture_output=True)
    if init.returncode != 0:
        print(f"ERROR: daemon --init failed:\n{init.stderr}")
        return False

    print("--- Live handshake: booting the released daemon")
    log = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [
            bins.daemon,
            "--socket", socket_path,
            "--db", db_path,
            "--key", key_path,
            # A throwaway tmpdir socket is outside the per-platform safe set;
            # opt in deliberately for the test rather than write under the
            # operator's real runtime dir.
            "--unsafe-socket-path",
        ],
        cwd=run_dir,
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        if not _wait_for(lambda: os.path.exists(socket_path), SOCKET_WAIT_SECONDS):
            print(f"ERROR: daemon socket never appeared at {socket_path}")
            _dump_log(log_path)
            return False

        print("--- Live handshake: emitting one event from the published SDK")
        sdk.emit(socket_path)

        def landed() -> bool:
            result = _run(
                [bins.cli, "list", "--json", "--db", db_path],
                cwd=run_dir,
                capture_output=True,
            )
            return result.returncode == 0 and count_receipts(result.stdout) >= 1

        if not _wait_for(landed, RECEIPT_WAIT_SECONDS):
            print("ERROR: no receipt landed in the store after emit")
            _dump_log(log_path)
            return False

        print("OK: the released SDK emitted a frame the released daemon turned into a receipt")
        return True
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


def _dump_log(log_path: str) -> None:
    try:
        with open(log_path, encoding="utf-8") as fh:
            content = fh.read()
    except OSError:
        return
    if content.strip():
        print("  daemon log:")
        for line in content.splitlines():
            print(f"    {line}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_gate(
    lang: str,
    sdk_version: str,
    daemon_version: str,
    workdir: str,
) -> int:
    bins = download_daemon(daemon_version, workdir)
    spoken = read_spoken_range(bins, workdir)
    print(f"  daemon {daemon_version} spoken range: [{spoken[0]}, {spoken[1]}]")

    sdk = _INSTALLERS[lang](sdk_version, workdir)
    declared = sdk.declared_range()
    print(f"  {lang} SDK {sdk_version} declared range: [{declared[0]}, {declared[1]}]")

    if not ranges_intersect(declared, spoken):
        print(
            f"\nERROR: the {lang} SDK {sdk_version} declared range "
            f"[{declared[0]}, {declared[1]}] does not intersect the daemon "
            f"{daemon_version} spoken range [{spoken[0]}, {spoken[1]}]; this "
            "pair cannot exchange frames"
        )
        return 1
    print(
        f"\nOK: declared range [{declared[0]}, {declared[1]}] intersects spoken "
        f"range [{spoken[0]}, {spoken[1]}]"
    )

    if not live_handshake(bins, sdk, workdir):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--sdk-lang", required=True, choices=["go", "ts", "py"])
    parser.add_argument(
        "--sdk-version",
        required=True,
        help="Released SDK version (no leading 'v'), or 'latest' to resolve from the registry",
    )
    parser.add_argument(
        "--daemon-version",
        required=True,
        help="Released daemon version (no leading 'v'), or 'latest' to resolve from GitHub releases",
    )
    parser.add_argument(
        "--allow-prerelease",
        action="store_true",
        help="When resolving 'latest', consider pre-release versions too",
    )
    parser.add_argument("--workdir", default=None)
    args = parser.parse_args(argv)

    try:
        sdk_version = _resolve(args.sdk_version, args.sdk_lang, args.allow_prerelease, is_daemon=False)
        daemon_version = _resolve(args.daemon_version, args.sdk_lang, args.allow_prerelease, is_daemon=True)
    except NoReleaseError as exc:
        # No counterpart to pair against yet (e.g. the first SDK release before
        # any daemon ships). Nothing can be incompatible, so skip rather than
        # block the release. A network failure during resolution is a different
        # exception and is NOT caught here — it fails the gate.
        print(f"Gate #8 SKIPPED: {exc}; nothing to pair against")
        return 0

    cleanup = False
    if args.workdir:
        workdir = os.path.abspath(args.workdir)
        os.makedirs(workdir, exist_ok=True)
    else:
        workdir = tempfile.mkdtemp(prefix="gate8-")
        cleanup = True

    print("Gate #8 — daemon ↔ SDK protocol compatibility")
    print(f"  sdk     : {args.sdk_lang} {sdk_version}")
    print(f"  daemon  : {daemon_version}")
    print(f"  workdir : {workdir}")

    try:
        rc = run_gate(args.sdk_lang, sdk_version, daemon_version, workdir)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"\nERROR: {exc}")
        rc = 1
    finally:
        if cleanup:
            shutil.rmtree(workdir, ignore_errors=True)

    if rc == 0:
        print(f"\nGate #8 PASSED for {args.sdk_lang} {sdk_version} ↔ daemon {daemon_version}")
    else:
        print(f"\nGate #8 FAILED for {args.sdk_lang} {sdk_version} ↔ daemon {daemon_version} (see errors above)")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
