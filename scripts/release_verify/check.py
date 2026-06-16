#!/usr/bin/env python3
"""Gate #2: Release round-trip verification.

After a release is published, verify that the public registry resolves the
exact version that was tagged and that it installs in a clean environment.
This closes the gap between "we tagged it" and "consumers can actually
install exactly that version".

Two properties this gate asserts (ADR-0024 D1/D2):

  1. Version identity — `pip install obsigna==X.Y.Z`, `npm install
     @obsigna/sdk-ts@X.Y.Z`, or `go get ...@vX.Y.Z` resolves to exactly
     the tagged version, not a redirect, yank-substitute, or nearest match.

  2. Installability — the artifact is fetchable in a clean environment.

Snippet consistency (documented code compiles against the published
artifact) is a separate property, covered by Gate #1
(`scripts/readme_snippets/check.py --source published`), which runs as its
own job alongside this gate in each release-sdk-*.yml workflow.

Usage:
    check.py --lang {go,ts,py} --version X.Y.Z

Exit codes:
    0  all assertions passed
    1  version mismatch or install/build failure
    2  usage error (missing args, unknown lang)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GO_MODULE = "github.com/agent-receipts/ar/sdk/go"
TS_PACKAGE = "@obsigna/sdk-ts"
PY_PACKAGE = "obsigna"

# How many times to retry a registry fetch before failing. The public
# registries have occasional propagation lag after a new version is pushed;
# retries cover the window between "tag pushed" and "version visible".
REGISTRY_RETRIES = 4


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(
    cmd: list[str],
    cwd: str,
    env: dict[str, str] | None = None,
    retries: int = 0,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    full_env = {**os.environ, **(env or {})}
    for attempt in range(retries + 1):
        print(f"  $ {' '.join(cmd)}  (cwd={cwd})", flush=True)
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=full_env,
            text=True,
            capture_output=capture_output,
        )
        if proc.returncode == 0 or attempt == retries:
            return proc
        wait = 2 ** (attempt + 1)
        print(f"  command failed (rc={proc.returncode}); retrying in {wait}s", flush=True)
        time.sleep(wait)
    return proc


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

_PY_VERSION_RE = re.compile(r"^Version:\s*(.+)$", re.MULTILINE)


def _parse_pip_show_version(output: str) -> str | None:
    """Extract the version string from `pip show` output.

    Returns None if the Version: line is absent (package not installed).
    """
    m = _PY_VERSION_RE.search(output)
    return m.group(1).strip() if m else None


def verify_py(version: str, workdir: str) -> int:
    """Install obsigna==version from PyPI and confirm the resolved version."""
    venv = os.path.join(workdir, "venv")
    if _run([sys.executable, "-m", "venv", venv], cwd=workdir).returncode != 0:
        return 1
    py = os.path.join(venv, "bin", "python")
    pip = [py, "-m", "pip"]

    spec = f"{PY_PACKAGE}=={version}"
    print(f"\n--- Installing {spec} from PyPI")
    if _run([*pip, "install", "--quiet", spec], cwd=workdir, retries=REGISTRY_RETRIES).returncode != 0:
        print(f"ERROR: failed to install {spec} from PyPI")
        return 1

    result = _run([*pip, "show", PY_PACKAGE], cwd=workdir, capture_output=True)
    if result.returncode != 0:
        print(f"ERROR: pip show {PY_PACKAGE} failed")
        return 1

    resolved = _parse_pip_show_version(result.stdout)
    return _assert_version(PY_PACKAGE, version, resolved)


# ---------------------------------------------------------------------------
# TypeScript
# ---------------------------------------------------------------------------


def _parse_npm_list_version(output: str, package: str) -> str | None:
    """Extract the installed version for *package* from `npm list --json` output.

    Returns None if the package is not present in the output.
    """
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return None
    deps = data.get("dependencies", {})
    entry = deps.get(package, {})
    version = entry.get("version")
    return str(version).strip() if version else None


def verify_ts(version: str, workdir: str) -> int:
    """Install @obsigna/sdk-ts@version from npm and confirm the resolved version."""
    package_json = {
        "name": "release-verify",
        "private": True,
        "type": "module",
        "dependencies": {TS_PACKAGE: version},
    }
    with open(os.path.join(workdir, "package.json"), "w", encoding="utf-8") as fh:
        json.dump(package_json, fh, indent=2)

    print(f"\n--- Installing {TS_PACKAGE}@{version} from npm")
    if (
        _run(
            ["npm", "install", "--no-audit", "--no-fund"],
            cwd=workdir,
            retries=REGISTRY_RETRIES,
        ).returncode
        != 0
    ):
        print(f"ERROR: npm install {TS_PACKAGE}@{version} failed")
        return 1

    result = _run(
        ["npm", "list", "--json", TS_PACKAGE],
        cwd=workdir,
        capture_output=True,
    )
    # npm list exits 1 for extraneous packages but still outputs valid JSON;
    # accept any output as long as we can parse the version.
    resolved = _parse_npm_list_version(result.stdout, TS_PACKAGE)
    return _assert_version(TS_PACKAGE, version, resolved)


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

_GO_MOD_VERSION_RE = re.compile(
    r"^" + re.escape(GO_MODULE) + r"\s+v(\S+)",
    re.MULTILINE,
)


def _parse_go_list_version(output: str) -> str | None:
    """Extract the version (without the leading 'v') from `go list -m` output.

    `go list -m` prints lines like:
        github.com/agent-receipts/ar/sdk/go v0.12.0

    Returns the bare semver string (e.g. "0.12.0"), or None if not found.
    """
    m = _GO_MOD_VERSION_RE.search(output)
    return m.group(1) if m else None


def verify_go(version: str, workdir: str) -> int:
    """Fetch github.com/agent-receipts/ar/sdk/go@vVERSION from the Go proxy
    and confirm the resolved version."""
    go_mod = [
        "module example.com/release-verify\n",
        "go 1.26.1\n",
        f"require {GO_MODULE} v{version}\n",
    ]
    with open(os.path.join(workdir, "go.mod"), "w", encoding="utf-8") as fh:
        fh.writelines(go_mod)

    # Minimal main.go so `go mod download` has something to compile against;
    # we only need the module graph to resolve, not to build an actual program.
    with open(os.path.join(workdir, "main.go"), "w", encoding="utf-8") as fh:
        fh.write("package main\n\nfunc main() {}\n")

    # Pin GOPROXY to the public proxy with no `direct` fallback. The default
    # (`https://proxy.golang.org,direct`) lets `go mod download` fetch straight
    # from VCS when the proxy hasn't indexed the tag yet — which would let this
    # gate pass without actually proving the public proxy resolves the release.
    # Gate #2 asserts registry resolution, so the proxy must be the only source.
    env = {
        "GOFLAGS": "-mod=mod",
        "GOWORK": "off",
        "GOPROXY": "https://proxy.golang.org",
    }
    print(f"\n--- Fetching {GO_MODULE}@v{version} from the Go proxy")
    if (
        _run(
            ["go", "mod", "download"],
            cwd=workdir,
            env=env,
            retries=REGISTRY_RETRIES,
        ).returncode
        != 0
    ):
        print(f"ERROR: go mod download for {GO_MODULE}@v{version} failed")
        return 1

    result = _run(
        ["go", "list", "-m", GO_MODULE],
        cwd=workdir,
        env=env,
        capture_output=True,
    )
    if result.returncode != 0:
        print(f"ERROR: go list -m {GO_MODULE} failed")
        return 1

    raw = _parse_go_list_version(result.stdout)
    # Strip the leading 'v' that go list emits (e.g. "v0.12.0" → "0.12.0")
    resolved = raw.lstrip("v") if raw else None
    return _assert_version(GO_MODULE, version, resolved)


# ---------------------------------------------------------------------------
# Version assertion (shared, unit-tested)
# ---------------------------------------------------------------------------


def assert_version(package: str, expected: str, resolved: str | None) -> int:
    """Return 0 if resolved == expected, 1 otherwise.

    This function is the core of the gate and is exercised by the unit tests
    with controlled inputs (no registry calls). All output goes to stdout so
    CI captures it in the job log.
    """
    if resolved is None:
        print(
            f"ERROR: could not determine installed version of {package}; "
            "registry output was unexpected"
        )
        return 1
    if resolved != expected:
        print(
            f"ERROR: version mismatch for {package}\n"
            f"  expected : {expected}\n"
            f"  resolved : {resolved}\n"
            "The registry may have returned a different version than the one just published. "
            "Check for yanked releases, index propagation delays, or a version bump mismatch."
        )
        return 1
    print(f"OK: {package} resolved to {resolved} (matches release tag)")
    return 0


# Module-private alias so internal callers use the public name; tests import
# the public name directly.
_assert_version = assert_version


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_VERIFIERS = {"go": verify_go, "ts": verify_ts, "py": verify_py}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--lang", required=True, choices=["go", "ts", "py"])
    parser.add_argument(
        "--version",
        required=True,
        help="Released version string (no leading 'v'), e.g. 0.12.0 or 0.12.0-alpha.1",
    )
    parser.add_argument(
        "--workdir",
        default=None,
        help="Working directory for the temporary project (default: auto-created tmpdir)",
    )
    args = parser.parse_args(argv)

    # Validate version looks like a bare semver (no leading 'v'); callers
    # pass the raw version, not the tag. We don't reject pre-release suffixes.
    if args.version.startswith("v"):
        parser.error(f"--version must not have a leading 'v' (got {args.version!r})")

    cleanup = False
    if args.workdir:
        workdir = os.path.abspath(args.workdir)
        os.makedirs(workdir, exist_ok=True)
    else:
        workdir = tempfile.mkdtemp(prefix="release-verify-")
        cleanup = True

    print("Gate #2 — release round-trip verification")
    print(f"  lang    : {args.lang}")
    print(f"  version : {args.version}")
    print(f"  workdir : {workdir}")

    try:
        rc = _VERIFIERS[args.lang](args.version, workdir)
    finally:
        if cleanup:
            shutil.rmtree(workdir, ignore_errors=True)

    if rc == 0:
        print(f"\nGate #2 PASSED for {args.lang} {args.version}")
    else:
        print(f"\nGate #2 FAILED for {args.lang} {args.version} (see errors above)")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
