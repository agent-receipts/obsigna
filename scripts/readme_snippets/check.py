#!/usr/bin/env python3
"""Compile / type-check the SDK code snippets embedded in the user-facing READMEs.

Three failure classes this guards against, all of which have shipped before
(see #593, #594): a snippet calls an API that never existed, imports a wrong
module path, or drifts behind a published rename.

Usage:
    check.py --lang {go,ts,py} --source {local,published} [--mode {typecheck,run}]
             [--version X.Y.Z] [--repo-root .] [--workdir DIR]
             README.md [more/README.md ...]

Source modes:
    local      Build snippets against the in-tree SDK. Used on PRs so a snippet
               and the API it documents are verified against the same commit
               (and new, unreleased APIs are allowed).
    published  Build against the released artifact at --version (default: read
               from the manifest). Used at release time to catch a README that
               has drifted from what users will actually `pip install` /
               `npm install` / `go get`.

Check modes:
    typecheck  (default) Compile (Go) / type-check (TS `tsc --noEmit`, Py mypy)
               every SDK snippet without executing it. Catches API drift.
    run        Execute every runnable SDK snippet in an isolated tmpdir and
               assert it exits 0 (verification-gate #1 / ADR-0024). Snippets
               that can't run hermetically (daemon, network, AWS, a writable
               system path) carry a `<!-- snippet-check: no-run -->` directive
               and are skipped here while remaining covered by typecheck mode.

Only the extraction/assembly logic is unit tested (see test_extract.py); this
module is the IO + subprocess driver and is exercised end-to-end by CI.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import extract  # noqa: E402

GO_MODULE = "github.com/agent-receipts/ar/sdk/go"
TS_PACKAGE = "@obsigna/sdk-ts"
PY_PACKAGE = "obsigna"
MYPY_VERSION = "mypy==2.1.0"


def _run(cmd: list[str], cwd: str, env: dict[str, str] | None = None, retries: int = 0) -> int:
    full_env = {**os.environ, **(env or {})}
    for attempt in range(retries + 1):
        print(f"  $ {' '.join(cmd)}  (cwd={cwd})", flush=True)
        proc = subprocess.run(cmd, cwd=cwd, env=full_env)
        if proc.returncode == 0 or attempt == retries:
            return proc.returncode
        wait = 2 ** (attempt + 1)
        print(f"  command failed (rc={proc.returncode}); retrying in {wait}s", flush=True)
        time.sleep(wait)
    return proc.returncode


def _collect_units(readmes: list[str], lang: str, mode: str = "typecheck") -> list[extract.Unit]:
    units: list[extract.Unit] = []
    for path in readmes:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        found = extract.build_units(path, text, lang, mode=mode)
        units.extend(found)
        print(f"  {path}: {len(found)} {lang} unit(s)")
    return units


# Written into every run dir so snippets that read a taxonomy config from the
# working directory (`load_taxonomy_config` / `loadTaxonomyConfig`) resolve it.
# The mapping matches what the READMEs claim classify returns for "read_file".
_TAXONOMY_FIXTURE = json.dumps(
    {"mappings": [{"tool_name": "read_file", "action_type": "filesystem.file.read"}]},
    indent=2,
)


def _runnable(units: list[extract.Unit], lang: str) -> list[extract.Unit]:
    """Filter to executable units, reporting any skipped via the no-run opt-out."""
    runnable = [u for u in units if u.run]
    skipped = [u for u in units if not u.run]
    for u in skipped:
        print(f"  skipping (no-run): {', '.join(u.sources)}")
    if not runnable:
        print(f"  no runnable {lang} units")
    return runnable


def _prepare_run_dir(workdir: str, n: int, filename: str, unit: extract.Unit) -> str:
    """Create an isolated per-snippet run dir holding the snippet + fixtures."""
    run_dir = os.path.join(workdir, f"run_{n:03d}")
    os.makedirs(run_dir, exist_ok=True)
    _write_unit(run_dir, filename, unit)
    with open(os.path.join(run_dir, "taxonomy.json"), "w", encoding="utf-8") as fh:
        fh.write(_TAXONOMY_FIXTURE)
    return run_dir


def _summarize_run(failures: list[extract.Unit], runnable: list[extract.Unit], label: str) -> int:
    if failures:
        print(f"\n{len(failures)} of {len(runnable)} {label} snippet(s) failed to run:")
        for u in failures:
            print(f"  - {', '.join(u.sources)}")
        return 1
    print(f"\nAll {len(runnable)} {label} snippet(s) ran and exited 0.")
    return 0


# --------------------------------------------------------------------------- #
# Version resolution
# --------------------------------------------------------------------------- #


def _resolve_version(lang: str, repo_root: str, override: str | None) -> str:
    if override:
        return override
    if lang == "ts":
        with open(os.path.join(repo_root, "sdk/ts/package.json"), encoding="utf-8") as fh:
            return json.load(fh)["version"]
    if lang == "py":
        import re

        with open(os.path.join(repo_root, "sdk/py/pyproject.toml"), encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r'\s*version\s*=\s*"([^"]+)"', line)
                if m:
                    return m.group(1)
        raise SystemExit("could not read version from sdk/py/pyproject.toml")
    raise SystemExit(
        "--version is required for Go published-mode checks (read it from the release tag)"
    )


# --------------------------------------------------------------------------- #
# Go
# --------------------------------------------------------------------------- #


_GO_ENV = {"GOFLAGS": "-mod=mod", "GOWORK": "off"}


def _go_noncanonical_guard(units: list[extract.Unit]) -> bool:
    """Print and flag any non-canonical SDK import path. Returns True if found."""
    found = False
    for unit in units:
        for path in extract.go_noncanonical_imports(unit.code):
            found = True
            print(
                f"  non-canonical SDK import {path!r} ({', '.join(unit.sources)}); "
                f"use {GO_MODULE}"
            )
    return found


def _write_go_mod(source: str, version: str | None, repo_root: str, workdir: str) -> int:
    """Write a throwaway go.mod for the snippet module; return the retry budget."""
    go_mod = ["module example.com/readme-snippets\n", "go 1.26.1\n"]
    if source == "local":
        sdk_path = os.path.join(repo_root, "sdk", "go")
        # Throwaway module — a local replace here is fine and never published
        # (publish-go.yml only rejects replaces in the SDK's own go.mod).
        go_mod.append(f"require {GO_MODULE} v0.0.0\n")
        go_mod.append(f"replace {GO_MODULE} => {sdk_path}\n")
    else:
        go_mod.append(f"require {GO_MODULE} v{version}\n")
    with open(os.path.join(workdir, "go.mod"), "w", encoding="utf-8") as fh:
        fh.writelines(go_mod)
    return 4 if source == "published" else 0


def check_go(units: list[extract.Unit], source: str, version: str | None, repo_root: str, workdir: str) -> int:
    if not units:
        print("  no Go units to check")
        return 0

    if _go_noncanonical_guard(units):
        return 1

    network_retries = _write_go_mod(source, version, repo_root, workdir)

    for n, unit in enumerate(units, start=1):
        pkg_dir = os.path.join(workdir, f"snippet_{n:03d}")
        os.makedirs(pkg_dir, exist_ok=True)
        _write_unit(pkg_dir, "main.go", unit)

    if _run(["go", "mod", "tidy"], cwd=workdir, env=_GO_ENV, retries=network_retries) != 0:
        return 1
    return _run(["go", "build", "./..."], cwd=workdir, env=_GO_ENV)


def run_go(units: list[extract.Unit], source: str, version: str | None, repo_root: str, workdir: str) -> int:
    runnable = _runnable(units, "Go")
    if not runnable:
        return 0

    if _go_noncanonical_guard(runnable):
        return 1

    network_retries = _write_go_mod(source, version, repo_root, workdir)

    # build_units(mode="run") rendered each unit as an executable `package main`.
    run_dirs = [
        _prepare_run_dir(workdir, n, "main.go", unit) for n, unit in enumerate(runnable, start=1)
    ]

    if _run(["go", "mod", "tidy"], cwd=workdir, env=_GO_ENV, retries=network_retries) != 0:
        return 1

    failures: list[extract.Unit] = []
    for unit, run_dir in zip(runnable, run_dirs, strict=True):
        if _run(["go", "run", "."], cwd=run_dir, env=_GO_ENV) != 0:
            failures.append(unit)
    return _summarize_run(failures, runnable, "Go")


# --------------------------------------------------------------------------- #
# TypeScript
# --------------------------------------------------------------------------- #


def _exact_version(spec: str) -> str:
    """Strip a leading ^ / ~ range so the temp project pins an exact version."""
    spec = spec.strip()
    return spec[1:] if spec[:1] in "^~" else spec


def _read_ts_dev_deps(repo_root: str) -> dict[str, str]:
    try:
        with open(os.path.join(repo_root, "sdk/ts/package.json"), encoding="utf-8") as fh:
            return json.load(fh).get("devDependencies", {})
    except (OSError, ValueError):
        return {}


def _ts_dep_spec(source: str, version: str | None, repo_root: str) -> str:
    """The `@obsigna/sdk-ts` dependency spec: in-tree file: install or version."""
    if source == "local":
        return f"file:{os.path.join(repo_root, 'sdk', 'ts')}"
    return version or ""


def check_ts(units: list[extract.Unit], source: str, version: str | None, repo_root: str, workdir: str) -> int:
    if not units:
        print("  no TypeScript units to check")
        return 0

    dep = _ts_dep_spec(source, version, repo_root)

    # Type-check with the same typescript / @types/node the SDK is built with,
    # so the gate matches the published .d.ts (newer TS type features included)
    # instead of an arbitrary major. Pin to exact versions (strip the ^/~ range)
    # so resolution is deterministic and doesn't drift with registry state.
    sdk_dev = _read_ts_dev_deps(repo_root)
    package_json = {
        "name": "readme-snippets",
        "private": True,
        "type": "module",
        "dependencies": {TS_PACKAGE: dep},
        "devDependencies": {
            "typescript": _exact_version(sdk_dev.get("typescript", "5")),
            "@types/node": _exact_version(sdk_dev.get("@types/node", "22")),
        },
    }
    with open(os.path.join(workdir, "package.json"), "w", encoding="utf-8") as fh:
        json.dump(package_json, fh, indent=2)

    tsconfig = {
        "compilerOptions": {
            "module": "nodenext",
            "moduleResolution": "nodenext",
            "target": "esnext",
            "lib": ["esnext"],
            "types": ["node"],
            "strict": True,
            "noEmit": True,
            "skipLibCheck": True,
        },
        "include": ["snippets/*.ts"],
    }
    with open(os.path.join(workdir, "tsconfig.json"), "w", encoding="utf-8") as fh:
        json.dump(tsconfig, fh, indent=2)

    snip_dir = os.path.join(workdir, "snippets")
    os.makedirs(snip_dir, exist_ok=True)
    for n, unit in enumerate(units, start=1):
        _write_unit(snip_dir, f"snippet_{n:03d}.ts", unit)

    retries = 4 if source == "published" else 0
    if _run(["npm", "install", "--no-audit", "--no-fund"], cwd=workdir, retries=retries) != 0:
        return 1
    return _run(["npx", "--no-install", "tsc", "--noEmit"], cwd=workdir)


# Node executes the .ts directly via type stripping (Node 22.18+) rather than a
# separate compile step; `node:sqlite` (used by the store snippets) is still
# behind --experimental-sqlite on Node 22.
_NODE_RUN_FLAGS = ["--experimental-strip-types", "--experimental-sqlite"]


def run_ts(units: list[extract.Unit], source: str, version: str | None, repo_root: str, workdir: str) -> int:
    runnable = _runnable(units, "TypeScript")
    if not runnable:
        return 0

    package_json = {
        "name": "readme-snippets-run",
        "private": True,
        "type": "module",
        "dependencies": {TS_PACKAGE: _ts_dep_spec(source, version, repo_root)},
    }
    with open(os.path.join(workdir, "package.json"), "w", encoding="utf-8") as fh:
        json.dump(package_json, fh, indent=2)

    retries = 4 if source == "published" else 0
    if _run(["npm", "install", "--no-audit", "--no-fund"], cwd=workdir, retries=retries) != 0:
        return 1

    failures: list[extract.Unit] = []
    for n, unit in enumerate(runnable, start=1):
        run_dir = _prepare_run_dir(workdir, n, "snippet.ts", unit)
        if _run(["node", *_NODE_RUN_FLAGS, "snippet.ts"], cwd=run_dir, env={"NODE_NO_WARNINGS": "1"}) != 0:
            failures.append(unit)
    return _summarize_run(failures, runnable, "TypeScript")


# --------------------------------------------------------------------------- #
# Python
# --------------------------------------------------------------------------- #


def _make_venv(workdir: str) -> str | None:
    """Create a venv under workdir; return the interpreter path or None on error."""
    venv = os.path.join(workdir, "venv")
    if _run([sys.executable, "-m", "venv", venv], cwd=workdir) != 0:
        return None
    return os.path.join(venv, "bin", "python")


def _pip_install_sdk(py: str, source: str, version: str | None, repo_root: str, workdir: str) -> int:
    if source == "local":
        target = os.path.join(repo_root, "sdk", "py")
        retries = 0
    else:
        target = f"{PY_PACKAGE}=={version}"
        retries = 4
    return _run([py, "-m", "pip", "install", "--quiet", target], cwd=workdir, retries=retries)


def check_py(units: list[extract.Unit], source: str, version: str | None, repo_root: str, workdir: str) -> int:
    if not units:
        print("  no Python units to check")
        return 0

    snip_dir = os.path.join(workdir, "snippets")
    os.makedirs(snip_dir, exist_ok=True)
    files = []
    for n, unit in enumerate(units, start=1):
        path = _write_unit(snip_dir, f"snippet_{n:03d}.py", unit)
        files.append(path)

    py = _make_venv(workdir)
    if py is None:
        return 1
    # Pin mypy so the gate is deterministic — a behaviour change in a future
    # release shouldn't silently start failing (or passing) snippet checks.
    if _run([py, "-m", "pip", "install", "--quiet", MYPY_VERSION], cwd=workdir) != 0:
        return 1
    if _pip_install_sdk(py, source, version, repo_root, workdir) != 0:
        return 1

    # mypy's default errors on a missing/renamed import and on a non-existent
    # attribute of a typed object (obsigna ships py.typed), catching all
    # three drift classes without executing the snippet.
    return _run([py, "-m", "mypy", *files], cwd=workdir)


def run_py(units: list[extract.Unit], source: str, version: str | None, repo_root: str, workdir: str) -> int:
    runnable = _runnable(units, "Python")
    if not runnable:
        return 0

    py = _make_venv(workdir)
    if py is None:
        return 1
    if _pip_install_sdk(py, source, version, repo_root, workdir) != 0:
        return 1

    failures: list[extract.Unit] = []
    for n, unit in enumerate(runnable, start=1):
        run_dir = _prepare_run_dir(workdir, n, "snippet.py", unit)
        if _run([py, "snippet.py"], cwd=run_dir) != 0:
            failures.append(unit)
    return _summarize_run(failures, runnable, "Python")


# --------------------------------------------------------------------------- #


def _write_unit(dirpath: str, filename: str, unit: extract.Unit) -> str:
    path = os.path.join(dirpath, filename)
    header = f"// snippet sources: {', '.join(unit.sources)}" if unit.lang != "py" else f"# snippet sources: {', '.join(unit.sources)}"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(header + "\n")
        fh.write(unit.code)
        if not unit.code.endswith("\n"):
            fh.write("\n")
    return path


_CHECKERS = {
    "typecheck": {"go": check_go, "ts": check_ts, "py": check_py},
    "run": {"go": run_go, "ts": run_ts, "py": run_py},
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lang", required=True, choices=["go", "ts", "py"])
    parser.add_argument("--source", required=True, choices=["local", "published"])
    parser.add_argument("--mode", default="typecheck", choices=["typecheck", "run"])
    parser.add_argument("--version", default=None)
    parser.add_argument("--repo-root", default=os.getcwd())
    parser.add_argument("--workdir", default=None)
    parser.add_argument("readmes", nargs="+")
    args = parser.parse_args(argv)

    repo_root = os.path.abspath(args.repo_root)
    readmes = [os.path.join(repo_root, r) if not os.path.isabs(r) else r for r in args.readmes]
    missing = [r for r in readmes if not os.path.exists(r)]
    if missing:
        # Fail loudly rather than silently disable the gate — a path typo or a
        # renamed README must not quietly pass as "nothing to check".
        print("ERROR: README path(s) not found:")
        for r in missing:
            print(f"  {r}")
        return 2

    print(f"Checking {args.lang} snippets ({args.source}, mode={args.mode}) in:")
    units = _collect_units(readmes, args.lang, args.mode)
    if not units:
        print("No SDK snippets found — nothing to check.")
        return 0

    version = None
    if args.source == "published":
        version = _resolve_version(args.lang, repo_root, args.version)
        print(f"  pinning to published version: {version}")

    cleanup = False
    if args.workdir:
        workdir = os.path.abspath(args.workdir)
        os.makedirs(workdir, exist_ok=True)
    else:
        workdir = tempfile.mkdtemp(prefix="readme-snippets-")
        cleanup = True

    try:
        rc = _CHECKERS[args.mode][args.lang](units, args.source, version, repo_root, workdir)
    finally:
        if cleanup:
            shutil.rmtree(workdir, ignore_errors=True)

    if rc == 0 and args.mode == "typecheck":
        # run mode prints its own per-unit summary via _summarize_run.
        print(f"\nAll {len(units)} {args.lang} snippet unit(s) compiled cleanly.")
    elif rc != 0:
        print(f"\nSnippet {args.mode} FAILED for {args.lang} (see errors above).")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
