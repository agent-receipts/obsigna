#!/usr/bin/env python3
"""Anti-regression guard for the SDK package rename to the Obsigna brand.

The TypeScript and Python SDKs moved off their legacy distribution names onto
the Obsigna brand:

    npm   @agnt-rcpt/sdk-ts      -> @obsigna/sdk-ts
    npm   @agnt-rcpt/sdk-ts-aws  -> @obsigna/sdk-ts-aws
    PyPI  agent-receipts         -> obsigna   (import: agent_receipts -> obsigna)

This guard fails CI if a legacy *distribution / install* name reappears in a
package manifest, lockfile, or install doc — the same shape as the daemon
entrypoint guard. It is deliberately narrow (two-layer naming): it does NOT
flag identifiers that are not the distribution name, namely

  - the GitHub org / Go module path ``github.com/agent-receipts/...`` and bare
    repo refs like ``agent-receipts/ar`` (the Go SDK ships by module path, a
    separate concern),
  - release-binary names like ``agent-receipts-daemon`` / ``agent-receipts-hook``,
  - protocol identifiers such as ``agent_receipts.events_dropped``,
  - the unrelated ``@agnt-rcpt/openclaw`` package,
  - the deprecation shim's own metadata under ``dist/sdk-py-deprecation/`` (it
    intentionally keeps the legacy name as a redirect — the one exception).

Run:
    python3 scripts/legacy_name_guard/check.py        # scan the gated file set
    python3 scripts/legacy_name_guard/check.py PATH…  # scan explicit files
"""

from __future__ import annotations

import argparse
import os
import re
import sys

# Files the guard scans by default: the renamed SDKs' manifests, lockfiles, and
# install docs. The deprecation shim (dist/sdk-py-deprecation/) is intentionally
# absent — it is the one place the legacy name is allowed.
GATED_FILES = [
    "sdk/ts/package.json",
    "sdk/ts-aws/package.json",
    "sdk/py/pyproject.toml",
    "sdk/ts/pnpm-lock.yaml",
    "sdk/ts-aws/pnpm-lock.yaml",
    "sdk/py/uv.lock",
    "README.md",
    "sdk/ts/README.md",
    "sdk/ts-aws/README.md",
    "sdk/py/README.md",
    # User-facing install docs on the site — same shape as the README install
    # commands, so they regress the same way (a snippet drifting back onto the
    # legacy npm scope / PyPI name).
    "site/src/content/docs/sdk-ts/installation.mdx",
    "site/src/content/docs/sdk-py/installation.mdx",
]

# Each entry: (compiled pattern, human description). The patterns match only the
# legacy *distribution / install / import* forms of the SDK packages. They are
# intentionally precise so they do NOT flag adjacent identifiers that are out of
# scope for this rename: the GitHub org / Go module path
# ``github.com/agent-receipts/…``, repo refs like ``agent-receipts/sdk-py``, the
# daemon CLI command ``agent-receipts verify`` and its ``agent-receipts-daemon``
# binary (a separate, in-progress rename), protocol identifiers like
# ``agent_receipts.events_dropped``, and ``@agnt-rcpt/openclaw``.
FORBIDDEN = [
    (re.compile(r"@agnt-rcpt/sdk-ts"), "legacy npm scope @agnt-rcpt/sdk-ts(-aws) (use @obsigna/…)"),
    (re.compile(r"""pip install\s+["']?agent-receipts"""), "legacy PyPI install `pip install agent-receipts` (use obsigna)"),
    (re.compile(r"\bagent-receipts=="), "legacy PyPI pinned install agent-receipts== (use obsigna==)"),
    (re.compile(r"pypi\.org/project/agent-receipts\b"), "legacy PyPI project link agent-receipts (use obsigna)"),
    (re.compile(r"shields\.io/pypi/[^)\s]*agent-receipts\b"), "legacy PyPI badge for agent-receipts (use obsigna)"),
    (re.compile(r"""(?m)^\s*name\s*=\s*["']agent-receipts["']"""), "legacy PyPI project name in manifest (use obsigna)"),
    (re.compile(r"^#\s+agent-receipts\s*$"), "legacy package title `# agent-receipts` (use # obsigna)"),
    (re.compile(r"\b(?:from|import)\s+agent_receipts\b"), "legacy Python import module agent_receipts (use obsigna)"),
    # Slash-preceded path segment (e.g. ``src/agent_receipts`` in a manifest).
    # The leading ``/`` distinguishes a package path from the protocol
    # identifier ``agent_receipts.events_dropped`` (quote-preceded, never gated).
    (re.compile(r"/agent_receipts\b"), "legacy Python package dir src/agent_receipts (use src/obsigna)"),
]


def scan_text(text: str) -> list[tuple[int, str, str]]:
    """Return ``(line_number, description, line)`` for every forbidden match."""
    violations: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pattern, description in FORBIDDEN:
            if pattern.search(line):
                violations.append((lineno, description, line.strip()))
    return violations


def scan_file(path: str) -> list[tuple[int, str, str]]:
    with open(path, encoding="utf-8") as fh:
        return scan_text(fh.read())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Guard against legacy SDK package names.")
    parser.add_argument(
        "--root",
        default=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        help="Repo root to resolve the default gated file set against.",
    )
    parser.add_argument("files", nargs="*", help="Explicit files to scan (overrides the gated set).")
    args = parser.parse_args(argv)

    if args.files:
        targets = args.files
    else:
        targets = [os.path.join(args.root, rel) for rel in GATED_FILES]

    total = 0
    for path in targets:
        if not os.path.exists(path):
            # A gated file may legitimately not exist yet (e.g. a lockfile);
            # skip silently rather than fail the build on absence.
            continue
        violations = scan_file(path)
        for lineno, description, line in violations:
            total += 1
            print(f"{path}:{lineno}: {description}\n    {line}")

    if total:
        print(f"\nlegacy_name_guard: {total} legacy package-name reference(s) found.", file=sys.stderr)
        print("Rename to the Obsigna brand (@obsigna/… , obsigna). If this is the", file=sys.stderr)
        print("deprecation shim, it must live under dist/sdk-py-deprecation/.", file=sys.stderr)
        return 1

    print("legacy_name_guard: clean — no legacy SDK package names in gated files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
