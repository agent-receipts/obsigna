#!/usr/bin/env python3
"""Emit the conformance-vector counts for the published conformance page.

The conformance page on agentreceipts.ai (``site/src/content/docs/conformance.mdx``)
carries a results matrix whose vector counts must not be hand-typed — a stale
number on a citeable page is worse than no number. This
script reads the frozen vector files directly and emits the counts, so the page
can be regenerated and reviewers can reproduce every figure from source.

It is deliberately read-only and dependency-free (standard library only): it
never writes, generates, or mutates a vector file. The vector corpora it counts
are frozen (see ``cross-sdk-tests/README.md`` and each ``spec/test-vectors``
README); this script only measures them.

Usage:
    count.py                 # human-readable table
    count.py --format md     # Markdown table (paste-ready for the page)
    count.py --format json   # machine-readable counts

Exit codes:
    0  all vector files read and counted
    1  a vector file was missing or malformed
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

# Repo root is three levels up from this file (scripts/conformance_matrix/).
_REPO_ROOT = Path(__file__).resolve().parents[2]

# Object-valued top-level keys in the version-pinned vector files that are NOT a
# receipt/chain vector. Scalar metadata ($comment, version, adr, …) is excluded
# by type below, so this list only needs the non-vector *objects* — currently
# just `keys` (the shared keypair). Keeping this a denylist of objects rather
# than an allowlist of vectors avoids hand-maintaining vector names, while the
# type check stops a future scalar metadata field from inflating the count.
_VERSION_METADATA_OBJECTS = frozenset({"keys"})


def _sum_len(*fields: str) -> Callable[[dict[str, Any]], int]:
    """Count the combined length of one or more list fields."""

    def counter(doc: dict[str, Any]) -> int:
        return sum(len(doc[field]) for field in fields)

    return counter


def _top_level_vectors(doc: dict[str, Any]) -> int:
    """Count top-level receipt/chain vectors in a version-pinned file.

    A vector is a JSON object; scalar metadata (``$comment``, ``version``,
    ``adr``, …) is excluded by type, and the one non-vector object (``keys``,
    the shared keypair) by name. Counting objects rather than "everything not on
    a denylist" means a newly added scalar metadata field cannot silently
    inflate the published count.
    """
    return sum(
        1
        for key, value in doc.items()
        if isinstance(value, dict) and key not in _VERSION_METADATA_OBJECTS
    )


def _single(_doc: dict[str, Any]) -> int:
    """A file that is itself a single vector (one example document)."""
    return 1


@dataclass(frozen=True)
class VectorSet:
    """One row of the conformance matrix."""

    name: str
    path: str  # repo-relative
    purpose: str
    consumers: str  # which SDKs consume/verify it
    spec_versions: str
    counter: Callable[[dict[str, Any]], int]

    def count(self) -> int:
        doc = json.loads((_REPO_ROOT / self.path).read_text(encoding="utf-8"))
        return self.counter(doc)


# The matrix, in the order it appears on the page. Consumer/spec-version columns
# are authored here (they describe how the suites wire the file up, not
# something derivable from the JSON); the count column is computed.
VECTOR_SETS: list[VectorSet] = [
    VectorSet(
        name="canonicalization",
        path="cross-sdk-tests/canonicalization_vectors.json",
        purpose="RFC 8785 canonical JSON + receipt-hash agreement",
        consumers="Go, Py, TS",
        spec_versions="version-independent",
        counter=_sum_len("canonicalization_vectors", "receipt_hash_vectors"),
    ),
    VectorSet(
        name="emit-failure",
        path="cross-sdk-tests/emit_failure_vectors.json",
        purpose="emit-failure outcome contract (ADR-0025)",
        consumers="Go, Py, TS",
        spec_versions="version-independent",
        counter=_sum_len("cases"),
    ),
    VectorSet(
        name="malformed (MUST-reject)",
        path="cross-sdk-tests/malformed_vectors.json",
        purpose="negative corpus: every verifier MUST reject these",
        consumers="Go, Py, TS",
        spec_versions="version-independent",
        counter=_sum_len("receipts", "chains"),
    ),
    VectorSet(
        name="v0.2.0",
        path="cross-sdk-tests/v020_vectors.json",
        purpose="frozen v0.2.0 receipts + chains",
        consumers="Go, Py, TS",
        spec_versions="0.2.0",
        counter=_top_level_vectors,
    ),
    VectorSet(
        name="v0.3.0",
        path="cross-sdk-tests/v030_vectors.json",
        purpose="frozen v0.3.0 receipts + chains",
        consumers="Go, Py, TS",
        spec_versions="0.3.0",
        counter=_top_level_vectors,
    ),
    VectorSet(
        name="v0.4.0",
        path="cross-sdk-tests/v040_vectors.json",
        purpose="frozen v0.4.0 receipts + chains",
        consumers="Go, Py, TS",
        spec_versions="0.4.0",
        counter=_top_level_vectors,
    ),
    VectorSet(
        name="v0.5.0",
        path="cross-sdk-tests/v050_vectors.json",
        purpose="frozen v0.5.0 receipts + chains",
        consumers="Go, Py, TS",
        spec_versions="0.5.0",
        counter=_top_level_vectors,
    ),
    VectorSet(
        name="did:key resolution",
        path="spec/test-vectors/did-key/vectors.json",
        purpose="did:key v0.7 resolution wire shape (ADR-0007)",
        consumers="Go, Py, TS",
        spec_versions="did:key v0.7",
        counter=_sum_len("vectors"),
    ),
    VectorSet(
        name="disclosure envelope",
        path="spec/test-vectors/disclosure-envelope/vectors.json",
        purpose="parameter-disclosure envelope: pinned ciphertext",
        consumers="Go, Py, TS",
        spec_versions="envelope v1",
        counter=_sum_len("vectors"),
    ),
    VectorSet(
        name="rotation event",
        path="spec/test-vectors/rotation-event/example.json",
        purpose="key-rotation event verifies under the outgoing key",
        consumers="Go, Py, TS",
        spec_versions="0.2.1",
        counter=_single,
    ),
]


def collect() -> list[tuple[VectorSet, int]]:
    """Read every vector file and pair each set with its count."""
    return [(vs, vs.count()) for vs in VECTOR_SETS]


def _render_table(rows: list[tuple[VectorSet, int]]) -> str:
    header = ("Vector set", "Purpose", "Consumers", "Spec", "Count")
    lines = [f"{header[0]:<24} {header[1]:<48} {header[2]:<44} {header[3]:<16} {header[4]}"]
    for vs, count in rows:
        lines.append(
            f"{vs.name:<24} {vs.purpose:<48} {vs.consumers:<44} {vs.spec_versions:<16} {count}"
        )
    total = sum(count for _, count in rows)
    lines.append("")
    lines.append(f"Total vectors: {total}")
    return "\n".join(lines)


def _render_md(rows: list[tuple[VectorSet, int]]) -> str:
    lines = [
        "| Vector set | Purpose | Consumers | Spec version(s) | Vectors |",
        "| --- | --- | --- | --- | ---: |",
    ]
    for vs, count in rows:
        lines.append(
            f"| {vs.name} | {vs.purpose} | {vs.consumers} | {vs.spec_versions} | {count} |"
        )
    return "\n".join(lines)


def _render_json(rows: list[tuple[VectorSet, int]]) -> str:
    payload = {
        "sets": [
            {
                "name": vs.name,
                "path": vs.path,
                "purpose": vs.purpose,
                "consumers": vs.consumers,
                "specVersions": vs.spec_versions,
                "count": count,
            }
            for vs, count in rows
        ],
        "total": sum(count for _, count in rows),
    }
    return json.dumps(payload, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--format",
        choices=("table", "md", "json"),
        default="table",
        help="output format (default: table)",
    )
    args = parser.parse_args(argv)

    try:
        rows = collect()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError) as err:
        print(f"error: could not count vectors: {err}", file=sys.stderr)
        return 1

    renderer = {"table": _render_table, "md": _render_md, "json": _render_json}[args.format]
    print(renderer(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
