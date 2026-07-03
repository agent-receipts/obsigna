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
    count.py --format md     # Markdown table (on-page sets only; the page splits
                              # this output's "Consumers" column into separate
                              # Go/Py/TS columns, so paste it in as a reference,
                              # not a drop-in replacement)
    count.py --format enforces  # Markdown "Enforces" table: per-vector clause
                              # traceability for the MUST-reject corpus
    count.py --format json   # machine-readable counts (+ malformedCorpus clauses)

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
    # Whether this set appears as a row in the published matrix on the page.
    # A reference-fixture set that no SDK suite consumes yet is still counted
    # here — so the corpus stays fully reproducible from source — but should
    # be kept off the results matrix rather than shown as an all-dashes row
    # that invites the wrong question. The page reconciliation test binds the
    # page's matrix to the on_page=True rows.
    on_page: bool = True

    def count(self) -> int:
        doc = json.loads((_REPO_ROOT / self.path).read_text(encoding="utf-8"))
        return self.counter(doc)


# Every frozen vector set, in matrix order. Consumer/spec-version columns are
# authored here (they describe how the suites wire the file up, not something
# derivable from the JSON); the count column is computed. Sets with
# on_page=False are counted but omitted from the published results matrix.
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


def _malformed_set() -> VectorSet:
    """The MUST-reject corpus set, located by path so its file is a single source."""
    for vs in VECTOR_SETS:
        if vs.path.endswith("malformed_vectors.json"):
            return vs
    raise KeyError("malformed vector set not found in VECTOR_SETS")


# Published spec pages the clause sections live on (Starlight slugs). The site's
# spec is reorganised from the source spec.md, so not every source subsection
# (e.g. §7.3.5, §7.8) has its own on-page anchor; those map to the nearest
# containing section that does. The `clause` field stays a plain source-section
# reference (it is shared across the three SDKs in the vector JSON and must not
# carry site URLs); the anchor is resolved here, at render time, so the page's
# "Enforces" links stay generated rather than hand-typed.
_SPEC_CHAIN = "/specification/receipt-chain-verification/"
_SPEC_SCHEMA = "/specification/agent-receipt-schema/"

# Map the leading section token of a clause (e.g. "§7.3.5") to its published
# anchor. A clause whose section token is absent here raises KeyError, so a new
# vector referencing an unmapped section fails the count rather than shipping an
# unlinked or dead-linked cell.
_CLAUSE_ANCHOR: dict[str, str] = {
    "§4.3.2": _SPEC_SCHEMA + "#chain",  # chain.chain_id is a required chain field
    "§4.3.3": _SPEC_SCHEMA + "#proof",
    "§7.3": _SPEC_CHAIN + "#chain-integrity-verification",
    "§7.3.5": _SPEC_CHAIN + "#chain-integrity-verification",
    "§7.8": _SPEC_CHAIN + "#chain-integrity-verification",
}


def _clause_anchor(clause: str) -> str:
    """Resolve a clause string to its published spec anchor via its leading
    section token (the first whitespace-delimited word, e.g. ``§7.3.5``)."""
    section = clause.split(None, 1)[0]
    try:
        return _CLAUSE_ANCHOR[section]
    except KeyError:
        raise KeyError(
            f"no published anchor mapped for clause section {section!r} "
            f"(clause: {clause!r}); add it to _CLAUSE_ANCHOR"
        ) from None


def malformed_corpus() -> list[dict[str, str]]:
    """Clause traceability for every vector in the MUST-reject corpus.

    Reads the same file the ``malformed (MUST-reject)`` set counts and returns
    one ``{name, kind, clause, anchor}`` entry per vector — receipt-level cases
    from ``receipts[]`` and chain-level cases from ``chains[]``. The ``clause``
    names the normative spec section the vector enforces and ``anchor`` is the
    published spec-page anchor it resolves to; together they feed the "Enforces"
    column on the conformance page. A vector missing its ``clause`` raises
    ``KeyError`` here, so an unannotated vector fails the count rather than
    silently shipping a blank cell.
    """
    doc = json.loads((_REPO_ROOT / _malformed_set().path).read_text(encoding="utf-8"))
    out: list[dict[str, str]] = []
    for kind, key in (("receipt", "receipts"), ("chain", "chains")):
        for case in doc[key]:
            clause = case["clause"]
            out.append(
                {
                    "name": case["name"],
                    "kind": kind,
                    "clause": clause,
                    "anchor": _clause_anchor(clause),
                }
            )
    return out


def _render_table(rows: list[tuple[VectorSet, int]]) -> str:
    header = ("Vector set", "Purpose", "Consumers", "Spec", "Count")
    lines = [
        f"{header[0]:<24} {header[1]:<48} {header[2]:<44} {header[3]:<16} {header[4]}"
    ]
    for vs, count in rows:
        lines.append(
            f"{vs.name:<24} {vs.purpose:<48} {vs.consumers:<44} {vs.spec_versions:<16} {count}"
        )
    total = sum(count for _, count in rows)
    lines.append("")
    lines.append(f"Total vectors: {total}")
    return "\n".join(lines)


def _render_md(rows: list[tuple[VectorSet, int]]) -> str:
    # Paste-ready for the published matrix, which lists only the on-page sets.
    lines = [
        "| Vector set | Purpose | Consumers | Spec version(s) | Vectors |",
        "| --- | --- | --- | --- | ---: |",
    ]
    for vs, count in rows:
        if not vs.on_page:
            continue
        lines.append(
            f"| {vs.name} | {vs.purpose} | {vs.consumers} | {vs.spec_versions} | {count} |"
        )
    return "\n".join(lines)


def _render_enforces(_rows: list[tuple[VectorSet, int]]) -> str:
    """Markdown "Enforces" table: per-vector clause traceability for the
    MUST-reject corpus. Paste-ready for the clause-traceability table on the
    conformance page; the reconciliation test pins that table to this data."""
    lines = [
        "| Vector | Layer | Enforces |",
        "| --- | --- | --- |",
    ]
    for case in malformed_corpus():
        enforces = f"[{case['clause']}]({case['anchor']})"
        lines.append(f"| {case['name']} | {case['kind']} | {enforces} |")
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
                "onPage": vs.on_page,
            }
            for vs, count in rows
        ],
        "total": sum(count for _, count in rows),
        "malformedCorpus": malformed_corpus(),
    }
    return json.dumps(payload, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--format",
        choices=("table", "md", "enforces", "json"),
        default="table",
        help="output format (default: table)",
    )
    args = parser.parse_args(argv)

    renderer = {
        "table": _render_table,
        "md": _render_md,
        "enforces": _render_enforces,
        "json": _render_json,
    }[args.format]
    try:
        rows = collect()
        # Render inside the try so a vector missing its `clause` (raised by
        # malformed_corpus during md/json rendering) is reported as a count
        # error, not an uncaught traceback.
        output = renderer(rows)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError) as err:
        print(f"error: could not count vectors: {err}", file=sys.stderr)
        return 1

    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
