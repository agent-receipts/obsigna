#!/usr/bin/env python3
"""Guard against a spec edit silently outrunning the formal chain-invariants model.

``formal/chain-invariants/chain-tamper-evidence.als`` formalizes a specific set
of normative clauses from ``spec/v0.5.0/spec.md`` (see its header comment).
Nothing forces the Alloy model to change when those clauses do — the model does
not parse the spec, so a wording or requirement change under, say, §7.3.5 can
land, merge, and leave the model quietly describing a spec that no longer
exists.

This script pins the exact text of every clause the model depends on in
``formal/chain-invariants/spec-pins.json`` and fails if the live spec text at
that clause no longer matches. It is deliberately narrow: it does not
understand Alloy or re-run the model (that's ``formal/chain-invariants/run.sh``,
gated separately and expensively by CI: formal); it only detects that the spec
moved out from under a pin.

On a legitimate spec change to a pinned clause:

    1. Read the new clause text and decide whether
       chain-tamper-evidence.als still holds.
    2. If it doesn't, update the model (and re-run run.sh).
    3. Run ``check.py --write`` to re-pin the manifest to the new text, and
       commit the updated formal/chain-invariants/spec-pins.json alongside
       whatever else changed.

Anchors are the clause's numeral (e.g. ``"7.3.5"``), matched against the
leading number in a markdown heading; a pin's extracted text runs from that
heading to the next heading of any level. A pin may instead target one
markdown table row within a section via ``"row"`` (the row's first cell,
e.g. ``"`chain.chain_id`"``) — used for the handful of `credentialSubject`
schema fields the model depends on, so an edit to an unrelated field in the
same table doesn't trip the gate.

Usage:
    check.py              # fail if any pin has drifted from the live spec
    check.py --write       # re-pin every entry to the current spec text

Exit codes:
    0  every pin matches the live spec (or --write completed)
    1  at least one pin has drifted, or a pin's anchor/row no longer exists
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SPEC = _REPO_ROOT / "spec" / "v0.5.0" / "spec.md"
DEFAULT_PINS = _REPO_ROOT / "formal" / "chain-invariants" / "spec-pins.json"

# Matches an ATX heading's leading clause numeral: "## 3. Core Concepts" -> "3",
# "### 3.2 Receipt Chain" -> "3.2", "#### 7.3.1 Chain truncation..." -> "7.3.1".
_HEADING_RE = re.compile(r"^#{1,6}\s+(?P<num>\d+(?:\.\d+)*)\.?\s")


def _iter_headings(lines: list[str]) -> list[tuple[int, str]]:
    """Return [(line_index, clause_numeral), ...] for every numbered heading."""
    headings = []
    for i, line in enumerate(lines):
        m = _HEADING_RE.match(line)
        if m:
            headings.append((i, m.group("num")))
    return headings


def extract_section(spec_text: str, anchor: str) -> str:
    """Return the text of the clause numbered *anchor*, heading to next heading.

    The slice runs from the matching heading line up to (not including) the
    next heading of ANY level, so a parent clause's own body (e.g. §7.3's
    steps 1-4) does not swallow its subsections (§7.3.1, §7.3.2, ...) — those
    are pinned separately when needed.
    """
    lines = spec_text.splitlines()
    headings = _iter_headings(lines)
    for idx, (line_no, num) in enumerate(headings):
        if num != anchor:
            continue
        end = headings[idx + 1][0] if idx + 1 < len(headings) else len(lines)
        return "\n".join(lines[line_no:end]).strip()
    raise ValueError(f"no heading numbered {anchor!r} found in spec")


def extract_row(section_text: str, row: str) -> str:
    """Return the single markdown table row in *section_text* whose first cell
    (trimmed) equals *row*, e.g. ``"`chain.chain_id`"``."""
    for line in section_text.splitlines():
        if not line.strip().startswith("|"):
            continue
        first_cell = line.strip().strip("|").split("|", 1)[0].strip()
        if first_cell == row:
            return line.strip()
    raise ValueError(f"no table row {row!r} found in section")


def current_text(spec_text: str, pin: dict) -> str:
    section = extract_section(spec_text, pin["anchor"])
    row = pin.get("row")
    return extract_row(section, row) if row else section


def check_pins(spec_text: str, pins: list[dict]) -> list[str]:
    """Return a human-readable mismatch message per drifted or broken pin."""
    problems = []
    for pin in pins:
        label = f"{pin['id']} (§{pin['anchor']}" + (f", row {pin['row']}" if pin.get("row") else "") + ")"
        try:
            live = current_text(spec_text, pin)
        except ValueError as exc:
            problems.append(f"{label}: {exc}")
            continue
        if live != pin["text"]:
            problems.append(
                f"{label}: spec text has changed since this pin was last reviewed\n"
                f"    pinned: {pin['text']!r}\n"
                f"    live:   {live!r}"
            )
    return problems


def _load_manifest(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _write_manifest(path: Path, manifest: dict, spec_text: str) -> None:
    for pin in manifest["pins"]:
        pin["text"] = current_text(spec_text, pin)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC, help=f"Spec file to check against (default: {DEFAULT_SPEC})")
    parser.add_argument("--pins", type=Path, default=DEFAULT_PINS, help=f"Pin manifest (default: {DEFAULT_PINS})")
    parser.add_argument("--write", action="store_true", help="Re-pin every entry to the current spec text instead of checking")
    args = parser.parse_args(argv)

    spec_text = args.spec.read_text(encoding="utf-8")
    manifest = _load_manifest(args.pins)

    if args.write:
        _write_manifest(args.pins, manifest, spec_text)
        print(f"formal_spec_pins: re-pinned {len(manifest['pins'])} clause(s) in {args.pins}")
        return 0

    problems = check_pins(spec_text, manifest["pins"])
    if problems:
        print(f"formal_spec_pins: {len(problems)} pin(s) out of sync with {args.spec}:\n")
        for p in problems:
            print(f"  - {p}\n")
        print(
            "The formal chain-invariants model (formal/chain-invariants/*.als) claims to "
            "encode these clauses. Read the new text, decide whether the model still "
            "holds, update it if not, then run `check.py --write` to re-pin."
        )
        return 1

    print(f"formal_spec_pins: clean — {len(manifest['pins'])} pin(s) match {args.spec}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
