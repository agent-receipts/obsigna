#!/usr/bin/env python3
"""Unit tests for the conformance-matrix count emitter.

Runs against the real, committed vector files (no network, no SDK install), so
a drift between the page's numbers and the frozen corpora is caught here.
"""

from __future__ import annotations

import json
import unittest

import count


class TestCollect(unittest.TestCase):
    def test_every_set_reads_and_counts_positive(self) -> None:
        rows = count.collect()
        self.assertEqual(len(rows), len(count.VECTOR_SETS))
        for vector_set, n in rows:
            self.assertGreater(n, 0, f"{vector_set.name} counted zero vectors")

    def test_did_key_marked_not_yet_wired(self) -> None:
        # Honesty guard: the did:key vectors are reference fixtures not consumed
        # by any suite. If they get wired up, this row's consumer text must
        # change on the page too — fail here to force that.
        row = next(vs for vs, _ in count.collect() if vs.name == "did:key resolution")
        self.assertIn("not yet wired", row.consumers)

    def test_top_level_vectors_excludes_metadata(self) -> None:
        doc = {"$comment": "x", "version": "0.9.0", "keys": {}, "a": {}, "b": {}}
        self.assertEqual(count._top_level_vectors(doc), 2)

    def test_top_level_vectors_ignores_unknown_scalar_metadata(self) -> None:
        # A future scalar metadata field must not be counted as a vector — the
        # type check excludes it without needing to be added to a denylist.
        doc = {"version": "0.9.0", "keys": {}, "notes": "freeform", "a": {}}
        self.assertEqual(count._top_level_vectors(doc), 1)

    def test_json_output_is_valid_and_totals(self) -> None:
        payload = json.loads(count._render_json(count.collect()))
        self.assertEqual(payload["total"], sum(s["count"] for s in payload["sets"]))

    def test_md_output_has_header_and_one_row_per_on_page_set(self) -> None:
        md = count._render_md(count.collect())
        lines = md.splitlines()
        on_page = [vs for vs in count.VECTOR_SETS if vs.on_page]
        # header + separator + one row per on-page set. The published matrix
        # splits this output's combined "Consumers" column into separate
        # Go/Py/TS columns, so this is a reference table, not a drop-in paste.
        self.assertEqual(len(lines), 2 + len(on_page))

    def test_md_output_excludes_off_page_sets(self) -> None:
        # Off-page reference fixtures (currently did:key) are counted but must
        # not appear in the markdown output, matching the published page.
        md = count._render_md(count.collect())
        for vs in count.VECTOR_SETS:
            if not vs.on_page:
                self.assertNotIn(vs.name, md, f"{vs.name} leaked into the page matrix")

    def test_did_key_is_off_page(self) -> None:
        # The did:key fixtures are counted (reproducibility) but no SDK suite
        # consumes them, so they are kept off the published matrix rather than
        # shown as an all-dashes row.
        row = next(vs for vs in count.VECTOR_SETS if vs.name == "did:key resolution")
        self.assertFalse(row.on_page)


if __name__ == "__main__":
    unittest.main()
