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

    def test_json_output_is_valid_and_totals(self) -> None:
        payload = json.loads(count._render_json(count.collect()))
        self.assertEqual(payload["total"], sum(s["count"] for s in payload["sets"]))

    def test_md_output_has_header_and_one_row_per_set(self) -> None:
        md = count._render_md(count.collect())
        lines = md.splitlines()
        # header + separator + one row per set
        self.assertEqual(len(lines), 2 + len(count.VECTOR_SETS))


if __name__ == "__main__":
    unittest.main()
