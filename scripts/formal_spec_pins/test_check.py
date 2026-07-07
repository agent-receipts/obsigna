#!/usr/bin/env python3
"""Unit tests for the formal-model spec-pin guard.

Most tests exercise the extraction/comparison core against a small fake spec
fragment (no dependency on the real, 600+ line spec.md). One test runs against
the real, committed manifest and the real spec.md — so a drift between the
formal model's pinned assumptions and the live spec is caught here too, not
only by the dedicated CI: formal spec pins workflow.
"""

from __future__ import annotations

import unittest

import check

FAKE_SPEC = """\
# Fake Spec

## 3. Core Concepts

### 3.2 Receipt Chain

An ordered sequence of things.

### 3.3 Action Taxonomy

Unrelated section.

## 4. Schema

#### 4.3.2 `credentialSubject`

| Field | Required | Description |
|---|---|---|
| `chain.chain_id` | Yes | Groups receipts. |
| `chain.sequence` | Yes | Starts at 1. |

#### 4.3.2.1 Intent field guidance (non-normative)

Not part of 4.3.2.

## 7. Receipt Chain Verification

### 7.3 Chain integrity verification

Step 1. Step 2.

#### 7.3.1 Chain truncation detection

Truncation is a floor.
"""


class TestExtractSection(unittest.TestCase):
    def test_extracts_up_to_next_heading_of_any_level(self) -> None:
        section = check.extract_section(FAKE_SPEC, "7.3")
        self.assertIn("### 7.3 Chain integrity verification", section)
        self.assertIn("Step 1. Step 2.", section)
        self.assertNotIn("7.3.1", section)  # subsection excluded, not swallowed

    def test_same_level_sibling_does_not_leak_in(self) -> None:
        section = check.extract_section(FAKE_SPEC, "3.2")
        self.assertIn("An ordered sequence of things.", section)
        self.assertNotIn("Unrelated section.", section)

    def test_same_level_child_heading_terminates_parent(self) -> None:
        # 4.3.2.1 is the same heading level (####) as 4.3.2 but a distinct
        # clause; it must not be included in 4.3.2's extracted text.
        section = check.extract_section(FAKE_SPEC, "4.3.2")
        self.assertNotIn("Not part of 4.3.2.", section)

    def test_unknown_anchor_raises(self) -> None:
        with self.assertRaises(ValueError):
            check.extract_section(FAKE_SPEC, "99.9")


class TestExtractRow(unittest.TestCase):
    def test_finds_row_by_first_cell(self) -> None:
        section = check.extract_section(FAKE_SPEC, "4.3.2")
        row = check.extract_row(section, "`chain.sequence`")
        self.assertIn("Starts at 1.", row)

    def test_unknown_row_raises(self) -> None:
        section = check.extract_section(FAKE_SPEC, "4.3.2")
        with self.assertRaises(ValueError):
            check.extract_row(section, "`chain.nonexistent`")


class TestCheckPins(unittest.TestCase):
    def test_matching_pin_reports_no_problems(self) -> None:
        pin = {"id": "x", "anchor": "3.2", "text": check.extract_section(FAKE_SPEC, "3.2")}
        self.assertEqual(check.check_pins(FAKE_SPEC, [pin]), [])

    def test_drifted_pin_is_reported_with_both_texts(self) -> None:
        pin = {"id": "x", "anchor": "3.2", "text": "stale pinned text"}
        problems = check.check_pins(FAKE_SPEC, [pin])
        self.assertEqual(len(problems), 1)
        self.assertIn("x (§3.2)", problems[0])
        self.assertIn("stale pinned text", problems[0])
        self.assertIn("An ordered sequence of things.", problems[0])

    def test_row_pin_label_includes_row(self) -> None:
        pin = {"id": "x", "anchor": "4.3.2", "row": "`chain.chain_id`", "text": "stale"}
        problems = check.check_pins(FAKE_SPEC, [pin])
        self.assertIn("row `chain.chain_id`", problems[0])

    def test_broken_anchor_is_reported_not_raised(self) -> None:
        pin = {"id": "x", "anchor": "99.9", "text": "anything"}
        problems = check.check_pins(FAKE_SPEC, [pin])
        self.assertEqual(len(problems), 1)
        self.assertIn("no heading numbered", problems[0])


class TestRealManifestMatchesRealSpec(unittest.TestCase):
    """Guards the actual formal-model pins, not just the fake fragment above.

    If this fails, the live spec has drifted from what
    formal/chain-invariants/chain-tamper-evidence.als claims to encode — read
    the new clause text, update the model if it no longer holds, then run
    `check.py --write` to re-pin.
    """

    def test_no_drift(self) -> None:
        spec_text = check.DEFAULT_SPEC.read_text(encoding="utf-8")
        manifest = check._load_manifest(check.DEFAULT_PINS)
        problems = check.check_pins(spec_text, manifest["pins"])
        self.assertEqual(problems, [], "\n\n" + "\n".join(problems))


if __name__ == "__main__":
    unittest.main()
