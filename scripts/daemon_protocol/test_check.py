"""Unit tests for the Gate #8 daemon ↔ SDK protocol-compatibility verifier.

These tests exercise the pure comparison/parse core — range intersection,
semver "latest" selection, asset-URL construction, the daemon and SDK stdout
parsers, and receipt counting. No artifact is downloaded or installed and no
network call is made; the download/install/boot drivers are exercised
end-to-end by CI at release time, not here.

The core invariant under test: `ranges_intersect` is true exactly when two
inclusive ranges overlap, the parsers recover the pinned ranges from real
wire-shaped output and reject malformed input, and `count_receipts` reads the
`agent-receipts list --json` array. The failure cases — a disjoint range, an
inverted range, malformed JSON — are a direct implementation of ADR-0024 D6 (a
gate must be observed to fail on a deliberately-broken input).

Run with:
    python3 -m pytest scripts/daemon_protocol/test_check.py
    python3 scripts/daemon_protocol/test_check.py   # quick self-check
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import check  # noqa: E402


class TestRangesIntersect:
    def test_identical_single_point(self) -> None:
        assert check.ranges_intersect((1, 1), (1, 1))

    def test_overlapping(self) -> None:
        assert check.ranges_intersect((1, 3), (2, 5))

    def test_touching_at_boundary(self) -> None:
        assert check.ranges_intersect((1, 2), (2, 4))

    def test_one_contains_the_other(self) -> None:
        assert check.ranges_intersect((1, 9), (3, 4))

    def test_disjoint_sdk_ahead(self) -> None:
        # SDK speaks only v2; daemon speaks only v1 — incompatible.
        assert not check.ranges_intersect((2, 2), (1, 1))

    def test_disjoint_daemon_ahead(self) -> None:
        assert not check.ranges_intersect((1, 1), (2, 3))


class TestParseSpokenRange:
    def test_parses_wire_shape(self) -> None:
        out = '{"frame_version":{"min":1,"max":1}}'
        assert check.parse_spoken_range(out) == (1, 1)

    def test_parses_wider_range(self) -> None:
        out = '{"frame_version":{"min":1,"max":3}}'
        assert check.parse_spoken_range(out) == (1, 3)

    def test_ignores_leading_log_lines(self) -> None:
        out = "booting...\nready\n{\"frame_version\":{\"min\":2,\"max\":4}}"
        assert check.parse_spoken_range(out) == (2, 4)

    def test_missing_frame_version_raises(self) -> None:
        try:
            check.parse_spoken_range('{"something_else":1}')
        except ValueError:
            return
        raise AssertionError("expected ValueError for missing frame_version")

    def test_no_json_raises(self) -> None:
        try:
            check.parse_spoken_range("not json at all")
        except ValueError:
            return
        raise AssertionError("expected ValueError when no JSON object is present")


class TestParseDeclaredRange:
    def test_parses_minmax(self) -> None:
        assert check.parse_declared_range('{"min":1,"max":1}') == (1, 1)

    def test_inverted_range_raises(self) -> None:
        try:
            check.parse_declared_range('{"min":5,"max":2}')
        except ValueError:
            return
        raise AssertionError("expected ValueError for inverted range")

    def test_missing_key_raises(self) -> None:
        try:
            check.parse_declared_range('{"min":1}')
        except ValueError:
            return
        raise AssertionError("expected ValueError for missing max")


class TestCountReceipts:
    def test_empty_array(self) -> None:
        assert check.count_receipts("[]") == 0

    def test_empty_string(self) -> None:
        assert check.count_receipts("   ") == 0

    def test_one_receipt(self) -> None:
        assert check.count_receipts('[{"id":"a"}]') == 1

    def test_several_receipts(self) -> None:
        assert check.count_receipts('[{"id":"a"},{"id":"b"},{"id":"c"}]') == 3

    def test_non_array_reads_as_zero(self) -> None:
        assert check.count_receipts('{"oops":true}') == 0

    def test_garbage_reads_as_zero(self) -> None:
        assert check.count_receipts("not json") == 0


class TestDaemonAssetURL:
    def test_url_shape(self) -> None:
        url = check.daemon_asset_url("0.8.0")
        assert url == (
            "https://github.com/agent-receipts/obsigna/releases/download/"
            "obsigna%2Fv0.8.0/obsigna_0.8.0_linux_amd64.tar.gz"
        )

    def test_prerelease_version(self) -> None:
        url = check.daemon_asset_url("0.9.0-alpha.1")
        assert "obsigna%2Fv0.9.0-alpha.1/" in url
        assert url.endswith("obsigna_0.9.0-alpha.1_linux_amd64.tar.gz")


class TestPickLatest:
    def test_picks_highest_stable(self) -> None:
        assert check.pick_latest(["0.8.0", "0.10.0", "0.9.0"], False) == "0.10.0"

    def test_numeric_not_lexicographic(self) -> None:
        # "0.10.0" must beat "0.9.0" even though "9" > "1" lexicographically.
        assert check.pick_latest(["0.9.0", "0.10.0"], False) == "0.10.0"

    def test_excludes_prerelease_by_default(self) -> None:
        assert check.pick_latest(["0.8.0", "0.9.0-alpha.1"], False) == "0.8.0"

    def test_release_beats_its_own_prerelease(self) -> None:
        assert check.pick_latest(["0.9.0", "0.9.0-alpha.1"], True) == "0.9.0"

    def test_allows_prerelease_when_only_option(self) -> None:
        assert check.pick_latest(["0.9.0-alpha.1", "0.9.0-alpha.2"], True) == "0.9.0-alpha.2"

    def test_prerelease_numeric_identifiers_ordered_numerically(self) -> None:
        # SemVer §11: alpha.2 < alpha.10 (numeric identifiers compared as
        # numbers, not lexically). The lexical bug returned alpha.2.
        assert check.pick_latest(["0.9.0-alpha.2", "0.9.0-alpha.10"], True) == "0.9.0-alpha.10"

    def test_prerelease_alpha_below_beta(self) -> None:
        assert check.pick_latest(["0.9.0-beta.1", "0.9.0-alpha.9"], True) == "0.9.0-beta.1"

    def test_build_metadata_ignored(self) -> None:
        # Build metadata (+...) does not affect precedence (SemVer §10); the
        # higher core still wins and parsing must not choke on the '+'.
        assert check.pick_latest(["0.9.0+ci.7", "0.10.0+ci.1"], False) == "0.10.0+ci.1"

    def test_ignores_unparseable_tag_keeps_valid_latest(self) -> None:
        # A stray non-semver tag must not break or silently disarm resolution;
        # the well-formed versions still win.
        assert check.pick_latest(["0.9.0", "nightly", "0.10.0"], False) == "0.10.0"

    def test_no_stable_candidate_raises_typed(self) -> None:
        # Must raise the dedicated NoStableReleaseError (which resolve_* maps to
        # a skip), NOT a bare ValueError — a malformed-tag ValueError instead
        # propagates and fails the gate closed.
        try:
            check.pick_latest(["0.9.0-alpha.1"], False)
        except check.NoStableReleaseError:
            return
        raise AssertionError("expected NoStableReleaseError when no stable version exists")

    def test_all_unparseable_raises_no_stable(self) -> None:
        try:
            check.pick_latest(["nightly", "edge"], True)
        except check.NoStableReleaseError:
            return
        raise AssertionError("expected NoStableReleaseError when no parseable version exists")


# ---------------------------------------------------------------------------
# Self-runner (no pytest dependency required)
# ---------------------------------------------------------------------------


def _run_all() -> int:
    failures = 0
    suites = [
        TestRangesIntersect,
        TestParseSpokenRange,
        TestParseDeclaredRange,
        TestCountReceipts,
        TestDaemonAssetURL,
        TestPickLatest,
    ]
    for suite_cls in suites:
        suite = suite_cls()
        for name in sorted(dir(suite_cls)):
            if not name.startswith("test_"):
                continue
            fn = getattr(suite, name)
            try:
                fn()
                print(f"ok   {suite_cls.__name__}.{name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {suite_cls.__name__}.{name}: {exc}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"ERROR {suite_cls.__name__}.{name}: {type(exc).__name__}: {exc}")
    return failures


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
