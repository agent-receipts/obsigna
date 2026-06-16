"""Unit tests for the Gate #2 release round-trip verifier.

These tests exercise the version-parsing and comparison logic without
making network calls. The core invariant under test: the gate must *fail*
(return 1) when the registry resolves a version other than the one we
expected, and *pass* (return 0) only when the two are identical.

Run with:
    python3 -m pytest scripts/release_verify/test_check.py
    python3 scripts/release_verify/test_check.py   # quick self-check
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import check  # noqa: E402

# ---------------------------------------------------------------------------
# assert_version — the core gate logic
# ---------------------------------------------------------------------------


class TestAssertVersion:
    """The version assertion is the heart of Gate #2.

    Every test in this class that validates a *failure* case is a direct
    implementation of ADR-0024 D6: the gate must be observed to fail on a
    deliberately-broken input.
    """

    def test_matching_version_passes(self) -> None:
        assert check.assert_version("pkg", "1.2.3", "1.2.3") == 0

    def test_wrong_version_fails(self) -> None:
        # Registry returns a different version than the one tagged.
        assert check.assert_version("pkg", "1.2.3", "1.2.4") == 1

    def test_older_version_fails(self) -> None:
        # Registry returns an older version — e.g. index hasn't propagated yet.
        assert check.assert_version("pkg", "1.2.3", "1.2.2") == 1

    def test_none_resolved_fails(self) -> None:
        # Registry output was unparseable; resolved is None.
        assert check.assert_version("pkg", "1.2.3", None) == 1

    def test_prerelease_exact_match_passes(self) -> None:
        assert check.assert_version("pkg", "0.12.0-alpha.1", "0.12.0-alpha.1") == 0

    def test_prerelease_stable_mismatch_fails(self) -> None:
        # Released a pre-release but registry returned the stable version.
        assert check.assert_version("pkg", "0.12.0-alpha.1", "0.12.0") == 1

    def test_stable_prerelease_mismatch_fails(self) -> None:
        # Released stable but registry returned a pre-release.
        assert check.assert_version("pkg", "0.12.0", "0.12.0-alpha.1") == 1

    def test_version_with_leading_v_in_resolved_fails(self) -> None:
        # If a verifier forgets to strip the leading 'v' from go list output,
        # the comparison must fail so the bug is visible rather than silently
        # passing (e.g. resolved="v0.12.0" != expected="0.12.0").
        assert check.assert_version(check.GO_MODULE, "0.12.0", "v0.12.0") == 1

    def test_empty_string_resolved_fails(self) -> None:
        assert check.assert_version("pkg", "1.0.0", "") == 1


# ---------------------------------------------------------------------------
# _parse_pip_show_version
# ---------------------------------------------------------------------------


class TestParsePipShowVersion:
    def test_parses_version_line(self) -> None:
        output = (
            "Name: obsigna\n"
            "Version: 0.10.0\n"
            "Summary: Agent Receipts SDK\n"
        )
        assert check._parse_pip_show_version(output) == "0.10.0"

    def test_strips_whitespace(self) -> None:
        assert check._parse_pip_show_version("Version:   1.2.3  \n") == "1.2.3"

    def test_missing_version_returns_none(self) -> None:
        assert check._parse_pip_show_version("Name: obsigna\nSummary: x\n") is None

    def test_empty_output_returns_none(self) -> None:
        assert check._parse_pip_show_version("") is None

    def test_prerelease_version_parsed(self) -> None:
        assert check._parse_pip_show_version("Version: 0.10.0a1\n") == "0.10.0a1"


# ---------------------------------------------------------------------------
# _parse_npm_list_version
# ---------------------------------------------------------------------------


class TestParseNpmListVersion:
    _PACKAGE = check.TS_PACKAGE

    def test_parses_version_from_npm_list_json(self) -> None:
        import json

        data = {
            "name": "release-verify",
            "dependencies": {self._PACKAGE: {"version": "0.10.0", "resolved": "..."}},
        }
        assert check._parse_npm_list_version(json.dumps(data), self._PACKAGE) == "0.10.0"

    def test_missing_package_returns_none(self) -> None:
        import json

        data = {"name": "x", "dependencies": {}}
        assert check._parse_npm_list_version(json.dumps(data), self._PACKAGE) is None

    def test_malformed_json_returns_none(self) -> None:
        assert check._parse_npm_list_version("not json", self._PACKAGE) is None

    def test_empty_output_returns_none(self) -> None:
        assert check._parse_npm_list_version("", self._PACKAGE) is None

    def test_prerelease_version_parsed(self) -> None:
        import json

        data = {
            "name": "x",
            "dependencies": {self._PACKAGE: {"version": "0.10.0-alpha.1"}},
        }
        assert check._parse_npm_list_version(json.dumps(data), self._PACKAGE) == "0.10.0-alpha.1"


# ---------------------------------------------------------------------------
# _parse_go_list_version
# ---------------------------------------------------------------------------


class TestParseGoListVersion:
    def test_parses_module_version(self) -> None:
        output = f"{check.GO_MODULE} v0.12.0\n"
        assert check._parse_go_list_version(output) == "0.12.0"

    def test_strips_leading_v(self) -> None:
        # _parse_go_list_version returns the raw group (with 'v' stripped by regex).
        output = f"{check.GO_MODULE} v1.0.0\n"
        result = check._parse_go_list_version(output)
        # The regex captures after 'v', so the result should not start with 'v'.
        assert result is not None
        assert not result.startswith("v")

    def test_unrelated_module_returns_none(self) -> None:
        output = "github.com/some/other v1.0.0\n"
        assert check._parse_go_list_version(output) is None

    def test_empty_output_returns_none(self) -> None:
        assert check._parse_go_list_version("") is None

    def test_prerelease_version_parsed(self) -> None:
        output = f"{check.GO_MODULE} v0.12.0-alpha.1\n"
        assert check._parse_go_list_version(output) == "0.12.0-alpha.1"

    def test_multiple_lines_finds_correct_module(self) -> None:
        output = (
            "example.com/release-verify v0.0.0\n"
            f"{check.GO_MODULE} v0.12.0\n"
            "golang.org/x/crypto v0.30.0\n"
        )
        assert check._parse_go_list_version(output) == "0.12.0"


# ---------------------------------------------------------------------------
# Self-runner (no pytest dependency required)
# ---------------------------------------------------------------------------


def _run_all() -> int:
    failures = 0
    suites = [
        TestAssertVersion,
        TestParsePipShowVersion,
        TestParseNpmListVersion,
        TestParseGoListVersion,
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
