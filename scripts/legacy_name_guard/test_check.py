"""Unit tests for the legacy package-name guard.

The guard must FAIL (return 1) when a legacy SDK distribution / install / import
name reappears in a gated file, and must NOT fire on the adjacent identifiers
that are deliberately out of scope (GitHub org / Go module path, daemon CLI
command and binary, protocol identifiers, the @agnt-rcpt/openclaw package).

Run with:
    python3 -m pytest scripts/legacy_name_guard/test_check.py
    python3 scripts/legacy_name_guard/test_check.py   # quick self-check
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))

import check  # noqa: E402

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestForbiddenForms:
    """Every legacy distribution / install / import form must be flagged."""

    def test_npm_scope(self) -> None:
        assert check.scan_text('import x from "@agnt-rcpt/sdk-ts";')

    def test_npm_scope_aws(self) -> None:
        assert check.scan_text('import x from "@agnt-rcpt/sdk-ts-aws";')

    def test_pip_install(self) -> None:
        assert check.scan_text("pip install agent-receipts")

    def test_pip_install_quoted_extra(self) -> None:
        assert check.scan_text('pip install "agent-receipts[aws]"')

    def test_pinned_install(self) -> None:
        assert check.scan_text("agent-receipts==0.12.0")

    def test_pypi_link(self) -> None:
        assert check.scan_text("https://pypi.org/project/agent-receipts/")

    def test_pypi_badge(self) -> None:
        assert check.scan_text("https://img.shields.io/pypi/v/agent-receipts")

    def test_manifest_name(self) -> None:
        assert check.scan_text('name = "agent-receipts"')

    def test_readme_title(self) -> None:
        assert check.scan_text("# agent-receipts")

    def test_python_import(self) -> None:
        assert check.scan_text("from agent_receipts import create_receipt")
        assert check.scan_text("import agent_receipts")

    def test_python_submodule_import(self) -> None:
        assert check.scan_text("from agent_receipts.aws import KMSSigner")

    def test_python_package_dir(self) -> None:
        assert check.scan_text("packages = [\"src/agent_receipts\"]")


class TestPreservedForms:
    """Out-of-scope identifiers must NOT be flagged."""

    def test_github_org_path(self) -> None:
        assert not check.scan_text("https://github.com/agent-receipts/obsigna")

    def test_go_module_path(self) -> None:
        assert not check.scan_text("go get github.com/agent-receipts/ar/sdk/go")

    def test_repo_ref(self) -> None:
        assert not check.scan_text("| [agent-receipts/sdk-py](https://x) | y |")

    def test_daemon_cli_command(self) -> None:
        assert not check.scan_text("Confirm receipts with `agent-receipts verify`.")

    def test_daemon_binary(self) -> None:
        assert not check.scan_text("agent-receipts-daemon --init")

    def test_daemon_socket_dir(self) -> None:
        assert not check.scan_text("~/.local/share/agent-receipts/receipts.db")

    def test_protocol_identifier(self) -> None:
        assert not check.scan_text('action.type == "agent_receipts.events_dropped"')

    def test_openclaw_package(self) -> None:
        assert not check.scan_text('"@agnt-rcpt/openclaw"')

    def test_renamed_forms_are_clean(self) -> None:
        assert not check.scan_text("pip install obsigna")
        assert not check.scan_text('import x from "@obsigna/sdk-ts";')
        assert not check.scan_text("from obsigna import create_receipt")


class TestMain:
    """End-to-end exit-code behaviour."""

    def _write(self, dirpath: str, rel: str, body: str) -> None:
        full = os.path.join(dirpath, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(body)

    def test_clean_file_passes(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ok.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("pip install obsigna\nfrom obsigna import x\n")
            assert check.main([path]) == 0

    def test_dirty_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("pip install agent-receipts\n")
            assert check.main([path]) == 1

    def test_real_tree_is_clean(self) -> None:
        # The committed tree must pass the guard.
        assert check.main(["--root", _REPO_ROOT]) == 0


def _run_all() -> int:
    failures = 0
    suites = [TestForbiddenForms, TestPreservedForms, TestMain]
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
