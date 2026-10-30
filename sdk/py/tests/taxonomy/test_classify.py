"""Tests for tool call classification."""

from __future__ import annotations

import pytest

from obsigna.taxonomy.classify import classify_tool_call
from obsigna.taxonomy.types import TaxonomyMapping


class TestClassifyToolCall:
    def test_classify_no_mappings_returns_unknown(self) -> None:
        result = classify_tool_call("some_tool")
        assert result.action_type == "unknown"
        assert result.risk_level == "medium"

    def test_classify_with_mapping(self) -> None:
        mappings = [
            TaxonomyMapping(
                tool_name="write_file",
                action_type="filesystem.file.create",
            ),
        ]
        result = classify_tool_call("write_file", mappings=mappings)
        assert result.action_type == "filesystem.file.create"
        assert result.risk_level == "low"

    def test_classify_mapping_not_found_returns_unknown(self) -> None:
        mappings = [
            TaxonomyMapping(
                tool_name="write_file",
                action_type="filesystem.file.create",
            ),
        ]
        result = classify_tool_call("other_tool", mappings=mappings)
        assert result.action_type == "unknown"
        assert result.risk_level == "medium"

    @pytest.mark.parametrize(
        ("tool_name", "action_type", "risk_level"),
        [
            ("list_dir", "filesystem.directory.list", "low"),
            ("run_code", "system.code.execute", "high"),
            ("open_pty", "system.pty.open", "critical"),
            ("close_pty", "system.pty.close", "high"),
            ("egress", "network.egress.observed", "medium"),
        ],
    )
    def test_classify_spec_parity_action_types(
        self, tool_name: str, action_type: str, risk_level: str
    ) -> None:
        mappings = [TaxonomyMapping(tool_name=tool_name, action_type=action_type)]
        result = classify_tool_call(tool_name, mappings=mappings)
        assert result.action_type == action_type
        assert result.risk_level == risk_level

    def test_classify_with_empty_mappings(self) -> None:
        result = classify_tool_call("some_tool", mappings=[])
        assert result.action_type == "unknown"
        assert result.risk_level == "medium"
