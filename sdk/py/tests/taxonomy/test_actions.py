"""Tests for taxonomy action types."""

from __future__ import annotations

import pytest

from obsigna.taxonomy.actions import (
    ALL_ACTIONS,
    FILESYSTEM_ACTIONS,
    SYSTEM_ACTIONS,
    UNKNOWN_ACTION,
    get_action_type,
    resolve_action_type,
)


class TestActionCounts:
    def test_filesystem_actions_count(self) -> None:
        assert len(FILESYSTEM_ACTIONS) == 8

    def test_system_actions_count(self) -> None:
        assert len(SYSTEM_ACTIONS) == 10

    def test_all_actions_count(self) -> None:
        # filesystem + system + network + data + unknown
        assert len(ALL_ACTIONS) == 23


class TestUnknownAction:
    def test_unknown_action_is_medium_risk(self) -> None:
        assert UNKNOWN_ACTION.risk_level == "medium"
        assert UNKNOWN_ACTION.type == "unknown"


class TestGetActionType:
    def test_get_action_type_found(self) -> None:
        entry = get_action_type("filesystem.file.create")
        assert entry is not None
        assert entry.type == "filesystem.file.create"
        assert entry.risk_level == "low"

    def test_get_action_type_not_found_returns_none(self) -> None:
        assert get_action_type("nonexistent.action") is None

    @pytest.mark.parametrize(
        ("action_type", "risk_level"),
        [
            ("filesystem.directory.list", "low"),
            ("system.code.execute", "high"),
            ("system.pty.open", "critical"),
            ("system.pty.close", "high"),
            ("network.egress.observed", "medium"),
        ],
    )
    def test_get_action_type_spec_parity(
        self, action_type: str, risk_level: str
    ) -> None:
        entry = get_action_type(action_type)
        assert entry is not None
        assert entry.type == action_type
        assert entry.risk_level == risk_level


class TestResolveActionType:
    def test_resolve_action_type_found(self) -> None:
        entry = resolve_action_type("system.command.execute")
        assert entry.type == "system.command.execute"
        assert entry.risk_level == "high"

    def test_resolve_action_type_unknown_falls_back(self) -> None:
        entry = resolve_action_type("nonexistent.action")
        assert entry.type == "unknown"
        assert entry.risk_level == "medium"
