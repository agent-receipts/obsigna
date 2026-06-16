"""Tests for taxonomy action types."""

from __future__ import annotations

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
        assert len(FILESYSTEM_ACTIONS) == 7

    def test_system_actions_count(self) -> None:
        assert len(SYSTEM_ACTIONS) == 7

    def test_all_actions_count(self) -> None:
        assert len(ALL_ACTIONS) == 18


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


class TestResolveActionType:
    def test_resolve_action_type_found(self) -> None:
        entry = resolve_action_type("system.command.execute")
        assert entry.type == "system.command.execute"
        assert entry.risk_level == "high"

    def test_resolve_action_type_unknown_falls_back(self) -> None:
        entry = resolve_action_type("nonexistent.action")
        assert entry.type == "unknown"
        assert entry.risk_level == "medium"
