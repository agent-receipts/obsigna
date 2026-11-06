"""Pin the built-in taxonomy against the spec's canonical action-types.json.

Mirrors sdk/go/taxonomy/spec_test.go. risk_level is a signed receipt field,
so any drift here changes signed audit records.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from obsigna.taxonomy.actions import (
    ALL_ACTIONS,
    get_action_type,
    resolve_action_type,
)

_SPEC_PATH = (
    Path(__file__).resolve().parents[4]
    / "spec"
    / "spec"
    / "taxonomy"
    / "action-types.json"
)

_IMPLEMENTED_DOMAINS = ("filesystem", "system", "network")
_IMPLEMENTED_DATA_ACTIONS = ("data.api.read", "data.api.write", "data.api.delete")


def _load_spec() -> dict[str, dict[str, list[dict[str, str]]]]:
    with _SPEC_PATH.open(encoding="utf-8") as f:
        data: dict[str, dict[str, dict[str, list[dict[str, str]]]]] = json.load(f)
    return data["domains"]


def _implemented_spec_actions() -> list[dict[str, str]]:
    domains = _load_spec()
    actions: list[dict[str, str]] = []
    for name in _IMPLEMENTED_DOMAINS:
        actions.extend(domains[name]["actions"])
    actions.extend(
        a for a in domains["data"]["actions"] if a["type"] in _IMPLEMENTED_DATA_ACTIONS
    )
    return actions


_SPEC_ACTIONS = _implemented_spec_actions()


def test_implemented_spec_actions_cover_expected_types() -> None:
    types = {a["type"] for a in _SPEC_ACTIONS}
    assert set(_IMPLEMENTED_DATA_ACTIONS) <= types
    assert "network.egress.observed" in types


@pytest.mark.parametrize(
    "spec_action", _SPEC_ACTIONS, ids=[a["type"] for a in _SPEC_ACTIONS]
)
def test_spec_action_matches_sdk(spec_action: dict[str, str]) -> None:
    entry = get_action_type(spec_action["type"])
    assert entry is not None, f"Python SDK missing action type {spec_action['type']}"
    assert entry.description == spec_action["description"]
    assert entry.risk_level == spec_action["risk_level"]


def test_all_sdk_actions_exist_in_spec() -> None:
    spec_types = {
        a["type"] for domain in _load_spec().values() for a in domain["actions"]
    }
    missing = [
        a.type for a in ALL_ACTIONS if a.type != "unknown" and a.type not in spec_types
    ]
    assert missing == []


@pytest.mark.parametrize(
    ("action_type", "description", "risk_level"),
    [
        ("filesystem.directory.list", "List directory contents", "low"),
        ("system.code.execute", "Execute code in a sandbox code interpreter", "high"),
        ("system.pty.open", "Open an interactive PTY session", "critical"),
        ("system.pty.close", "Close a PTY session", "high"),
        (
            "network.egress.observed",
            "Observed outbound network connection crossing a sandbox boundary",
            "medium",
        ),
    ],
)
def test_new_action_types_resolve_to_spec_risk(
    action_type: str, description: str, risk_level: str
) -> None:
    entry = resolve_action_type(action_type)
    assert entry.type == action_type
    assert entry.description == description
    assert entry.risk_level == risk_level
