"""Pin the Python taxonomy against the spec's canonical action-types.json."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from obsigna.taxonomy.actions import ALL_ACTIONS, get_action_type, resolve_action_type

SPEC_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "spec"
    / "spec"
    / "taxonomy"
    / "action-types.json"
)

# The Python SDK implements the filesystem, system and network domains
# (matching the Go SDK); data is partially implemented and checked by the
# reverse test.
IMPLEMENTED_DOMAINS = ("filesystem", "system", "network")

VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}


def _load_spec() -> dict[str, dict[str, list[dict[str, str]]]]:
    data: dict[str, dict[str, dict[str, list[dict[str, str]]]]] = json.loads(
        SPEC_PATH.read_text(encoding="utf-8")
    )
    return data["domains"]


SPEC_DOMAINS = _load_spec()

IMPLEMENTED_SPEC_ACTIONS = [
    action
    for domain in IMPLEMENTED_DOMAINS
    for action in SPEC_DOMAINS.get(domain, {}).get("actions", [])
]


def _is_spec_tracked(action_type: str) -> bool:
    # "unknown" is the SDK fallback entry; doctor.* types classify daemon/CLI
    # self-checks rather than agent tool calls. Neither is in the spec.
    return action_type != "unknown" and not action_type.startswith("doctor.")


@pytest.mark.parametrize("domain", IMPLEMENTED_DOMAINS)
def test_spec_defines_implemented_domain(domain: str) -> None:
    assert domain in SPEC_DOMAINS


@pytest.mark.parametrize(
    "spec_action", IMPLEMENTED_SPEC_ACTIONS, ids=lambda a: a["type"]
)
def test_taxonomy_matches_spec(spec_action: dict[str, str]) -> None:
    entry = get_action_type(spec_action["type"])
    assert entry is not None, f"Python SDK missing {spec_action['type']}"
    assert entry.description == spec_action["description"]
    assert entry.risk_level == spec_action["risk_level"]


def test_all_sdk_actions_exist_in_spec() -> None:
    spec_types = {
        action["type"]
        for domain in SPEC_DOMAINS.values()
        for action in domain["actions"]
    }
    extra = [
        a.type
        for a in ALL_ACTIONS
        if _is_spec_tracked(a.type) and a.type not in spec_types
    ]
    assert extra == []


def test_spec_risk_levels_are_valid() -> None:
    for domain in SPEC_DOMAINS.values():
        for action in domain["actions"]:
            assert action["risk_level"] in VALID_RISK_LEVELS, action["type"]


class TestPreviouslyMissingActionTypes:
    def test_filesystem_directory_list_is_low(self) -> None:
        entry = resolve_action_type("filesystem.directory.list")
        assert entry.type == "filesystem.directory.list"
        assert entry.description == "List directory contents"
        assert entry.risk_level == "low"

    def test_system_code_execute_is_high(self) -> None:
        entry = resolve_action_type("system.code.execute")
        assert entry.type == "system.code.execute"
        assert entry.risk_level == "high"

    def test_system_pty_open_is_critical(self) -> None:
        entry = resolve_action_type("system.pty.open")
        assert entry.type == "system.pty.open"
        assert entry.risk_level == "critical"

    def test_system_pty_close_is_high(self) -> None:
        entry = resolve_action_type("system.pty.close")
        assert entry.type == "system.pty.close"
        assert entry.risk_level == "high"

    def test_network_egress_observed_is_not_unknown(self) -> None:
        entry = resolve_action_type("network.egress.observed")
        assert entry.type == "network.egress.observed"
        assert (
            entry.description
            == "Observed outbound network connection crossing a sandbox boundary"
        )
        assert entry.risk_level == "medium"
