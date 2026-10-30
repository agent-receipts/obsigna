"""Spec parity tests for the taxonomy.

Asserts the Python SDK's built-in action types against the spec's canonical
``spec/spec/taxonomy/action-types.json``, mirroring
``sdk/go/taxonomy/spec_test.go`` so all SDKs sign the same ``risk_level`` for
the same action type.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from obsigna.taxonomy.actions import ALL_ACTIONS, get_action_type

REPO_ROOT = Path(__file__).resolve().parents[4]
SPEC_PATH = REPO_ROOT / "spec" / "spec" / "taxonomy" / "action-types.json"

# Domains the SDK implements; must match sdk/go/taxonomy/spec_test.go.
IMPLEMENTED_DOMAINS = ("filesystem", "system", "network")


def _load_spec() -> dict[str, dict[str, list[dict[str, str]]]]:
    with open(SPEC_PATH) as f:
        data: dict[str, dict[str, dict[str, list[dict[str, str]]]]] = json.load(f)
    return data["domains"]


SPEC_DOMAINS = _load_spec()

IMPLEMENTED_SPEC_ACTIONS = [
    action
    for domain in IMPLEMENTED_DOMAINS
    for action in SPEC_DOMAINS.get(domain, {}).get("actions", [])
]


@pytest.mark.parametrize("domain", IMPLEMENTED_DOMAINS)
def test_spec_has_implemented_domain(domain: str) -> None:
    assert domain in SPEC_DOMAINS


@pytest.mark.parametrize(
    "spec_action",
    IMPLEMENTED_SPEC_ACTIONS,
    ids=[a["type"] for a in IMPLEMENTED_SPEC_ACTIONS],
)
def test_taxonomy_matches_spec(spec_action: dict[str, str]) -> None:
    entry = get_action_type(spec_action["type"])
    assert entry is not None, f"Python SDK missing action type {spec_action['type']!r}"
    assert entry.description == spec_action["description"]
    assert entry.risk_level == spec_action["risk_level"]


def test_all_sdk_actions_exist_in_spec() -> None:
    spec_types = {
        action["type"]
        for domain in SPEC_DOMAINS.values()
        for action in domain["actions"]
    }
    # "unknown" is the SDK fallback and doctor.* types classify a daemon/CLI
    # self-check rather than an agent tool call; neither is in the spec.
    missing = [
        entry.type
        for entry in ALL_ACTIONS
        if entry.type != "unknown"
        and not entry.type.startswith("doctor.")
        and entry.type not in spec_types
    ]
    assert missing == []


def test_spec_risk_levels_are_valid() -> None:
    for domain in SPEC_DOMAINS.values():
        for action in domain["actions"]:
            assert action["risk_level"] in {"low", "medium", "high", "critical"}
