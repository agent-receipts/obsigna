"""Data-driven conformance runner for the shared emit failure contract vector.

Loads ``cross-sdk-tests/emit_failure_vectors.json`` (ADR-0025), iterates every
case, runs it against ``DaemonEmitter`` (default mode, no listener), maps the
outcome to an outcome category, and asserts it matches ``expect``. The vector
is the single source of truth for which cases exist: this runner fails on any
case name it does not handle, so adding a case to the JSON breaks this SDK
until it is implemented here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from obsigna.daemon_emitter import DaemonEmitter, EmitTransportError

if TYPE_CHECKING:
    from collections.abc import Callable

_VECTOR_PATH = (
    Path(__file__).parent.parent.parent.parent
    / "cross-sdk-tests"
    / "emit_failure_vectors.json"
)


def _load_cases() -> list[dict[str, str]]:
    data = json.loads(_VECTOR_PATH.read_text())
    cases = data["cases"]
    assert cases, "emit_failure_vectors.json has no cases"
    return cases


def _classify(emit_call: Callable[[], object]) -> str:
    """Map an emit outcome to an outcome category.

    Transport failures raise EmitTransportError (ADR-0025); caller bugs raise
    ValueError/RuntimeError. The two are distinct types, so the contract's
    distinguishability requirement holds without string matching.
    """
    try:
        emit_call()
    except EmitTransportError:
        return "transport_error"
    except (ValueError, RuntimeError):
        return "caller_error"
    return "success"


@pytest.mark.parametrize("case", _load_cases(), ids=lambda c: c["name"])
def test_emit_failure_contract_vector(case: dict[str, str], tmp_path: Path) -> None:
    name = case["name"]
    if name == "dial_failure_unreachable_socket":
        decision = "allowed"
    elif name == "caller_bug_invalid_decision":
        decision = "bogus"
    else:
        pytest.fail(
            f"unhandled emit-failure case {name!r}: "
            "implement it or remove it from the vector"
        )

    # Default mode (no best_effort) against a socket with no listener.
    with DaemonEmitter(
        socket_path=str(tmp_path / "missing.sock"), session_id="vec"
    ) as e:
        got = _classify(
            lambda: e.emit(channel="sdk", tool_name="noop", decision=decision)
        )
    assert got == case["expect"], (
        f"case {name!r}: outcome {got!r}, want {case['expect']!r}"
    )
