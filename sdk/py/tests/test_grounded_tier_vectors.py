"""Cross-SDK grounded-tier corpus (spec v0.7.0 §7.9, ADR-0041).

Loads ``cross-sdk-tests/grounded_tier_vectors.json``. The Go and TypeScript
SDKs run the same file; all three must agree on every case.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from obsigna.receipt.grant_resolver import (
    GrantInfo,
    GrantResolver,
    verify_grounded_principal_tier,
)
from obsigna.receipt.types import AgentReceipt

_CORPUS = (
    Path(__file__).parent.parent.parent.parent
    / "cross-sdk-tests"
    / "grounded_tier_vectors.json"
)
_CASES: list[dict[str, Any]] = json.loads(_CORPUS.read_text())["cases"]


def _time(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


def _grant(g: dict[str, Any]) -> GrantInfo:
    # The corpus is untyped JSON. Missing required fields stay missing (None)
    # and invalid values stay invalid, so the malformed-grant cases reach the
    # verifier as a loosely typed resolver could send them.
    fields: dict[str, Any] = {
        "subject": g.get("subject"),
        "scopes": g.get("scopes"),
        "valid_from": _time(g.get("valid_from")),
        "revocation": g.get("revocation"),
        "issuer": g.get("issuer"),
        "expires_at": _time(g.get("expires_at")),
        "revoked_at": _time(g.get("revoked_at")),
    }
    return GrantInfo(**fields)


def _receipt(case: dict[str, Any]) -> AgentReceipt:
    r = case["receipt"]
    subject: dict[str, Any] = {
        "principal": {"id": r["principal_id"]},
        "action": {
            "id": "act_00000000-0000-0000-0000-000000000001",
            "type": "filesystem.file.write",
            "risk_level": r["risk_level"],
            "timestamp": r["action_timestamp"],
        },
        "outcome": {"status": "success"},
        "chain": {"sequence": 1, "previous_receipt_hash": None, "chain_id": "chain-1"},
    }
    if r["authorization"] is not None:
        subject["authorization"] = r["authorization"]
    return AgentReceipt.model_validate(
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://agentreceipts.ai/context/v3",
            ],
            "id": f"urn:receipt:{case['name']}",
            "type": ["VerifiableCredential", "AgentReceipt"],
            "version": "0.6.0",
            "issuer": {"id": "did:key:z6Mk1"},
            "issuanceDate": r["action_timestamp"],
            "credentialSubject": subject,
            "proof": {
                "type": "Ed25519Signature2020",
                "created": r["action_timestamp"],
                "verificationMethod": "did:key:z6Mk1#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": "u",
            },
        }
    )


class _CorpusResolver(GrantResolver):
    def __init__(self, case: dict[str, Any]) -> None:
        self._resolver: dict[str, Any] = case["resolver"]

    def resolve_grant(self, grant_ref: str, principal_id: str) -> GrantInfo:
        if "error" in self._resolver:
            raise LookupError(self._resolver["error"])
        return _grant(self._resolver["grant"])


def test_corpus_has_cases() -> None:
    assert _CASES


@pytest.mark.parametrize("case", _CASES, ids=[c["name"] for c in _CASES])
def test_grounded_tier_vector(case: dict[str, Any]) -> None:
    expected = case["expected"]
    receipts = [_receipt(case)]
    resolver = _CorpusResolver(case)
    skew = case["clock_skew_ms"]

    if expected.get("config_error"):
        with pytest.raises(ValueError, match="clock_skew_ms"):
            verify_grounded_principal_tier(receipts, resolver, clock_skew_ms=skew)
        return

    results = verify_grounded_principal_tier(receipts, resolver, clock_skew_ms=skew)
    if not expected["checked"]:
        assert results == []
        return

    assert len(results) == 1
    result = results[0]
    want = expected["outcome"]
    got = None if result.outcome is None else str(result.outcome)
    assert got == want, result.detail
    assert result.grounded == (want is None)
    assert [str(w.code) for w in result.warnings] == expected["warnings"]
