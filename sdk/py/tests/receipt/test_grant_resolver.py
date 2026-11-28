"""Tests for the grounded-principal conformance tier (ADR-0038)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from obsigna.receipt.grant_resolver import (
    GrantInfo,
    GrantResolver,
    GroundedOutcome,
    GroundedResult,
    Revocation,
    verify_grounded_principal_tier,
)
from obsigna.receipt.signing import generate_key_pair, sign_receipt
from obsigna.receipt.types import (
    Action,
    Authorization,
    Chain,
    CredentialSubject,
    Issuer,
    Outcome,
    Principal,
    UnsignedAgentReceipt,
)

if TYPE_CHECKING:
    from obsigna.receipt.types import AgentReceipt, RiskLevel


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_grounded_receipt(
    principal_id: str,
    risk_level: RiskLevel,
    grant_ref: str | None,
) -> AgentReceipt:
    kp = generate_key_pair()
    now = datetime.now(UTC).isoformat()
    auth: Authorization | None = None
    if grant_ref is not None:
        auth = Authorization(
            scopes=["files:write"],
            granted_at=now,
            grant_ref=grant_ref,
        )
    unsigned = UnsignedAgentReceipt(
        **{
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://agentreceipts.ai/context/v2",
            ],
            "id": "urn:receipt:00000000-0000-0000-0000-000000000001",
            "type": ["VerifiableCredential", "AgentReceipt"],
            "version": "0.5.0",
            "issuer": Issuer(id="did:key:z6Mk1"),
            "issuanceDate": now,
            "credentialSubject": CredentialSubject(
                principal=Principal(id=principal_id),
                action=Action(
                    id="act_00000000-0000-0000-0000-000000000001",
                    type="filesystem.file.write",
                    risk_level=risk_level,
                    timestamp=now,
                ),
                outcome=Outcome(status="success"),
                authorization=auth,
                chain=Chain(
                    sequence=1,
                    previous_receipt_hash=None,
                    chain_id="chain-grounded-1",
                ),
            ),
        }
    )
    return sign_receipt(unsigned, kp.private_key, "did:key:z6Mk1#key-1")


def _valid_grant(subject: str) -> GrantInfo:
    """A well-formed grant for *subject*, in force around now."""
    now = datetime.now(UTC)
    return GrantInfo(
        subject=subject,
        scopes=["files:write"],
        valid_from=now - timedelta(hours=1),
        expires_at=now + timedelta(hours=1),
        revocation=Revocation.NOT_REVOKED,
        issuer="https://auth.example.com",
    )


def _failures(results: list[GroundedResult]) -> list[GroundedResult]:
    """The results that are not grounded."""
    return [r for r in results if not r.grounded]


class StubResolver(GrantResolver):
    """Test double: returns pre-configured grants or raises on error refs."""

    def __init__(
        self,
        grants: dict[str, GrantInfo],
        error_refs: set[str] | None = None,
    ) -> None:
        self._grants = grants
        self._error_refs: set[str] = error_refs or set()

    def resolve_grant(self, grant_ref: str, _principal_id: str) -> GrantInfo:
        if grant_ref in self._error_refs:
            raise ValueError("resolver: grant not found")
        if grant_ref in self._grants:
            return self._grants[grant_ref]
        raise ValueError("resolver: unknown grant ref")


# ---------------------------------------------------------------------------
# GrantInfo field coverage
# ---------------------------------------------------------------------------


def test_grant_info_fields() -> None:
    g = _valid_grant("did:user:alice")
    assert g.subject == "did:user:alice"
    assert g.scopes == ["files:write"]


# ---------------------------------------------------------------------------
# verify_grounded_principal_tier
# ---------------------------------------------------------------------------


def test_no_resolver_returns_no_violations() -> None:
    r = _make_grounded_receipt("did:user:alice", "high", None)
    assert verify_grounded_principal_tier([r], None) == []


def test_low_medium_receipts_skipped() -> None:
    resolver = StubResolver({})
    low = _make_grounded_receipt("did:user:alice", "low", None)
    med = _make_grounded_receipt("did:user:alice", "medium", None)
    assert verify_grounded_principal_tier([low, med], resolver) == []


def test_high_without_grant_ref_is_ungrounded() -> None:
    resolver = StubResolver({})
    r = _make_grounded_receipt("did:user:alice", "high", None)
    violations = _failures(verify_grounded_principal_tier([r], resolver))
    assert len(violations) == 1
    assert violations[0].outcome == GroundedOutcome.UNGROUNDED_PRINCIPAL


def test_high_with_empty_grant_ref_is_ungrounded() -> None:
    resolver = StubResolver({})
    r = _make_grounded_receipt("did:user:alice", "high", "")
    violations = _failures(verify_grounded_principal_tier([r], resolver))
    assert len(violations) == 1
    assert violations[0].outcome == GroundedOutcome.UNGROUNDED_PRINCIPAL


def test_resolution_failure_is_ungrounded() -> None:
    resolver = StubResolver({}, error_refs={"bad-ref"})
    r = _make_grounded_receipt("did:user:alice", "high", "bad-ref")
    violations = _failures(verify_grounded_principal_tier([r], resolver))
    assert len(violations) == 1
    assert violations[0].outcome == GroundedOutcome.UNGROUNDED_PRINCIPAL


def test_subject_mismatch_is_principal_grant_mismatch() -> None:
    resolver = StubResolver({"grant-abc": _valid_grant("did:user:bob")})
    r = _make_grounded_receipt("did:user:alice", "high", "grant-abc")
    violations = _failures(verify_grounded_principal_tier([r], resolver))
    assert len(violations) == 1
    assert violations[0].outcome == GroundedOutcome.PRINCIPAL_GRANT_MISMATCH


def test_valid_grounding_produces_no_violation() -> None:
    resolver = StubResolver({"grant-xyz": _valid_grant("did:user:alice")})
    r = _make_grounded_receipt("did:user:alice", "high", "grant-xyz")
    [result] = verify_grounded_principal_tier([r], resolver)
    assert result.grounded
    assert "issuer-asserted action time" in result.detail


def test_critical_receipts_also_checked() -> None:
    resolver = StubResolver({})
    r = _make_grounded_receipt("did:user:alice", "critical", None)
    violations = _failures(verify_grounded_principal_tier([r], resolver))
    assert len(violations) == 1
    assert violations[0].outcome == GroundedOutcome.UNGROUNDED_PRINCIPAL


def test_all_violations_collected() -> None:
    resolver = StubResolver(
        {"grant-good": _valid_grant("did:user:alice")},
        error_refs={"grant-bad"},
    )
    r1 = _make_grounded_receipt("did:user:alice", "high", None)  # UNGROUNDED
    r2 = _make_grounded_receipt("did:user:alice", "high", "grant-good")  # OK
    r3 = _make_grounded_receipt("did:user:alice", "critical", "grant-bad")  # UNGROUNDED
    results = verify_grounded_principal_tier([r1, r2, r3], resolver)
    assert len(results) == 3
    assert len(_failures(results)) == 2


def test_violation_reports_correct_index() -> None:
    resolver = StubResolver({})
    low = _make_grounded_receipt("did:user:alice", "low", None)  # index 0, skipped
    high = _make_grounded_receipt("did:user:alice", "high", None)  # index 1, violation
    violations = _failures(verify_grounded_principal_tier([low, high], resolver))
    assert len(violations) == 1
    assert violations[0].index == 1


def test_empty_receipts_returns_no_violations() -> None:
    resolver = StubResolver({})
    assert verify_grounded_principal_tier([], resolver) == []


def test_grounded_result_fields() -> None:
    v = GroundedResult(
        index=0,
        receipt_id="urn:receipt:00000000-0000-0000-0000-000000000001",
        principal_id="did:user:alice",
        grant_ref="grant-abc",
        outcome=GroundedOutcome.UNGROUNDED_PRINCIPAL,
        detail="authorization.grant_ref is absent on a high receipt",
    )
    assert v.index == 0
    assert v.outcome == GroundedOutcome.UNGROUNDED_PRINCIPAL
    assert not v.grounded
    assert v.warnings == []


def test_negative_clock_skew_rejected_without_resolver() -> None:
    with pytest.raises(ValueError, match="clock_skew_ms"):
        verify_grounded_principal_tier([], None, clock_skew_ms=-1)


class _LooseResolver(GrantResolver):
    """Returns whatever it was given, as a resolver without type checking might."""

    def __init__(self, value: object) -> None:
        self._value = value

    def resolve_grant(self, grant_ref: str, principal_id: str) -> GrantInfo:
        return self._value  # type: ignore[return-value]


@pytest.mark.parametrize("value", [None, {"subject": "did:user:alice"}, "grant"])
def test_non_grant_return_is_ungrounded(value: object) -> None:
    r = _make_grounded_receipt("did:user:alice", "high", "grant-xyz")
    [result] = verify_grounded_principal_tier([r], _LooseResolver(value))
    assert result.outcome == GroundedOutcome.UNGROUNDED_PRINCIPAL


def test_string_scopes_are_malformed_not_substring_matched() -> None:
    grant = _valid_grant("did:user:alice")
    loose = GrantInfo(
        subject=grant.subject,
        scopes="files:write",  # type: ignore[arg-type]
        valid_from=grant.valid_from,
        revocation=grant.revocation,
        issuer=grant.issuer,
        expires_at=grant.expires_at,
    )
    r = _make_grounded_receipt("did:user:alice", "high", "grant-xyz")
    [result] = verify_grounded_principal_tier([r], _LooseResolver(loose))
    assert result.outcome == GroundedOutcome.UNGROUNDED_PRINCIPAL


@pytest.mark.parametrize("skew", [float("nan"), float("inf"), True, "5"])
def test_invalid_clock_skew_rejected(skew: object) -> None:
    with pytest.raises(ValueError, match="clock_skew_ms"):
        verify_grounded_principal_tier([], None, clock_skew_ms=skew)  # type: ignore[arg-type]


def test_fractional_clock_skew_is_accepted() -> None:
    assert verify_grounded_principal_tier([], StubResolver({}), clock_skew_ms=1.9) == []
