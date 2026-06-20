"""Tests for the grounded-principal conformance tier (ADR-0038)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from obsigna.receipt.grant_resolver import (
    GrantInfo,
    GrantResolver,
    GroundedOutcome,
    GroundedPrincipalViolation,
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
    now = datetime.now(UTC)
    g = GrantInfo(
        subject="did:user:alice",
        scopes=["files:write"],
        issued_at=now,
        expires_at=now,
        issuer="https://auth.example.com",
    )
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
    violations = verify_grounded_principal_tier([r], resolver)
    assert len(violations) == 1
    assert violations[0].outcome == GroundedOutcome.UNGROUNDED_PRINCIPAL


def test_high_with_empty_grant_ref_is_ungrounded() -> None:
    resolver = StubResolver({})
    r = _make_grounded_receipt("did:user:alice", "high", "")
    violations = verify_grounded_principal_tier([r], resolver)
    assert len(violations) == 1
    assert violations[0].outcome == GroundedOutcome.UNGROUNDED_PRINCIPAL


def test_resolution_failure_is_ungrounded() -> None:
    resolver = StubResolver({}, error_refs={"bad-ref"})
    r = _make_grounded_receipt("did:user:alice", "high", "bad-ref")
    violations = verify_grounded_principal_tier([r], resolver)
    assert len(violations) == 1
    assert violations[0].outcome == GroundedOutcome.UNGROUNDED_PRINCIPAL


def test_subject_mismatch_is_principal_grant_mismatch() -> None:
    resolver = StubResolver(
        {"grant-abc": GrantInfo(subject="did:user:bob", scopes=["files:write"])}
    )
    r = _make_grounded_receipt("did:user:alice", "high", "grant-abc")
    violations = verify_grounded_principal_tier([r], resolver)
    assert len(violations) == 1
    assert violations[0].outcome == GroundedOutcome.PRINCIPAL_GRANT_MISMATCH


def test_valid_grounding_produces_no_violation() -> None:
    resolver = StubResolver(
        {"grant-xyz": GrantInfo(subject="did:user:alice", scopes=["files:write"])}
    )
    r = _make_grounded_receipt("did:user:alice", "high", "grant-xyz")
    assert verify_grounded_principal_tier([r], resolver) == []


def test_critical_receipts_also_checked() -> None:
    resolver = StubResolver({})
    r = _make_grounded_receipt("did:user:alice", "critical", None)
    violations = verify_grounded_principal_tier([r], resolver)
    assert len(violations) == 1
    assert violations[0].outcome == GroundedOutcome.UNGROUNDED_PRINCIPAL


def test_all_violations_collected() -> None:
    resolver = StubResolver(
        {"grant-good": GrantInfo(subject="did:user:alice", scopes=[])},
        error_refs={"grant-bad"},
    )
    r1 = _make_grounded_receipt("did:user:alice", "high", None)  # UNGROUNDED
    r2 = _make_grounded_receipt("did:user:alice", "high", "grant-good")  # OK
    r3 = _make_grounded_receipt("did:user:alice", "critical", "grant-bad")  # UNGROUNDED
    violations = verify_grounded_principal_tier([r1, r2, r3], resolver)
    assert len(violations) == 2


def test_violation_reports_correct_index() -> None:
    resolver = StubResolver({})
    low = _make_grounded_receipt("did:user:alice", "low", None)  # index 0, skipped
    high = _make_grounded_receipt("did:user:alice", "high", None)  # index 1, violation
    violations = verify_grounded_principal_tier([low, high], resolver)
    assert len(violations) == 1
    assert violations[0].index == 1


def test_empty_receipts_returns_no_violations() -> None:
    resolver = StubResolver({})
    assert verify_grounded_principal_tier([], resolver) == []


def test_grounded_principal_violation_fields() -> None:
    v = GroundedPrincipalViolation(
        index=0,
        receipt_id="urn:receipt:00000000-0000-0000-0000-000000000001",
        principal_id="did:user:alice",
        grant_ref="grant-abc",
        outcome=GroundedOutcome.UNGROUNDED_PRINCIPAL,
        detail="authorization.grant_ref is absent on a high receipt",
    )
    assert v.index == 0
    assert v.outcome == GroundedOutcome.UNGROUNDED_PRINCIPAL
