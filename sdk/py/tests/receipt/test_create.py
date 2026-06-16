"""Tests for receipt creation."""

from obsigna.receipt.create import (
    ActionInput,
    CreateReceiptInput,
    create_receipt,
)
from obsigna.receipt.types import (
    CONTEXT,
    CREDENTIAL_TYPE,
    VERSION,
    Authorization,
    Chain,
    Delegation,
    Delegator,
    Intent,
    Issuer,
    Outcome,
    Principal,
)


def _make_input(**overrides: object) -> CreateReceiptInput:
    defaults = {
        "issuer": Issuer(id="did:agent:test"),
        "principal": Principal(id="did:user:test"),
        "action": ActionInput(
            type="filesystem.file.read",
            risk_level="low",
        ),
        "outcome": Outcome(status="success"),
        "chain": Chain(
            sequence=1,
            previous_receipt_hash=None,
            chain_id="chain_test",
        ),
    }
    defaults.update(overrides)
    return CreateReceiptInput(**defaults)  # type: ignore[arg-type]


class TestCreateReceipt:
    def test_sets_context(self) -> None:
        receipt = create_receipt(_make_input())
        assert receipt.context == list(CONTEXT)

    def test_sets_type(self) -> None:
        receipt = create_receipt(_make_input())
        assert receipt.type == list(CREDENTIAL_TYPE)

    def test_sets_version(self) -> None:
        receipt = create_receipt(_make_input())
        assert receipt.version == VERSION

    def test_generates_receipt_id(self) -> None:
        receipt = create_receipt(_make_input())
        assert receipt.id.startswith("urn:receipt:")

    def test_generates_unique_ids(self) -> None:
        r1 = create_receipt(_make_input())
        r2 = create_receipt(_make_input())
        assert r1.id != r2.id

    def test_generates_action_id(self) -> None:
        receipt = create_receipt(_make_input())
        assert receipt.credentialSubject.action.id.startswith("act_")

    def test_sets_issuance_date(self) -> None:
        receipt = create_receipt(_make_input())
        assert receipt.issuanceDate.endswith("Z")

    def test_sets_action_timestamp(self) -> None:
        receipt = create_receipt(_make_input())
        assert receipt.credentialSubject.action.timestamp.endswith("Z")

    def test_custom_action_timestamp(self) -> None:
        receipt = create_receipt(_make_input(action_timestamp="2026-01-01T00:00:00Z"))
        assert receipt.credentialSubject.action.timestamp == "2026-01-01T00:00:00Z"

    def test_passes_through_fields(self) -> None:
        receipt = create_receipt(_make_input())
        assert receipt.issuer.id == "did:agent:test"
        assert receipt.credentialSubject.principal.id == "did:user:test"
        assert receipt.credentialSubject.action.type == "filesystem.file.read"

    def test_excludes_intent_when_not_provided(self) -> None:
        receipt = create_receipt(_make_input())
        assert receipt.credentialSubject.intent is None

    def test_includes_intent_when_provided(self) -> None:
        receipt = create_receipt(
            _make_input(intent=Intent(prompt_preview="do the thing"))
        )
        assert receipt.credentialSubject.intent is not None
        assert receipt.credentialSubject.intent.prompt_preview == "do the thing"

    def test_excludes_authorization_when_not_provided(self) -> None:
        receipt = create_receipt(_make_input())
        assert receipt.credentialSubject.authorization is None

    def test_includes_authorization_when_provided(self) -> None:
        receipt = create_receipt(
            _make_input(
                authorization=Authorization(
                    scopes=["read"],
                    granted_at="2026-01-01T00:00:00Z",
                )
            )
        )
        assert receipt.credentialSubject.authorization is not None
        assert receipt.credentialSubject.authorization.scopes == ["read"]

    def test_preserves_correlation_id(self) -> None:
        cid = "toolu_01AAAAAAAAAAAAAAAAAAAAAA"
        receipt = create_receipt(_make_input(correlation_id=cid))
        assert receipt.credentialSubject.correlation_id == cid

    def test_excludes_correlation_id_when_not_provided(self) -> None:
        receipt = create_receipt(_make_input())
        assert receipt.credentialSubject.correlation_id is None

    def test_excludes_correlation_id_when_empty_string(self) -> None:
        receipt = create_receipt(_make_input(correlation_id=""))
        assert receipt.credentialSubject.correlation_id is None

    def test_preserves_delegation(self) -> None:
        delegation = Delegation(
            parent_chain_id="root-chain",
            parent_receipt_id="urn:receipt:parent-uuid",
            delegator=Delegator(id="did:agent-receipts-daemon:host"),
        )
        receipt = create_receipt(_make_input(delegation=delegation))
        assert receipt.credentialSubject.delegation == delegation

    def test_excludes_delegation_when_not_provided(self) -> None:
        receipt = create_receipt(_make_input())
        assert receipt.credentialSubject.delegation is None
