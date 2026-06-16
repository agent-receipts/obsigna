"""Shared test fixtures for receipts."""

from __future__ import annotations

from obsigna.receipt.signing import generate_key_pair
from obsigna.receipt.types import (
    CONTEXT,
    CREDENTIAL_TYPE,
    VERSION,
    Action,
    AgentReceipt,
    Chain,
    CredentialSubject,
    Issuer,
    Outcome,
    Principal,
    Proof,
    UnsignedAgentReceipt,
)

# Shared test key pair
_TEST_KEYS = generate_key_pair()
TEST_PUBLIC_KEY = _TEST_KEYS.public_key
TEST_PRIVATE_KEY = _TEST_KEYS.private_key


def make_receipt(
    *,
    id: str = "urn:receipt:test-1",
    sequence: int = 1,
    chain_id: str = "chain_test",
    action_type: str = "filesystem.file.read",
    risk_level: str = "low",
    status: str = "success",
    timestamp: str = "2026-03-29T14:00:00Z",
    previous_hash: str | None = None,
) -> AgentReceipt:
    """Create a signed AgentReceipt with overridable fields.

    Includes a dummy proof — use sign_receipt() for real signatures.
    """
    return AgentReceipt(
        **{
            "@context": list(CONTEXT),
            "id": id,
            "type": list(CREDENTIAL_TYPE),
            "version": VERSION,
            "issuer": Issuer(id="did:agent:test"),
            "issuanceDate": "2026-03-29T14:00:00Z",
            "credentialSubject": CredentialSubject(
                principal=Principal(id="did:user:test"),
                action=Action(
                    id="act_1",
                    type=action_type,
                    risk_level=risk_level,  # type: ignore[arg-type]
                    timestamp=timestamp,
                ),
                outcome=Outcome(status=status),  # type: ignore[arg-type]
                chain=Chain(
                    sequence=sequence,
                    previous_receipt_hash=previous_hash,
                    chain_id=chain_id,
                ),
            ),
            "proof": Proof(type="Ed25519Signature2020", proofValue="utest"),
        }
    )


def make_unsigned(
    sequence: int,
    previous_hash: str | None,
    chain_id: str = "chain_test",
) -> UnsignedAgentReceipt:
    """Create an UnsignedAgentReceipt for chain/signing tests."""
    return UnsignedAgentReceipt(
        **{
            "@context": list(CONTEXT),
            "id": f"urn:receipt:{chain_id}-{sequence}",
            "type": list(CREDENTIAL_TYPE),
            "version": VERSION,
            "issuer": Issuer(id="did:agent:test"),
            "issuanceDate": "2026-03-29T14:31:00Z",
            "credentialSubject": CredentialSubject(
                principal=Principal(id="did:user:test"),
                action=Action(
                    id=f"act_{sequence}",
                    type="filesystem.file.read",
                    risk_level="low",
                    timestamp="2026-03-29T14:31:00Z",
                ),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=sequence,
                    previous_receipt_hash=previous_hash,
                    chain_id=chain_id,
                ),
            ),
        }
    )
