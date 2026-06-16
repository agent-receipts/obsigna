"""Tests for Ed25519 signing and verification."""

from obsigna.receipt.signing import (
    generate_key_pair,
    sign_receipt,
    verify_receipt,
)
from obsigna.receipt.types import AgentReceipt
from tests.conftest import TEST_PRIVATE_KEY, TEST_PUBLIC_KEY, make_unsigned


class TestGenerateKeyPair:
    def test_returns_pem_keys(self) -> None:
        keys = generate_key_pair()
        assert keys.public_key.startswith("-----BEGIN PUBLIC KEY-----")
        assert keys.private_key.startswith("-----BEGIN PRIVATE KEY-----")

    def test_generates_different_keys_each_time(self) -> None:
        k1 = generate_key_pair()
        k2 = generate_key_pair()
        assert k1.public_key != k2.public_key
        assert k1.private_key != k2.private_key


class TestSignReceipt:
    def test_returns_agent_receipt(self) -> None:
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        assert isinstance(signed, AgentReceipt)

    def test_proof_type(self) -> None:
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        assert signed.proof.type == "Ed25519Signature2020"

    def test_proof_purpose(self) -> None:
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        assert signed.proof.proofPurpose == "assertionMethod"

    def test_proof_value_starts_with_u(self) -> None:
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        assert signed.proof.proofValue.startswith("u")

    def test_preserves_all_fields(self) -> None:
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        assert signed.id == unsigned.id
        assert signed.credentialSubject.chain.sequence == 1


class TestVerifyReceipt:
    def test_valid_signature(self) -> None:
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        assert verify_receipt(signed, TEST_PUBLIC_KEY) is True

    def test_wrong_key_fails(self) -> None:
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        other_keys = generate_key_pair()
        assert verify_receipt(signed, other_keys.public_key) is False

    def test_tampered_receipt_fails(self) -> None:
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        signed.credentialSubject.action.type = "filesystem.file.delete"
        assert verify_receipt(signed, TEST_PUBLIC_KEY) is False

    def test_invalid_proof_value_returns_false(self) -> None:
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        signed.proof.proofValue = "invalid"
        assert verify_receipt(signed, TEST_PUBLIC_KEY) is False

    def test_empty_proof_value_returns_false(self) -> None:
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        signed.proof.proofValue = ""
        assert verify_receipt(signed, TEST_PUBLIC_KEY) is False

    def test_wrong_proof_type_returns_false(self) -> None:
        # proof.type lives outside the signed bytes, so the Ed25519 signature
        # is still mathematically valid here. Verify MUST still reject the
        # receipt — otherwise an attacker could swap the type to claim a
        # different scheme.
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        signed.proof.type = "RsaSignature2018"
        assert verify_receipt(signed, TEST_PUBLIC_KEY) is False
