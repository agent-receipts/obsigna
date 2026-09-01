"""Tests for Ed25519 signing and verification."""

import json

import pytest

from obsigna.receipt.signing import (
    PROOF_TYPE_ED25519_SIGNATURE_2020,
    generate_key_pair,
    sign_receipt,
    verify_raw,
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


class TestVerifyRaw:
    def test_matches_verify_receipt_for_known_fields(self) -> None:
        # Real wire serialization the emitters send (no exclude_none), so
        # this also exercises verify_raw's ADR-0009 Rule 2 normalisation.
        unsigned = make_unsigned(1, None, chain_id="chain-1")
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        raw = signed.model_dump_json(by_alias=True)

        assert verify_raw(raw, TEST_PUBLIC_KEY) is True

        other = generate_key_pair()
        assert verify_raw(raw, other.public_key) is False

    def test_accepts_forward_compat_nested_field(self) -> None:
        # The reason verify_raw exists: a newer SDK can add and sign over a
        # field nested inside the payload that the installed Pydantic model
        # does not know about. verify_receipt drops it via model_dump's
        # extra="ignore" and false-negatives; verify_raw canonicalizes the
        # verbatim wire JSON and accepts the receipt.
        unsigned = make_unsigned(1, None, chain_id="chain-fc")
        payload = json.loads(unsigned.model_dump_json(by_alias=True))
        payload["credentialSubject"]["future_field_v7"] = "v2"

        signed_raw = _sign_raw_payload(payload, TEST_PRIVATE_KEY)
        assert verify_raw(signed_raw, TEST_PUBLIC_KEY) is True

        parsed = AgentReceipt.model_validate_json(signed_raw)
        assert verify_receipt(parsed, TEST_PUBLIC_KEY) is False

    def test_rejects_tampered_bytes(self) -> None:
        unsigned = make_unsigned(1, None, chain_id="chain-1")
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        raw = signed.model_dump_json(by_alias=True)

        tampered = raw.replace("filesystem.file.read", "filesystem.file.delete", 1)
        assert tampered != raw
        assert verify_raw(tampered, TEST_PUBLIC_KEY) is False

    def test_rejects_wrong_proof_type(self) -> None:
        unsigned = make_unsigned(1, None, chain_id="chain-1")
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        raw = signed.model_dump_json(by_alias=True)

        swapped = raw.replace(PROOF_TYPE_ED25519_SIGNATURE_2020, "RsaSignature2018", 1)
        assert swapped != raw
        with pytest.raises(ValueError, match="unsupported proof type"):
            verify_raw(swapped, TEST_PUBLIC_KEY)

    @pytest.mark.parametrize(
        "body",
        [
            "[1,2,3]",
            "42",
            "null",
            "",
            '{"id":"urn:r:1","credentialSubject":{"x":1}}',
            '{"id":"urn:r:1","proof":"u-AAA"}',
            '{"id":"urn:r:1","proof":{"type":123,"proofValue":"uAAA"}}',
            '{"id":"urn:r:1","proof":{"type":"Ed25519Signature2020","proofValue":123}}',
            '{"id":"urn:r:1","proof":{"type":"Ed25519Signature2020"}}',
        ],
    )
    def test_rejects_malformed_input(self, body: str) -> None:
        with pytest.raises(ValueError):
            verify_raw(body, TEST_PUBLIC_KEY)


def _sign_raw_payload(payload: dict, private_key: str) -> str:
    """Sign a raw dict payload directly, bypassing the Pydantic model.

    Test helper simulating a newer SDK that signs over a field the current
    Python model does not know about.
    """
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    from obsigna.receipt.hash import canonicalize, normalize_receipt_dict
    from obsigna.receipt.signing import MULTIBASE_BASE64URL

    canonical = canonicalize(normalize_receipt_dict(dict(payload)))

    key = load_pem_private_key(private_key.encode("ascii"), password=None)
    assert isinstance(key, Ed25519PrivateKey)
    signature = key.sign(canonical.encode("utf-8"))
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")

    payload["proof"] = {
        "type": PROOF_TYPE_ED25519_SIGNATURE_2020,
        "proofValue": f"{MULTIBASE_BASE64URL}{sig_b64}",
    }
    return json.dumps(payload)
