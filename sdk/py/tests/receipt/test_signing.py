"""Tests for Ed25519 signing and verification."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from obsigna.receipt.signing import (
    PROOF_TYPE_ED25519_SIGNATURE_2020,
    generate_key_pair,
    public_key_to_pem,
    sign_receipt,
    verify_raw,
    verify_receipt,
)
from obsigna.receipt.types import AgentReceipt
from tests.conftest import TEST_PRIVATE_KEY, TEST_PUBLIC_KEY, make_unsigned


class _FakeSigner:
    """Minimal ``Signer`` implementation: signs in-process, never via PEM.

    Stands in for a KMS/HSM adapter to exercise the ``Signer`` branch of
    ``sign_receipt`` without a real KMS dependency.
    """

    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.generate()
        self.sign_calls: list[bytes] = []

    def sign(self, message: bytes) -> bytes:
        self.sign_calls.append(message)
        return self._key.sign(message)

    def get_public_key(self) -> bytes:
        return self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


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


class TestSignReceiptWithSigner:
    """``sign_receipt`` accepts anything satisfying the ``Signer`` protocol,
    not just a PEM string, so KMS/HSM-backed keys reuse the same
    canonicalization + proof-construction pipeline."""

    def test_returns_agent_receipt(self) -> None:
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, _FakeSigner(), "did:agent:test#key-1")
        assert isinstance(signed, AgentReceipt)

    def test_signs_over_canonical_receipt_bytes(self) -> None:
        # The Signer branch must receive exactly one call, with the same
        # canonicalized payload the PEM branch signs (verified below via
        # round-trip verification rather than reimplementing
        # canonicalization here).
        signer = _FakeSigner()
        unsigned = make_unsigned(1, None)
        sign_receipt(unsigned, signer, "did:agent:test#key-1")
        assert len(signer.sign_calls) == 1

    def test_verify_via_public_key_to_pem(self) -> None:
        signer = _FakeSigner()
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, signer, "did:agent:test#key-1")

        public_pem = public_key_to_pem(signer.get_public_key())
        assert verify_receipt(signed, public_pem) is True

    def test_wrong_signer_key_fails_verification(self) -> None:
        signer = _FakeSigner()
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, signer, "did:agent:test#key-1")

        other = _FakeSigner()
        other_pem = public_key_to_pem(other.get_public_key())
        assert verify_receipt(signed, other_pem) is False

    def test_pem_string_still_works_unchanged(self) -> None:
        # The str branch (existing behavior) must be untouched by adding
        # the Signer branch.
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        assert verify_receipt(signed, TEST_PUBLIC_KEY) is True


class TestPublicKeyToPem:
    def test_returns_spki_pem(self) -> None:
        priv = Ed25519PrivateKey.generate()
        raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        pem = public_key_to_pem(raw_pub)
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")

    def test_matches_generate_key_pair_public_pem(self) -> None:
        # public_key_to_pem(raw) must produce the same PEM verify_receipt
        # already accepts from generate_key_pair()'s public_key field.
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        pair = generate_key_pair()
        loaded = load_pem_public_key(pair.public_key.encode("ascii"))
        assert isinstance(loaded, Ed25519PublicKey)
        raw = loaded.public_bytes(Encoding.Raw, PublicFormat.Raw)

        assert public_key_to_pem(raw) == pair.public_key


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
