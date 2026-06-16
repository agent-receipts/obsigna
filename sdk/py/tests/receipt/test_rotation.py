"""Tests for key-rotation verification (ADR-0015)."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from obsigna import generate_key_pair, hash_receipt, verify_chain
from obsigna.receipt.rotation import (
    ed25519_raw_to_pem,
    key_fingerprint,
    pem_to_ed25519_raw,
    verify_rotation_event,
)
from obsigna.receipt.signing import sign_receipt
from obsigna.receipt.types import (
    CONTEXT,
    CREDENTIAL_TYPE,
    VERSION,
    Action,
    AgentReceipt,
    Chain,
    CredentialSubject,
    Issuer,
    KeyRotation,
    Outcome,
    Principal,
    UnsignedAgentReceipt,
)

# RFC 8032 §7.1 well-known test public keys (raw 32-byte Ed25519), reused by the
# spec rotation-event vector. TEST 2 is the outgoing key (signs the rotation);
# TEST 3 is the incoming key.
RFC8032_TEST2_PUB_HEX = (
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)
RFC8032_TEST3_PUB_HEX = (
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
)

_VECTOR_PATH = (
    Path(__file__).resolve().parents[4]
    / "spec"
    / "test-vectors"
    / "rotation-event"
    / "example.json"
)
_VERIFICATION_METHOD = "did:agent:test#key-1"


def _pem_from_hex(hex_key: str) -> str:
    return ed25519_raw_to_pem(bytes.fromhex(hex_key))


def _multibase(raw: bytes) -> str:
    return "u" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _load_vector() -> AgentReceipt:
    return AgentReceipt.model_validate_json(_VECTOR_PATH.read_text())


def _unsigned(
    sequence: int,
    previous_hash: str | None,
    action_type: str,
    risk_level: str,
    *,
    key_rotation: KeyRotation | None = None,
) -> UnsignedAgentReceipt:
    return UnsignedAgentReceipt(
        **{
            "@context": list(CONTEXT),
            "id": f"urn:receipt:chain_rot-{sequence}",
            "type": list(CREDENTIAL_TYPE),
            "version": VERSION,
            "issuer": Issuer(id="did:agent:test"),
            "issuanceDate": "2026-05-18T10:00:00Z",
            "credentialSubject": CredentialSubject(
                principal=Principal(id="did:user:test"),
                action=Action(
                    id=f"act_{sequence}",
                    type=action_type,
                    risk_level=risk_level,
                    timestamp="2026-05-18T10:00:00Z",
                ),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=sequence,
                    previous_receipt_hash=previous_hash,
                    chain_id="chain_rot",
                ),
                key_rotation=key_rotation,
            ),
        }
    )


def test_rotation_vector_verifies() -> None:
    vector = _load_vector()
    assert vector.credentialSubject.key_rotation is not None
    assert vector.credentialSubject.key_rotation.event_type == "key_rotated"

    outgoing_pem = _pem_from_hex(RFC8032_TEST2_PUB_HEX)
    result = verify_chain([vector], outgoing_pem)
    assert result.valid, f"broken_at={result.broken_at} error={result.error!r}"


def test_rotation_vector_canonical_hash() -> None:
    got = hash_receipt(_load_vector())
    assert got == (
        "sha256:6983c9bd6fb24e844b90f7616315a914fdedc5fef8126e11d46149ba2f320457"
    )


def test_verify_rotation_event_binds_incoming_key() -> None:
    vector = _load_vector()
    outgoing_pem = _pem_from_hex(RFC8032_TEST2_PUB_HEX)
    kr = vector.credentialSubject.key_rotation
    assert kr is not None
    new_pem = verify_rotation_event(outgoing_pem, kr)
    assert new_pem == _pem_from_hex(RFC8032_TEST3_PUB_HEX)


def test_verify_rotation_event_rejects() -> None:
    outgoing_pem = _pem_from_hex(RFC8032_TEST2_PUB_HEX)
    zero_fp = "sha256:" + "0" * 64
    base = _load_vector().credentialSubject.key_rotation
    assert base is not None

    cases: list[tuple[dict[str, str], str]] = [
        ({"event_type": "rotated"}, "event_type"),
        ({"signed_with": "new"}, "signed_with"),
        ({"old_algorithm": "ml-dsa"}, "old_algorithm"),
        ({"new_algorithm": "ml-dsa"}, "new_algorithm"),
        ({"old_key_fingerprint": zero_fp}, "old_key_fingerprint"),
        ({"new_key_fingerprint": zero_fp}, "new_key_fingerprint"),
        ({"new_public_key": "z" + base.new_public_key[1:]}, "new_public_key"),
        ({"new_public_key": "uAAAA"}, "new_public_key"),
    ]
    for overrides, want in cases:
        kr = base.model_copy(update=overrides)
        with pytest.raises(ValueError, match=want):
            verify_rotation_event(outgoing_pem, kr)


def test_rotation_chain_switches_key() -> None:
    out_kp = generate_key_pair()
    in_kp = generate_key_pair()
    in_raw = pem_to_ed25519_raw(in_kp.public_key)

    kr = KeyRotation(
        event_type="key_rotated",
        new_public_key=_multibase(in_raw),
        old_key_fingerprint=key_fingerprint(pem_to_ed25519_raw(out_kp.public_key)),
        new_key_fingerprint=key_fingerprint(in_raw),
        old_algorithm="ed25519",
        new_algorithm="ed25519",
        signed_with="old",
    )
    rot = _unsigned(1, None, "agent.key.rotate", "high", key_rotation=kr)
    signed0 = sign_receipt(rot, out_kp.private_key, _VERIFICATION_METHOD)
    h0 = hash_receipt(signed0)
    r1 = _unsigned(2, h0, "filesystem.file.read", "low")
    signed1 = sign_receipt(r1, in_kp.private_key, _VERIFICATION_METHOD)

    # Verified under only the outgoing genesis key — succeeds because the
    # rotation hands the key over.
    assert verify_chain([signed0, signed1], out_kp.public_key).valid

    # Without the rotation handover, the successor signed by the incoming key
    # fails under the outgoing key alone.
    no_rot0 = sign_receipt(
        _unsigned(1, None, "agent.key.rotate", "high"),
        out_kp.private_key,
        _VERIFICATION_METHOD,
    )
    h0b = hash_receipt(no_rot0)
    no_rot1 = sign_receipt(
        _unsigned(2, h0b, "filesystem.file.read", "low"),
        in_kp.private_key,
        _VERIFICATION_METHOD,
    )
    assert not verify_chain([no_rot0, no_rot1], out_kp.public_key).valid
