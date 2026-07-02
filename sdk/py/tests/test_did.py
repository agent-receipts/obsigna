"""Unit tests for obsigna.did (ADR-0007 did:key v0.7)."""

from __future__ import annotations

import pytest

from obsigna.did import from_public_key, resolve

# RFC 8032 §7.1 TEST 1's public key — same key vector-1 in
# spec/test-vectors/did-key/vectors.json uses.
PUBLIC_KEY_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
EXPECTED_DID = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"


def test_from_public_key() -> None:
    pub = bytes.fromhex(PUBLIC_KEY_HEX)
    assert from_public_key(pub) == EXPECTED_DID


@pytest.mark.parametrize("n", [0, 16, 31, 33, 64])
def test_from_public_key_rejects_wrong_length(n: int) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        from_public_key(bytes(n))


def test_resolve_round_trip() -> None:
    doc = resolve(EXPECTED_DID)
    assert doc.id == EXPECTED_DID

    fragment = EXPECTED_DID[len("did:key:") :]
    vm_id = f"{EXPECTED_DID}#{fragment}"

    assert len(doc.verification_method) == 1
    vm = doc.verification_method[0]
    assert vm.id == vm_id
    assert vm.type == "Multikey"
    assert vm.controller == EXPECTED_DID
    assert vm.public_key_multibase == fragment

    assert doc.authentication == [vm_id]
    assert doc.assertion_method == [vm_id]
    assert doc.context == [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1",
    ]


def test_resolve_to_dict_matches_shape() -> None:
    doc = resolve(EXPECTED_DID)
    fragment = EXPECTED_DID[len("did:key:") :]
    vm_id = f"{EXPECTED_DID}#{fragment}"
    assert doc.to_dict() == {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": EXPECTED_DID,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "Multikey",
                "controller": EXPECTED_DID,
                "publicKeyMultibase": fragment,
            }
        ],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
    }


@pytest.mark.parametrize(
    "did",
    [
        "",
        "did:key:",
        "did:web:example.com",
        "did:key:u" + EXPECTED_DID[len("did:key:z") :],
        "key:z6Mktwup",
        EXPECTED_DID[1:],
    ],
)
def test_resolve_rejects_missing_prefix(did: str) -> None:
    with pytest.raises(ValueError, match="prefix"):
        resolve(did)


@pytest.mark.parametrize("ch", ["0", "O", "I", "l"])
def test_resolve_rejects_excluded_base58_characters(ch: str) -> None:
    with pytest.raises(ValueError, match="base58btc"):
        resolve(f"did:key:z{ch}6Mktwup")


def test_resolve_rejects_wrong_payload_length() -> None:
    from obsigna.did import _base58btc_encode  # noqa: PLC0415

    short = _base58btc_encode(b"\xed" + bytes(32))
    with pytest.raises(ValueError, match="34 bytes"):
        resolve(f"did:key:z{short}")

    long_ = _base58btc_encode(b"\xed\x01" + bytes(33))
    with pytest.raises(ValueError, match="34 bytes"):
        resolve(f"did:key:z{long_}")


def test_resolve_rejects_wrong_multicodec() -> None:
    from obsigna.did import _base58btc_encode  # noqa: PLC0415

    payload = _base58btc_encode(b"\xed\x02" + bytes(32))
    with pytest.raises(ValueError, match="multicodec"):
        resolve(f"did:key:z{payload}")

    secp = _base58btc_encode(b"\x12\x05" + bytes(32))
    with pytest.raises(ValueError, match="multicodec"):
        resolve(f"did:key:z{secp}")


def test_base58_encode_decode_round_trip() -> None:
    from obsigna.did import _base58btc_decode, _base58btc_encode  # noqa: PLC0415

    cases = [b"", b"\x00", b"\x00\x00\x01", b"\xff", b"\xed\x01", bytes(34)]
    for data in cases:
        encoded = _base58btc_encode(data)
        assert not any(ch in encoded for ch in "0OIl")
        assert _base58btc_decode(encoded) == data
