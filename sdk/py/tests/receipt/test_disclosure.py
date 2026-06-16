"""Tests for the HPKE disclosure envelope (ADR-0012, amendment 2026-05-18).

Mirrors sdk/go/receipt/disclosure_test.go and sdk/ts/src/receipt/disclosure.test.ts.
Both spec test vectors MUST produce byte-identical ``enc`` and ``ct`` across all
three SDKs — see ``spec/test-vectors/disclosure-envelope/vectors.json``.
"""

from __future__ import annotations

import binascii
import json
from typing import Any, cast

import pytest

from obsigna.receipt.disclosure import (
    DisclosureEnvelope,
    _encrypt_disclosure_with_seed,
    decrypt_disclosure,
    encrypt_disclosure,
    generate_forensic_key_pair,
)
from obsigna.receipt.hash import canonicalize

# RFC 7748 §6.1 well-known X25519 test keys. Published IETF test vectors — not
# real secrets. Verified: X25519(alicePriv, basepoint) === alicePub.
ALICE_PUB_HEX = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
ALICE_PRIV_HEX = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
BOB_PUB_HEX = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
BOB_PRIV_HEX = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"

# ikmE values from spec/test-vectors/disclosure-envelope/vectors.json
VECTOR1_IKME_HEX = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"
VECTOR2_IKME_HEX = "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b"


def _hex(s: str) -> bytes:
    return binascii.unhexlify(s)


class TestGenerateForensicKeyPair:
    def test_produces_32_byte_keys(self) -> None:
        kp = generate_forensic_key_pair()
        assert len(kp.public_key) == 32
        assert len(kp.private_key) == 32
        assert kp.public_key != kp.private_key

    def test_round_trip_with_fresh_keys(self) -> None:
        kp = generate_forensic_key_pair()
        params = {"tool": "read_file", "path": "/tmp/test.txt"}
        env = encrypt_disclosure(params, kp.public_key, "sha256:test")
        got = decrypt_disclosure(env, kp.private_key)
        assert got["tool"] == "read_file"
        assert got["path"] == "/tmp/test.txt"


class TestEncryptDisclosure:
    def test_produces_valid_v1_envelope_shape(self) -> None:
        alice_pub = _hex(ALICE_PUB_HEX)
        env = encrypt_disclosure(
            {"command": 'echo "build complete"'},
            alice_pub,
            "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQUQUaHL9XJ7Z5W#enc-1",
        )
        assert env["v"] == "1"
        assert env["alg"] == "hpke-x25519-hkdf-sha256-aes-256-gcm"
        assert len(env["recipients"]) == 1
        # enc: 43 chars = unpadded base64url of 32 bytes
        assert len(env["recipients"][0]["enc"]) == 43
        for ch in "+/=":
            assert ch not in env["recipients"][0]["enc"]
            assert ch not in env["ct"]
        assert len(env["ct"]) >= 24
        # No nonce field — v1 is single-shot.
        assert "nonce" not in json.dumps(env)

    def test_round_trip_with_alice_rfc7748_keys(self) -> None:
        alice_pub = _hex(ALICE_PUB_HEX)
        alice_priv = _hex(ALICE_PRIV_HEX)
        params = {"command": 'echo "build complete"'}
        env = encrypt_disclosure(params, alice_pub, "test-kid")
        got = decrypt_disclosure(env, alice_priv)
        assert got["command"] == 'echo "build complete"'

    def test_jcs_canonicalizes_plaintext(self) -> None:
        """Plaintext encrypted into ct MUST be the JCS of params, not raw JSON."""
        alice_pub = _hex(ALICE_PUB_HEX)
        alice_priv = _hex(ALICE_PRIV_HEX)
        # Non-trivially-ordered keys so JCS sort is observable.
        params = {"z_last": "last", "a_first": "first", "m_mid": "middle"}
        env = encrypt_disclosure(params, alice_pub, "test-kid")
        got = decrypt_disclosure(env, alice_priv)
        assert canonicalize(got) == canonicalize(params)

    def test_rejects_short_recipient_public_key(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_disclosure({}, b"\x00" * 16, "kid")

    def test_rejects_long_recipient_public_key(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_disclosure({}, b"\x00" * 33, "kid")

    def test_rejects_empty_kid(self) -> None:
        alice_pub = _hex(ALICE_PUB_HEX)
        with pytest.raises(ValueError, match="kid"):
            encrypt_disclosure({}, alice_pub, "")

    def test_rejects_non_dict_params(self) -> None:
        alice_pub = _hex(ALICE_PUB_HEX)
        # Lists, strings, None, Mapping subclasses are all rejected.
        with pytest.raises(TypeError, match="plain dict"):
            encrypt_disclosure(cast("Any", ["a", "b"]), alice_pub, "kid")
        with pytest.raises(TypeError, match="plain dict"):
            encrypt_disclosure(cast("Any", None), alice_pub, "kid")
        with pytest.raises(TypeError, match="plain dict"):
            encrypt_disclosure(cast("Any", "string"), alice_pub, "kid")

    def test_rejects_mapping_subclass(self) -> None:
        """Mapping subclasses (OrderedDict, ChainMap, custom dict) are rejected.

        JCS canonicalisation only handles plain dicts; accepting subclasses
        would let user types leak through.
        """
        from collections import OrderedDict

        alice_pub = _hex(ALICE_PUB_HEX)
        with pytest.raises(TypeError, match="plain dict"):
            encrypt_disclosure(cast("Any", OrderedDict({"a": 1})), alice_pub, "kid")


class TestDecryptDisclosure:
    def _valid_env(self) -> DisclosureEnvelope:
        alice_pub = _hex(ALICE_PUB_HEX)
        return encrypt_disclosure({"k": "v"}, alice_pub, "kid")

    def test_rejects_none_envelope(self) -> None:
        with pytest.raises(ValueError, match="must not be None"):
            decrypt_disclosure(cast("Any", None), b"\x00" * 32)

    def test_rejects_wrong_version(self) -> None:
        env: DisclosureEnvelope = {
            "v": cast("Any", "2"),
            "alg": "hpke-x25519-hkdf-sha256-aes-256-gcm",
            "recipients": [{"kid": "k", "enc": "A" * 43}],
            "ct": "B" * 24,
        }
        with pytest.raises(ValueError, match="unsupported envelope version"):
            decrypt_disclosure(env, b"\x00" * 32)

    def test_rejects_wrong_alg(self) -> None:
        env: DisclosureEnvelope = {
            "v": "1",
            "alg": cast("Any", "hpke-x25519-chacha20poly1305"),
            "recipients": [{"kid": "k", "enc": "A" * 43}],
            "ct": "B" * 24,
        }
        with pytest.raises(ValueError, match="unsupported algorithm"):
            decrypt_disclosure(env, b"\x00" * 32)

    def test_rejects_zero_recipients(self) -> None:
        env: DisclosureEnvelope = {
            "v": "1",
            "alg": "hpke-x25519-hkdf-sha256-aes-256-gcm",
            "recipients": [],
            "ct": "B" * 24,
        }
        with pytest.raises(ValueError, match="exactly 1 recipient"):
            decrypt_disclosure(env, b"\x00" * 32)

    def test_rejects_two_recipients(self) -> None:
        env: DisclosureEnvelope = {
            "v": "1",
            "alg": "hpke-x25519-hkdf-sha256-aes-256-gcm",
            "recipients": [
                {"kid": "k1", "enc": "A" * 43},
                {"kid": "k2", "enc": "A" * 43},
            ],
            "ct": "B" * 24,
        }
        with pytest.raises(ValueError, match="exactly 1 recipient"):
            decrypt_disclosure(env, b"\x00" * 32)

    def test_rejects_short_private_key(self) -> None:
        env = self._valid_env()
        with pytest.raises(ValueError, match="32 bytes"):
            decrypt_disclosure(env, b"\x00" * 16)

    def test_rejects_long_private_key(self) -> None:
        env = self._valid_env()
        with pytest.raises(ValueError, match="32 bytes"):
            decrypt_disclosure(env, b"\x00" * 33)

    def test_rejects_wrong_private_key_authentication_failure(self) -> None:
        alice_pub = _hex(ALICE_PUB_HEX)
        bob_priv = _hex(BOB_PRIV_HEX)
        env = encrypt_disclosure({"x": 1}, alice_pub, "kid")
        # Bob's key successfully completes Decap on Alice's envelope but the
        # derived AEAD key is different, so AES-GCM authentication fails.
        with pytest.raises(ValueError, match="HPKE open failed"):
            decrypt_disclosure(env, bob_priv)

    def test_rejects_padded_base64_in_enc(self) -> None:
        alice_pub = _hex(ALICE_PUB_HEX)
        alice_priv = _hex(ALICE_PRIV_HEX)
        env = encrypt_disclosure({"k": "v"}, alice_pub, "kid")
        bad_enc = env["recipients"][0]["enc"][:42] + "="
        bad_env: DisclosureEnvelope = {
            **env,
            "recipients": [{"kid": "kid", "enc": bad_enc}],
        }
        with pytest.raises(ValueError, match="invalid base64url"):
            decrypt_disclosure(bad_env, alice_priv)

    def test_rejects_standard_base64_plus_character(self) -> None:
        alice_pub = _hex(ALICE_PUB_HEX)
        alice_priv = _hex(ALICE_PRIV_HEX)
        env = encrypt_disclosure({"k": "v"}, alice_pub, "kid")
        bad_env: DisclosureEnvelope = {
            **env,
            "recipients": [{"kid": "kid", "enc": "A" * 42 + "+"}],
        }
        with pytest.raises(ValueError, match="invalid base64url"):
            decrypt_disclosure(bad_env, alice_priv)

    def test_rejects_enc_with_invalid_base64url_length(self) -> None:
        """``len % 4 == 1`` is never a valid base64 string, even unpadded."""
        alice_pub = _hex(ALICE_PUB_HEX)
        alice_priv = _hex(ALICE_PRIV_HEX)
        env = encrypt_disclosure({"k": "v"}, alice_pub, "kid")
        bad_env: DisclosureEnvelope = {
            **env,
            "recipients": [{"kid": "kid", "enc": "A" * 41}],
        }
        with pytest.raises(ValueError, match="invalid base64url"):
            decrypt_disclosure(bad_env, alice_priv)

    def test_rejects_ct_shorter_than_24_chars(self) -> None:
        alice_pub = _hex(ALICE_PUB_HEX)
        alice_priv = _hex(ALICE_PRIV_HEX)
        env = encrypt_disclosure({"k": "v"}, alice_pub, "kid")
        bad_env: DisclosureEnvelope = {**env, "ct": "A" * 23}
        with pytest.raises(ValueError, match="ct is too short"):
            decrypt_disclosure(bad_env, alice_priv)

    def test_rejects_empty_kid_in_recipient(self) -> None:
        alice_pub = _hex(ALICE_PUB_HEX)
        alice_priv = _hex(ALICE_PRIV_HEX)
        env = encrypt_disclosure({"k": "v"}, alice_pub, "kid")
        bad_env: DisclosureEnvelope = {
            **env,
            "recipients": [{"kid": "", "enc": env["recipients"][0]["enc"]}],
        }
        with pytest.raises(ValueError, match="non-empty string"):
            decrypt_disclosure(bad_env, alice_priv)

    def test_rejects_non_string_enc(self) -> None:
        alice_pub = _hex(ALICE_PUB_HEX)
        alice_priv = _hex(ALICE_PRIV_HEX)
        env = encrypt_disclosure({"k": "v"}, alice_pub, "kid")
        bad_env: DisclosureEnvelope = {
            **env,
            "recipients": [cast("Any", {"kid": "kid", "enc": 42})],
        }
        with pytest.raises(TypeError, match="enc must be a string"):
            decrypt_disclosure(bad_env, alice_priv)

    def test_rejects_enc_wrong_byte_length(self) -> None:
        """A 28-char base64url decodes to 21 bytes — not 32 — so DHKEM must reject."""
        alice_pub = _hex(ALICE_PUB_HEX)
        alice_priv = _hex(ALICE_PRIV_HEX)
        env = encrypt_disclosure({"k": "v"}, alice_pub, "kid")
        bad_env: DisclosureEnvelope = {
            **env,
            "recipients": [{"kid": "kid", "enc": "A" * 28}],
        }
        with pytest.raises(ValueError, match="32 bytes"):
            decrypt_disclosure(bad_env, alice_priv)

    def test_json_round_trip(self) -> None:
        alice_pub = _hex(ALICE_PUB_HEX)
        alice_priv = _hex(ALICE_PRIV_HEX)
        env = encrypt_disclosure({"key": "value"}, alice_pub, "test-kid")
        raw = json.dumps(env)
        parsed = cast("DisclosureEnvelope", json.loads(raw))
        got = decrypt_disclosure(parsed, alice_priv)
        assert got["key"] == "value"


class TestEncryptDisclosureWithSeedValidation:
    def test_rejects_wrong_ikm_e_length(self) -> None:
        alice_pub = _hex(ALICE_PUB_HEX)
        for n in (0, 31, 33):
            with pytest.raises(ValueError, match="32 bytes"):
                _encrypt_disclosure_with_seed({}, alice_pub, "kid", b"\x00" * n)

    def test_validates_other_inputs_too(self) -> None:
        ikm = b"\x00" * 32
        with pytest.raises(ValueError, match="kid"):
            _encrypt_disclosure_with_seed({}, _hex(ALICE_PUB_HEX), "", ikm)
        with pytest.raises(ValueError, match="32 bytes"):
            _encrypt_disclosure_with_seed({}, b"\x00" * 16, "kid", ikm)
        with pytest.raises(TypeError, match="plain dict"):
            _encrypt_disclosure_with_seed(
                cast("Any", []), _hex(ALICE_PUB_HEX), "k", ikm
            )


class TestEnvelopeJCSCanonicalShape:
    def test_top_level_and_recipient_key_order(self) -> None:
        """Top-level keys sort as [alg, ct, recipients, v]; recipients as [enc, kid]."""
        enc = "A" * 43
        ct = "B" * 24
        env: DisclosureEnvelope = {
            "v": "1",
            "alg": "hpke-x25519-hkdf-sha256-aes-256-gcm",
            "recipients": [{"kid": "did:key:test#enc-1", "enc": enc}],
            "ct": ct,
        }
        want = (
            '{"alg":"hpke-x25519-hkdf-sha256-aes-256-gcm","ct":"'
            + ct
            + '","recipients":[{"enc":"'
            + enc
            + '","kid":"did:key:test#enc-1"}],"v":"1"}'
        )
        assert canonicalize(env) == want


class TestDeterministicSpecVectors:
    """Cross-SDK ground truth — both vectors MUST produce byte-identical output.

    See spec/test-vectors/disclosure-envelope/vectors.json for provenance.
    """

    def test_vector_1_matches_rfc9180_pkem_and_go_ts_sdks(self) -> None:
        alice_pub = _hex(ALICE_PUB_HEX)
        alice_priv = _hex(ALICE_PRIV_HEX)
        ikm_e = _hex(VECTOR1_IKME_HEX)
        params = {"command": 'echo "build complete"'}
        kid = "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQUQUaHL9XJ7Z5W#enc-1"

        env = _encrypt_disclosure_with_seed(params, alice_pub, kid, ikm_e)

        # enc = RFC 9180 §A.1.1 pkEm
        want_enc = "N_2jVnvb1ijohmjDyNfpfR0SU7bU6m1EwVD3QfG_RDE"
        assert env["recipients"][0]["enc"] == want_enc

        want_ct = (
            "YGn3i4NpiZxHjeZVggTP8lTxb0ZVdLl-2HjW31qsvo28PjQ_Lt_UQgAMidEXjzwhJPHM7OM"
        )
        assert env["ct"] == want_ct

        want_jcs = (
            '{"alg":"hpke-x25519-hkdf-sha256-aes-256-gcm","ct":"'
            + want_ct
            + '","recipients":[{"enc":"'
            + want_enc
            + '","kid":"'
            + kid
            + '"}],"v":"1"}'
        )
        assert canonicalize(env) == want_jcs

        # Plaintext JCS pinned by the vectors file.
        assert canonicalize(params) == '{"command":"echo \\"build complete\\""}'

        got = decrypt_disclosure(env, alice_priv)
        assert got["command"] == 'echo "build complete"'

    def test_vector_2_matches_pinned_go_ts_sdk_values(self) -> None:
        bob_pub = _hex(BOB_PUB_HEX)
        bob_priv = _hex(BOB_PRIV_HEX)
        ikm_e = _hex(VECTOR2_IKME_HEX)
        params = {
            "method": "POST",
            "headers": {
                "content-type": "application/json",
                "x-request-id": "abc-123",
            },
            "body": {"user": "otto", "delta": 42},
        }
        kid = "sha256:8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"

        env = _encrypt_disclosure_with_seed(params, bob_pub, kid, ikm_e)

        want_enc = "GvoI097AR6ZDiFFj8RgEdvp921TGqAKeoz-VeWvyrEo"
        assert env["recipients"][0]["enc"] == want_enc

        want_ct = (
            "vJG1bfcwNTnyL7gqfzkIg8oDl08Rd0z2kp-HVcRypJDrYdPBwvHWbIwdhCXuYB4mKANMm"
            "KejzrsDHvaOnFAAHxVzB-f57sljHW5aDsb4kp5mhtM2SIAQwUj6VlVonllEdQquRKOl3"
            "hjbXEOwjQeXQUxvI7avsiWuk5z41na_Xx6vVJd96lb-59YV"
        )
        assert env["ct"] == want_ct

        # Plaintext JCS pinned by the vectors file (sorted: body, headers, method).
        assert canonicalize(params) == (
            '{"body":{"delta":42,"user":"otto"},'
            '"headers":{"content-type":"application/json",'
            '"x-request-id":"abc-123"},"method":"POST"}'
        )

        got = decrypt_disclosure(env, bob_priv)
        assert got["method"] == "POST"
