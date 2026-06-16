"""HPKE disclosure envelope for parameters_disclosure (ADR-0012, amendment 2026-05-18).

Ciphersuite: hpke-x25519-hkdf-sha256-aes-256-gcm
(RFC 9180, KEM=DHKEM(X25519,HKDF-SHA256) 0x0020,
 KDF=HKDF-SHA256 0x0001, AEAD=AES-256-GCM 0x0002).

This module is a hand-rolled implementation of RFC 9180 base-mode HPKE on top
of pyca/cryptography (X25519, HKDF-SHA256, AES-256-GCM) — matching the no-extra-
dependency trajectory that PR #473 plans for the TS SDK. It MUST produce
byte-identical envelopes to the Go SDK (PR #468 / sdk/go/receipt/disclosure.go)
and the TS SDK (PR #472 / sdk/ts/src/receipt/disclosure.ts); the cross-SDK
invariant is pinned by spec/test-vectors/disclosure-envelope/vectors.json.

The DHKEM(X25519) ephemeral key MUST be derived via RFC 9180 §7.1.3
DeriveKeyPair (HKDF over ikmE), not used directly as the X25519 scalar. See
``_derive_x25519_key_pair`` for the one-shot LabeledExpand path for X25519.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Pydantic v2 requires `typing_extensions.TypedDict` on Python < 3.12 when
# the TypedDict is referenced from a Pydantic model field (see
# Action.parameters_disclosure in types.py). typing_extensions.TypedDict is
# the same API on 3.12+ — using it unconditionally keeps the SDK working
# across all supported Python versions.
from typing_extensions import TypedDict

from obsigna.receipt.hash import canonicalize

V1_ALG = "hpke-x25519-hkdf-sha256-aes-256-gcm"
"""ADR-0012 ciphersuite tag — the only value accepted by v1 decryptors."""

# RFC 9180 §7 codepoints for the pinned ciphersuite.
_KEM_ID = 0x0020  # DHKEM(X25519, HKDF-SHA256)
_KDF_ID = 0x0001  # HKDF-SHA256
_AEAD_ID = 0x0002  # AES-256-GCM

# RFC 9180 §4 / §7 KEM parameters for DHKEM(X25519, HKDF-SHA256).
_N_SECRET = 32  # KEM shared secret length
_N_ENC = 32  # encapsulated key length (X25519 public key)
_N_SK = 32  # private key (scalar) length

# RFC 9180 §4 KDF/AEAD parameters for HKDF-SHA256 + AES-256-GCM.
_N_H = 32  # HKDF-SHA256 hash length
_N_K = 32  # AES-256 key length
_N_N = 12  # AEAD nonce length

# RFC 9180 §4 suite_id values.
_KEM_SUITE_ID = b"KEM" + _KEM_ID.to_bytes(2, "big")
_HPKE_SUITE_ID = (
    b"HPKE"
    + _KEM_ID.to_bytes(2, "big")
    + _KDF_ID.to_bytes(2, "big")
    + _AEAD_ID.to_bytes(2, "big")
)

# RFC 9180 §5.1 mode byte for base mode.
_MODE_BASE = 0x00

# Strict unpadded base64url: [A-Za-z0-9_-]+, no padding, no standard-base64 chars.
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class DisclosureRecipient(TypedDict):
    """One entry in the recipients array of a DisclosureEnvelope.

    Field names match RFC 9180 §4.1 vocabulary ("enc", not "encap").
    """

    kid: str
    """Recipient key identifier (did:key DID URL or sha256:<hex> fingerprint)."""

    enc: str
    """HPKE encapsulated key; unpadded base64url, exactly 43 chars for X25519."""


class DisclosureEnvelope(TypedDict):
    """v1 asymmetric encryption envelope for parameters_disclosure (ADR-0012).

    The signed receipt commits to the ciphertext; only the holder of the
    forensic private key can recover the plaintext.
    """

    v: Literal["1"]
    alg: Literal["hpke-x25519-hkdf-sha256-aes-256-gcm"]
    recipients: list[DisclosureRecipient]
    """Length 1 in v1; length >1 is reserved for a future v2 envelope."""
    ct: str
    """AEAD ciphertext; unpadded base64url."""


@dataclass(frozen=True)
class ForensicKeyPair:
    """Raw X25519 key bytes (32 bytes each) for forensic disclosure.

    Separate from the Ed25519 signing key pair per ADR-0001 / ADR-0012.
    Unlike :class:`KeyPair` (Ed25519, PEM-encoded), these are raw bytes
    because X25519 has no widespread PKCS8 PEM convention and raw bytes
    compose more naturally with HPKE library APIs.
    """

    public_key: bytes
    """32-byte X25519 public key. Share with emitters to enable encryption."""

    private_key: bytes
    """32-byte X25519 private key. Keep offline; required to decrypt."""


def _b64url_encode(b: bytes) -> str:
    """Encode bytes as unpadded base64url (RFC 4648 §5)."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Strict unpadded base64url decoder.

    Rejects:
        - empty strings
        - any character outside ``[A-Za-z0-9_-]`` (no ``+``, ``/``, ``=``)
        - strings where ``len(s) % 4 == 1`` (never valid in base64, even unpadded)
    """
    if not s or len(s) % 4 == 1 or not _BASE64URL_RE.fullmatch(s):
        msg = (
            "invalid base64url: must be non-empty unpadded base64url "
            "[A-Za-z0-9_-] with valid length"
        )
        raise ValueError(msg)
    # urlsafe_b64decode requires padding; add it back.
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


def _i2osp(n: int, length: int) -> bytes:
    """RFC 9180 §4 I2OSP: big-endian integer-to-octet-string."""
    return n.to_bytes(length, "big")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract with SHA-256.

    Hand-rolled because cryptography's :class:`HKDF` only exposes the
    combined Extract+Expand operation; here we need Extract and Expand
    separately to match the RFC 9180 labelled-KDF construction.
    """
    import hmac

    salt = salt or bytes(_N_H)  # RFC 5869 §2.2: zero salt when not provided
    return hmac.new(salt, ikm, "sha256").digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand with SHA-256."""
    import hmac

    if length > 255 * _N_H:
        msg = f"HKDF-Expand: requested length {length} exceeds 255*HashLen"
        raise ValueError(msg)
    n = (length + _N_H - 1) // _N_H
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), "sha256").digest()
        okm += t
    return okm[:length]


def _labeled_extract(salt: bytes, label: bytes, ikm: bytes, suite_id: bytes) -> bytes:
    """RFC 9180 §4 LabeledExtract.

    LabeledExtract(salt, label, ikm) =
        HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)
    """
    return _hkdf_extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def _labeled_expand(
    prk: bytes, label: bytes, info: bytes, length: int, suite_id: bytes
) -> bytes:
    """RFC 9180 §4 LabeledExpand.

    LabeledExpand(prk, label, info, L) =
        HKDF-Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L)
    """
    labeled_info = _i2osp(length, 2) + b"HPKE-v1" + suite_id + label + info
    return _hkdf_expand(prk, labeled_info, length)


def _derive_x25519_key_pair(ikm: bytes) -> tuple[bytes, bytes]:
    """RFC 9180 §7.1.3 DeriveKeyPair for DHKEM(X25519, HKDF-SHA256).

    Returns ``(sk, pk)`` as raw 32-byte values. For X25519 this is a single
    LabeledExpand — no "candidate" counter loop like the NIST curves use.

    .. note::
        X25519 scalar clamping (RFC 7748 §5) is applied by
        ``X25519PrivateKey.from_private_bytes`` on use, so we do NOT apply
        it here — matching circl (Go SDK) and @hpke/core (TS SDK) behaviour.
    """
    dkp_prk = _labeled_extract(b"", b"dkp_prk", ikm, _KEM_SUITE_ID)
    sk = _labeled_expand(dkp_prk, b"sk", b"", _N_SK, _KEM_SUITE_ID)
    pk = X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes_raw()
    return sk, pk


def _dh(sk_bytes: bytes, pk_bytes: bytes) -> bytes:
    """RFC 9180 §7.1.1 DH(skX, pkY) for X25519: raw scalar multiplication output."""
    sk = X25519PrivateKey.from_private_bytes(sk_bytes)
    pk = X25519PublicKey.from_public_bytes(pk_bytes)
    return sk.exchange(pk)


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    """RFC 9180 §4.1 ExtractAndExpand step inside DHKEM Encap/Decap.

    eae_prk     = LabeledExtract("", "eae_prk", dh)
    shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
    """
    eae_prk = _labeled_extract(b"", b"eae_prk", dh, _KEM_SUITE_ID)
    return _labeled_expand(
        eae_prk, b"shared_secret", kem_context, _N_SECRET, _KEM_SUITE_ID
    )


def _encap(pk_r: bytes, ikm_e: bytes | None) -> tuple[bytes, bytes]:
    """RFC 9180 §4.1 DHKEM(X25519) Encap (or its deterministic variant).

    Returns ``(shared_secret, enc)`` where ``enc`` is the ephemeral public key
    that the receiver will use to recover the same shared secret. If ``ikm_e``
    is provided it is fed through DeriveKeyPair (matching circl's
    ``Sender.Setup(io.Reader)`` and @hpke/core's ``ekm`` paths); otherwise a
    fresh ephemeral key pair is generated.
    """
    if ikm_e is None:
        ikm_e = os.urandom(32)
    sk_e, pk_e = _derive_x25519_key_pair(ikm_e)
    dh = _dh(sk_e, pk_r)
    kem_context = pk_e + pk_r
    shared_secret = _extract_and_expand(dh, kem_context)
    return shared_secret, pk_e


def _decap(enc: bytes, sk_r: bytes) -> bytes:
    """RFC 9180 §4.1 DHKEM(X25519) Decap.

    Recovers the same ``shared_secret`` that ``_encap`` produced for the
    matching recipient private key.
    """
    pk_r = X25519PrivateKey.from_private_bytes(sk_r).public_key().public_bytes_raw()
    dh = _dh(sk_r, enc)
    kem_context = enc + pk_r
    return _extract_and_expand(dh, kem_context)


def _key_schedule_base(shared_secret: bytes) -> tuple[bytes, bytes]:
    """RFC 9180 §5.1 KeySchedule for mode_base with info="" and psk="".

    Returns ``(key, base_nonce)``. For a single-shot seal/open at seq=0, the
    AEAD nonce is just ``base_nonce`` (XOR with ``I2OSP(0, Nn)`` is a no-op).
    """
    psk_id_hash = _labeled_extract(b"", b"psk_id_hash", b"", _HPKE_SUITE_ID)
    info_hash = _labeled_extract(b"", b"info_hash", b"", _HPKE_SUITE_ID)
    key_schedule_context = bytes([_MODE_BASE]) + psk_id_hash + info_hash
    secret = _labeled_extract(shared_secret, b"secret", b"", _HPKE_SUITE_ID)
    key = _labeled_expand(secret, b"key", key_schedule_context, _N_K, _HPKE_SUITE_ID)
    base_nonce = _labeled_expand(
        secret, b"base_nonce", key_schedule_context, _N_N, _HPKE_SUITE_ID
    )
    return key, base_nonce


def _is_plain_dict(v: object) -> bool:
    """Return True iff ``v`` is an exact ``dict`` (not a Mapping subclass).

    Mirrors the TS SDK's ``isPlainObject`` semantics: the JCS canonicaliser
    only handles plain JSON objects, and accepting arbitrary Mapping subclasses
    would let custom classes leak through. Pydantic models, OrderedDict, etc.
    must be converted to ``dict`` by the caller before encryption.
    """
    return type(v) is dict


def generate_forensic_key_pair() -> ForensicKeyPair:
    """Generate an X25519 key pair for forensic disclosure.

    The public key is shared with emitters; the private key must be kept
    offline (separate from the Ed25519 signing key per ADR-0001 / ADR-0012).
    """
    sk_obj = X25519PrivateKey.generate()
    sk = sk_obj.private_bytes_raw()
    pk = sk_obj.public_key().public_bytes_raw()
    return ForensicKeyPair(public_key=pk, private_key=sk)


def _encrypt_with_options(
    params: dict[str, Any],
    recipient_public_key: bytes,
    kid: str,
    ikm_e: bytes | None,
) -> DisclosureEnvelope:
    # RFC 8785 JCS before encryption — cross-SDK interop depends on this.
    canonical = canonicalize(params)

    shared_secret, enc = _encap(recipient_public_key, ikm_e)
    key, base_nonce = _key_schedule_base(shared_secret)

    # info="" and AAD="" per ADR-0012 amendment §8: no out-of-band context
    # binding at the HPKE layer (the receipt signature already authenticates
    # the parameters_disclosure field).
    ct = AESGCM(key).encrypt(base_nonce, canonical.encode("utf-8"), b"")

    return {
        "v": "1",
        "alg": V1_ALG,
        "recipients": [{"kid": kid, "enc": _b64url_encode(enc)}],
        "ct": _b64url_encode(ct),
    }


def encrypt_disclosure(
    params: dict[str, Any],
    recipient_public_key: bytes,
    kid: str,
) -> DisclosureEnvelope:
    """Encrypt ``params`` as a v1 HPKE disclosure envelope.

    ``params`` is RFC 8785 JCS-canonicalised before encryption so that all
    SDKs encrypt the same bytes for the same parameters object.

    Args:
        params: The parameters to encrypt. MUST be a plain ``dict`` (subclasses
            of ``Mapping`` are rejected to keep canonical-JSON semantics tight).
        recipient_public_key: 32-byte X25519 forensic public key.
        kid: Recipient key identifier (did:key DID URL or
            ``sha256:<hex>`` fingerprint).
    """
    if not _is_plain_dict(params):
        msg = "params must be a plain dict"
        raise TypeError(msg)
    if len(recipient_public_key) != 32:
        msg = f"recipient_public_key must be 32 bytes, got {len(recipient_public_key)}"
        raise ValueError(msg)
    if not kid:
        msg = "kid must not be empty"
        raise ValueError(msg)
    return _encrypt_with_options(params, recipient_public_key, kid, None)


def _encrypt_disclosure_with_seed(  # pyright: ignore[reportUnusedFunction]
    params: dict[str, Any],
    recipient_public_key: bytes,
    kid: str,
    ikm_e: bytes,
) -> DisclosureEnvelope:
    """Deterministic variant of :func:`encrypt_disclosure` for cross-SDK vectors.

    ``ikm_e`` (32 bytes) is fed to RFC 9180 §7.1.3 DeriveKeyPair to derive the
    ephemeral scalar — it is NOT used directly as the X25519 scalar. This
    matches circl's ``Sender.Setup(io.Reader)`` (Go SDK) and ``@hpke/core``'s
    ``ekm`` (TS SDK) and is confirmed by vector-1: ikm_e = RFC 9180 §A.1.1
    ikmE produces enc = the same RFC's pkEm.

    .. warning::
        For tests only. Reusing ``ikm_e`` across real encryptions breaks
        confidentiality.
    """
    if not _is_plain_dict(params):
        msg = "params must be a plain dict"
        raise TypeError(msg)
    if len(recipient_public_key) != 32:
        msg = f"recipient_public_key must be 32 bytes, got {len(recipient_public_key)}"
        raise ValueError(msg)
    if not kid:
        msg = "kid must not be empty"
        raise ValueError(msg)
    if len(ikm_e) != 32:
        msg = f"ikm_e must be 32 bytes, got {len(ikm_e)}"
        raise ValueError(msg)
    return _encrypt_with_options(params, recipient_public_key, kid, ikm_e)


def decrypt_disclosure(
    env: DisclosureEnvelope,
    recipient_private_key: bytes,
) -> dict[str, Any]:
    """Recover the plaintext parameters from a v1 HPKE disclosure envelope.

    Args:
        env: The disclosure envelope to decrypt. Statically a
            :class:`DisclosureEnvelope`; at runtime the shape is re-validated
            because callers commonly pass dicts loaded from JSON (e.g., from
            ``json.loads``) which the type system cannot constrain.
        recipient_private_key: 32-byte X25519 forensic private key.

    Returns:
        The decrypted parameters object. The structure reflects the JCS
        plaintext written by :func:`encrypt_disclosure`.

    Raises:
        ValueError: On any envelope-shape, encoding, or authentication
            failure. The error message classifies the failure (version, alg,
            recipient count, base64url shape, ciphertext length, AEAD auth).
    """
    # Defensive runtime checks against malformed input: TypedDict only
    # constrains the static type. Callers commonly pass dicts loaded from JSON
    # (e.g., ``json.loads`` output), so re-validate the shape here.
    if env is None:  # pyright: ignore[reportUnnecessaryComparison]
        msg = "disclosure envelope must not be None"
        raise ValueError(msg)
    if not _is_plain_dict(env):
        msg = "disclosure envelope must be a dict"
        raise TypeError(msg)
    v = env.get("v")
    if v != "1":
        msg = f'unsupported envelope version "{v}"'
        raise ValueError(msg)
    alg = env.get("alg")
    if alg != V1_ALG:
        msg = f'unsupported algorithm "{alg}"'
        raise ValueError(msg)
    recipients = env.get("recipients")
    if not isinstance(recipients, list) or len(recipients) != 1:  # pyright: ignore[reportUnnecessaryIsInstance]
        got = len(recipients) if isinstance(recipients, list) else 0  # pyright: ignore[reportUnnecessaryIsInstance]
        msg = f"v1 envelope must have exactly 1 recipient, got {got}"
        raise ValueError(msg)
    if len(recipient_private_key) != 32:
        msg = (
            f"recipient_private_key must be 32 bytes, got {len(recipient_private_key)}"
        )
        raise ValueError(msg)
    ct = env.get("ct")
    # 24 chars = 18 bytes minimum: AES-256-GCM 16-byte tag + 2-byte minimum
    # plaintext ("{}").
    if not isinstance(ct, str) or len(ct) < 24:  # pyright: ignore[reportUnnecessaryIsInstance]
        got = len(ct) if isinstance(ct, str) else 0  # pyright: ignore[reportUnnecessaryIsInstance]
        msg = (
            "ct is too short: expected at least 24 unpadded base64url "
            f"characters, got {got}"
        )
        raise ValueError(msg)

    recipient = recipients[0]
    if not _is_plain_dict(recipient):
        msg = "recipient must be a dict"
        raise TypeError(msg)
    enc_s = recipient.get("enc")
    if not isinstance(enc_s, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        msg = "recipient enc must be a string"
        raise TypeError(msg)
    kid = recipient.get("kid")
    if not isinstance(kid, str) or len(kid) == 0:  # pyright: ignore[reportUnnecessaryIsInstance]
        msg = "recipient kid must be a non-empty string"
        raise ValueError(msg)

    enc = _b64url_decode(enc_s)
    if len(enc) != _N_ENC:
        msg = (
            f"invalid enc: expected {_N_ENC} bytes (X25519 encapsulated key), "
            f"got {len(enc)}"
        )
        raise ValueError(msg)
    ct_bytes = _b64url_decode(ct)

    shared_secret = _decap(enc, recipient_private_key)
    key, base_nonce = _key_schedule_base(shared_secret)

    try:
        plaintext = AESGCM(key).decrypt(base_nonce, ct_bytes, b"")
    except Exception as exc:  # noqa: BLE001 — cryptography raises InvalidTag
        msg = f"HPKE open failed (authentication or decryption error): {exc}"
        raise ValueError(msg) from exc

    try:
        result = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = f"decrypted plaintext is not valid JSON: {exc}"
        raise ValueError(msg) from exc
    if not _is_plain_dict(result):
        msg = "decrypted plaintext is not a JSON object"
        raise ValueError(msg)
    return result
