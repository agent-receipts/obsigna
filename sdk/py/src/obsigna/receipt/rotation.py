"""Key-rotation verification helpers (ADR-0015)."""

from __future__ import annotations

import base64
import hashlib
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

if TYPE_CHECKING:
    from obsigna.receipt.types import KeyRotation

ALGORITHM_ED25519 = "ed25519"
"""The only signature algorithm the protocol supports (ADR-0001).

Cross-algorithm rotation is deferred to the algorithm-agility work and is
rejected by verifiers until then.
"""

_ED25519_PUBLIC_KEY_SIZE = 32


def key_fingerprint(raw: bytes) -> str:
    """Return the ADR-0015 fingerprint of a raw public key.

    SHA-256 of the raw key bytes (Ed25519: 32 bytes per RFC 8032 §5.1.5),
    rendered as ``sha256:<lowercase hex>`` — never an SPKI/PEM wrapper or a
    backend handle.
    """
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def decode_multibase_ed25519_key(s: str) -> bytes:
    """Decode a multibase-"u" base64url string into a 32-byte Ed25519 key.

    This is the encoding ADR-0001 uses for ``proof.proofValue``, applied here to
    raw public-key bytes.
    """
    if not s or s[0] != "u":
        msg = 'expected multibase "u" prefix'
        raise ValueError(msg)
    body = s[1:]
    raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    if len(raw) != _ED25519_PUBLIC_KEY_SIZE:
        msg = f"expected {_ED25519_PUBLIC_KEY_SIZE} key bytes, got {len(raw)}"
        raise ValueError(msg)
    return raw


def ed25519_raw_to_pem(raw: bytes) -> str:
    """Wrap a raw 32-byte Ed25519 public key in PEM-encoded SPKI."""
    key = Ed25519PublicKey.from_public_bytes(raw)
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(
        "ascii"
    )


def pem_to_ed25519_raw(pem: str) -> bytes:
    """Extract the raw 32-byte Ed25519 public key from a PEM-encoded SPKI key."""
    key = load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, Ed25519PublicKey):
        msg = "public key is not Ed25519"
        raise ValueError(msg)
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def verify_rotation_event(active_key_pem: str, kr: KeyRotation) -> str:
    """Validate the rotation-event fields and return the incoming key's PEM.

    Implements the field-level checks of the ADR-0015 verifier traversal: the
    constant fields, the supported-algorithm guard, the old-key fingerprint
    consistency check against the outgoing key, and the new-key fingerprint
    check against the inline ``new_public_key``. The rotation receipt's own
    signature is verified separately by the caller (it is signed with the
    outgoing key). Raises ``ValueError`` on any field or consistency error.
    """
    if kr.event_type != "key_rotated":
        msg = f'event_type must be "key_rotated", got "{kr.event_type}"'
        raise ValueError(msg)
    if kr.signed_with != "old":
        msg = f'signed_with must be "old", got "{kr.signed_with}"'
        raise ValueError(msg)
    if kr.old_algorithm != ALGORITHM_ED25519:
        msg = (
            f'unsupported old_algorithm "{kr.old_algorithm}": '
            f'only "{ALGORITHM_ED25519}" is supported'
        )
        raise ValueError(msg)
    if kr.new_algorithm != ALGORITHM_ED25519:
        msg = (
            f'unsupported new_algorithm "{kr.new_algorithm}": '
            f'only "{ALGORITHM_ED25519}" is supported'
        )
        raise ValueError(msg)

    try:
        out_raw = pem_to_ed25519_raw(active_key_pem)
    except ValueError as exc:
        msg = f"parse outgoing key: {exc}"
        raise ValueError(msg) from exc
    out_fp = key_fingerprint(out_raw)
    if out_fp != kr.old_key_fingerprint:
        msg = (
            f"old_key_fingerprint mismatch: outgoing key is {out_fp}, "
            f"field says {kr.old_key_fingerprint}"
        )
        raise ValueError(msg)

    try:
        new_raw = decode_multibase_ed25519_key(kr.new_public_key)
    except ValueError as exc:
        msg = f"decode new_public_key: {exc}"
        raise ValueError(msg) from exc
    new_fp = key_fingerprint(new_raw)
    if new_fp != kr.new_key_fingerprint:
        msg = (
            f"new_key_fingerprint mismatch: new_public_key hashes to {new_fp}, "
            f"field says {kr.new_key_fingerprint}"
        )
        raise ValueError(msg)

    return ed25519_raw_to_pem(new_raw)
