"""did:key v0.7 generation and resolution (ADR-0007).

Implements the normative wire shape from
``docs/adr/0007-did-method-strategy.md`` ("Implementation spec — did:key
v0.7 wire format"), which all SDKs and the hub re-verifier conform to. Do
not diverge from the ADR without updating it and
``spec/test-vectors/did-key/vectors.json`` first.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_PREFIX = "did:key:z"
_MULTICODEC_ED25519 = b"\xed\x01"
_PAYLOAD_LEN = 34  # 2-byte multicodec prefix + 32-byte Ed25519 public key
_PUBLIC_KEY_LEN = 32

# Bitcoin base58 alphabet: 0, O, I, and l are excluded to avoid visual
# ambiguity, per ADR-0007's resolution algorithm.
_BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58BTC_INDEX = {ch: i for i, ch in enumerate(_BASE58BTC_ALPHABET)}


@dataclass(frozen=True)
class VerificationMethod:
    """A single entry in a DID Document's ``verificationMethod`` array."""

    id: str
    type: str
    controller: str
    public_key_multibase: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "controller": self.controller,
            "publicKeyMultibase": self.public_key_multibase,
        }


@dataclass(frozen=True)
class Document:
    """A resolved did:key DID Document, per ADR-0007's "DID Document shape"."""

    id: str
    verification_method: list[VerificationMethod]
    authentication: list[str]
    assertion_method: list[str]
    context: list[str] = field(
        default_factory=lambda: [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ]
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "@context": list(self.context),
            "id": self.id,
            "verificationMethod": [vm.to_dict() for vm in self.verification_method],
            "authentication": list(self.authentication),
            "assertionMethod": list(self.assertion_method),
        }


def _base58btc_encode(data: bytes) -> str:
    zeros = 0
    for b in data:
        if b != 0:
            break
        zeros += 1

    n = int.from_bytes(data, "big")
    digits: list[str] = []
    while n > 0:
        n, rem = divmod(n, 58)
        digits.append(_BASE58BTC_ALPHABET[rem])
    digits.extend(_BASE58BTC_ALPHABET[0] for _ in range(zeros))
    return "".join(reversed(digits))


def _base58btc_decode(s: str) -> bytes:
    zeros = 0
    for ch in s:
        if ch != _BASE58BTC_ALPHABET[0]:
            break
        zeros += 1

    n = 0
    for i, ch in enumerate(s):
        idx = _BASE58BTC_INDEX.get(ch)
        if idx is None:
            msg = f"invalid base58btc character {ch!r} at position {i}"
            raise ValueError(msg)
        n = n * 58 + idx

    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    return b"\x00" * zeros + body


def from_public_key(public_key: bytes) -> str:
    """Derive the did:key identifier for a raw Ed25519 public key.

    ``did:key:z<base58btc(0xed01 || pubkey)>``. Raises ``ValueError`` if
    ``public_key`` is not exactly 32 bytes (RFC 8032 §5.1.5).
    """
    if len(public_key) != _PUBLIC_KEY_LEN:
        msg = f"did: public key must be {_PUBLIC_KEY_LEN} bytes, got {len(public_key)}"
        raise ValueError(msg)
    payload = _MULTICODEC_ED25519 + public_key
    return _PREFIX + _base58btc_encode(payload)


def resolve(did: str) -> Document:
    """Resolve a did:key identifier to its DID Document.

    Implements the ADR-0007 resolution algorithm: resolution is purely a
    function of the input string — no network access or out-of-band state
    is consulted. Raises ``ValueError`` if ``did`` does not begin with the
    literal prefix ``did:key:z``, contains a base58btc-invalid character,
    decodes to a payload whose length is not exactly 34 bytes, or carries a
    multicodec other than ``0xed01``.
    """
    if not did.startswith(_PREFIX):
        msg = f"did: {did!r} does not have the required {_PREFIX!r} prefix"
        raise ValueError(msg)

    # z_and_payload is the "z<X>" substring: the multibase prefix character
    # plus the base58btc-encoded payload. It doubles as the verification
    # method fragment and publicKeyMultibase value per the ADR's DID
    # Document shape.
    z_and_payload = did[len("did:key:") :]

    try:
        payload = _base58btc_decode(z_and_payload[1:])
    except ValueError as exc:
        msg = f"did: invalid base58btc encoding: {exc}"
        raise ValueError(msg) from exc

    if len(payload) != _PAYLOAD_LEN:
        msg = f"did: decoded payload must be {_PAYLOAD_LEN} bytes, got {len(payload)}"
        raise ValueError(msg)
    if payload[:2] != _MULTICODEC_ED25519:
        msg = (
            f"did: unsupported multicodec {payload[:2].hex()}, "
            "only ed01 (Ed25519) is accepted"
        )
        raise ValueError(msg)

    vm_id = f"{did}#{z_and_payload}"
    return Document(
        id=did,
        verification_method=[
            VerificationMethod(
                id=vm_id,
                type="Multikey",
                controller=did,
                public_key_multibase=z_and_payload,
            )
        ],
        authentication=[vm_id],
        assertion_method=[vm_id],
    )
