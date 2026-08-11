"""Ed25519 signing and verification for Agent Receipts."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from obsigna.receipt.hash import (
    canonicalize,
    normalize_receipt_dict,
    parse_raw_object,
)
from obsigna.receipt.types import (
    AgentReceipt,
    Proof,
    UnsignedAgentReceipt,
)

MULTIBASE_BASE64URL = "u"
"""Multibase prefix for base64url (no padding) encoding."""

PROOF_TYPE_ED25519_SIGNATURE_2020 = "Ed25519Signature2020"
"""The only proof.type the spec accepts. Verifiers MUST reject any other
value so that consumers cannot be tricked into believing a receipt was
signed under a different scheme.
"""


@dataclass
class KeyPair:
    """Ed25519 key pair (PEM-encoded)."""

    public_key: str
    private_key: str


def generate_key_pair() -> KeyPair:
    """Generate an Ed25519 key pair (PEM-encoded).

    Returns PEM-encoded keys: SPKI for public, PKCS8 for private.
    """
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode("ascii")
    public_pem = (
        private_key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
    return KeyPair(public_key=public_pem, private_key=private_pem)


def _canonicalize_receipt(receipt: UnsignedAgentReceipt) -> bytes:
    """Serialize an unsigned receipt to bytes using RFC 8785."""
    d = receipt.model_dump(by_alias=True, exclude_none=True)
    # Ensure previous_receipt_hash is preserved as null when None
    chain = d.get("credentialSubject", {}).get("chain", {})
    if "previous_receipt_hash" not in chain:
        chain["previous_receipt_hash"] = None
    return canonicalize(d).encode("utf-8")


def sign_receipt(
    unsigned: UnsignedAgentReceipt,
    private_key: str,
    verification_method: str,
) -> AgentReceipt:
    """Sign an unsigned receipt, returning a complete AgentReceipt with proof."""
    data = _canonicalize_receipt(unsigned)

    key = load_pem_private_key(private_key.encode("ascii"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        msg = "Expected Ed25519 private key"
        raise TypeError(msg)

    signature = key.sign(data)
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")

    now = datetime.now(UTC)
    created = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"

    proof = Proof(
        type=PROOF_TYPE_ED25519_SIGNATURE_2020,
        created=created,
        verificationMethod=verification_method,
        proofPurpose="assertionMethod",
        proofValue=f"{MULTIBASE_BASE64URL}{sig_b64}",
    )

    return AgentReceipt(
        **unsigned.model_dump(by_alias=True),
        proof=proof,
    )


def _verify_ed25519(data: bytes, proof_value: str, public_key: str) -> bool:
    """Check an Ed25519 signature encoded in ``proof_value`` over ``data``.

    Shared crypto core of ``verify_receipt`` and ``verify_raw`` once each
    has validated ``proof.type``; the two differ only in how they derive
    ``data`` (model re-serialization vs. verbatim wire bytes).
    """
    if len(proof_value) < 2 or not proof_value.startswith(MULTIBASE_BASE64URL):
        return False

    # Decode base64url signature (add padding back)
    sig_b64 = proof_value[1:]
    padding = 4 - len(sig_b64) % 4
    if padding != 4:
        sig_b64 += "=" * padding

    try:
        signature = base64.urlsafe_b64decode(sig_b64)
    except Exception:  # noqa: BLE001
        return False

    try:
        key = load_pem_public_key(public_key.encode("ascii"))
    except Exception:  # noqa: BLE001
        return False

    if not isinstance(key, Ed25519PublicKey):
        return False

    try:
        key.verify(signature, data)
    except InvalidSignature:
        return False

    return True


def verify_receipt(receipt: AgentReceipt, public_key: str) -> bool:
    """Verify the Ed25519 signature on a signed receipt."""
    if receipt.proof.type != PROOF_TYPE_ED25519_SIGNATURE_2020:
        return False

    # Reconstruct unsigned receipt
    d = receipt.model_dump(by_alias=True, exclude_none=True)
    d.pop("proof", None)
    # Ensure previous_receipt_hash is preserved as null
    chain = d.get("credentialSubject", {}).get("chain", {})
    if "previous_receipt_hash" not in chain:
        chain["previous_receipt_hash"] = None

    data = canonicalize(d).encode("utf-8")
    return _verify_ed25519(data, receipt.proof.proofValue, public_key)


def verify_raw(raw: bytes | str | dict[str, Any], public_key: str) -> bool:
    """Verify the Ed25519 signature on a receipt's verbatim wire JSON.

    ``verify_receipt`` reconstructs canonical bytes from ``model_dump()`` of
    the ``AgentReceipt`` Pydantic model, so a field a newer SDK signed over
    but the installed model does not know about is silently dropped before
    verification — turning a genuinely valid signature into a false
    negative. This function instead canonicalizes the on-wire JSON object
    directly (minus ``proof``), so every field present on the wire
    contributes to the verified payload. It is the verification counterpart
    to ``hash_raw_receipt``, and the Python equivalent of the Go SDK's
    ``VerifyRaw``.

    Accepts raw JSON bytes/str or an already-parsed dict. Raises
    ``ValueError`` if ``raw`` does not decode to a JSON object, carries no
    usable ``proof`` object, ``proof.type`` or ``proof.proofValue`` is
    present but not a string, or ``proof.type`` is not
    ``Ed25519Signature2020``. Returns ``False`` when the signature is
    well-formed but does not verify against ``public_key``.
    """
    generic = parse_raw_object(raw)

    proof = generic.get("proof")
    if not isinstance(proof, dict):
        msg = "raw receipt has no proof object"
        raise ValueError(msg)
    proof = cast("dict[str, Any]", proof)

    proof_type = proof.get("type")
    if proof_type is not None and not isinstance(proof_type, str):
        msg = "raw receipt proof.type is not a string"
        raise ValueError(msg)
    proof_value = proof.get("proofValue")
    if proof_value is not None and not isinstance(proof_value, str):
        msg = "raw receipt proof.proofValue is not a string"
        raise ValueError(msg)

    if proof_type != PROOF_TYPE_ED25519_SIGNATURE_2020:
        msg = (
            f"unsupported proof type {proof_type!r}: only "
            f"{PROOF_TYPE_ED25519_SIGNATURE_2020} is accepted"
        )
        raise ValueError(msg)

    # normalize_receipt_dict applies the same ADR-0009 Rule 2 normalisation
    # sign_receipt applied before signing: Pydantic's model_dump_json (used
    # by the emitters) writes absent optional fields as literal `null`,
    # unlike Go's struct tags, which omit them outright.
    d = normalize_receipt_dict(generic)
    data = canonicalize(d).encode("utf-8")

    return _verify_ed25519(data, proof_value or "", public_key)
