"""Ed25519 signing and verification for Agent Receipts."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime

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

from obsigna.receipt.hash import canonicalize
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


def verify_receipt(receipt: AgentReceipt, public_key: str) -> bool:
    """Verify the Ed25519 signature on a signed receipt."""
    if receipt.proof.type != PROOF_TYPE_ED25519_SIGNATURE_2020:
        return False
    proof_value = receipt.proof.proofValue
    if len(proof_value) < 2 or not proof_value.startswith(MULTIBASE_BASE64URL):
        return False

    # Reconstruct unsigned receipt
    d = receipt.model_dump(by_alias=True, exclude_none=True)
    d.pop("proof", None)
    # Ensure previous_receipt_hash is preserved as null
    chain = d.get("credentialSubject", {}).get("chain", {})
    if "previous_receipt_hash" not in chain:
        chain["previous_receipt_hash"] = None

    data = canonicalize(d).encode("utf-8")

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
