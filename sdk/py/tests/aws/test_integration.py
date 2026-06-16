"""Real-KMS integration test.

Skipped unless AGENTRECEIPTS_AWS_KMS_INTEGRATION_KEY_ARN is set, so CI stays
offline by default. Run it locally against a real ECC_NIST_EDWARDS25519 KMS key
with ambient credentials able to call kms:Sign and kms:GetPublicKey:

    AGENTRECEIPTS_AWS_KMS_INTEGRATION_KEY_ARN=arn:aws:kms:...:key/... \\
        uv run pytest tests/aws/test_integration.py -v
"""

from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from obsigna.aws import KMSSigner

_KEY_ARN = os.environ.get("AGENTRECEIPTS_AWS_KMS_INTEGRATION_KEY_ARN")


@pytest.mark.skipif(
    not _KEY_ARN,
    reason="set AGENTRECEIPTS_AWS_KMS_INTEGRATION_KEY_ARN to run",
)
def test_sign_and_verify() -> None:
    assert _KEY_ARN is not None
    signer = KMSSigner(_KEY_ARN, timeout=15.0)

    raw = signer.get_public_key()
    assert len(raw) == 32

    pub = Ed25519PublicKey.from_public_bytes(raw)
    message = b"agent-receipts kms integration test message"
    sig = signer.sign(message)

    pub.verify(sig, message)  # raises InvalidSignature on failure
