"""KMSSigner wired into the core sign_receipt/verify_receipt pipeline.

Exercises the gap #1086 closed: KMSSigner previously implemented Signer but
nothing in the repo actually passed one into sign_receipt. Uses MockKMSClient
so no real AWS access or the optional ``aws`` extra's boto3 dependency is
needed.
"""

from __future__ import annotations

from obsigna.aws import KMSSigner
from obsigna.receipt.signing import public_key_to_pem, sign_receipt, verify_receipt
from tests.aws.conftest import MockKMSClient
from tests.conftest import make_unsigned

TEST_KEY_ID = "arn:aws:kms:us-east-1:111122223333:key/test-ed25519"


def test_sign_receipt_with_kms_signer_verifies() -> None:
    signer = KMSSigner(TEST_KEY_ID, client=MockKMSClient())
    unsigned = make_unsigned(1, None)

    signed = sign_receipt(unsigned, signer, "did:agent:test#key-1")
    public_pem = public_key_to_pem(signer.get_public_key())

    assert verify_receipt(signed, public_pem) is True


def test_sign_receipt_with_kms_signer_rejects_tampered_receipt() -> None:
    signer = KMSSigner(TEST_KEY_ID, client=MockKMSClient())
    unsigned = make_unsigned(1, None)

    signed = sign_receipt(unsigned, signer, "did:agent:test#key-1")
    signed.credentialSubject.action.type = "filesystem.file.delete"

    public_pem = public_key_to_pem(signer.get_public_key())
    assert verify_receipt(signed, public_pem) is False


def test_sign_receipt_with_kms_signer_rejects_wrong_key() -> None:
    signer = KMSSigner(TEST_KEY_ID, client=MockKMSClient())
    unsigned = make_unsigned(1, None)
    signed = sign_receipt(unsigned, signer, "did:agent:test#key-1")

    other_signer = KMSSigner(TEST_KEY_ID, client=MockKMSClient())
    other_pem = public_key_to_pem(other_signer.get_public_key())
    assert verify_receipt(signed, other_pem) is False
