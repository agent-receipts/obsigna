"""Unit tests for the AWS KMS signer, against a mocked KMS client."""

from __future__ import annotations

import threading

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from obsigna.aws import KMSSigner, KMSSignerError
from obsigna.aws.kms import MESSAGE_TYPE, SIGNING_ALGORITHM
from tests.aws.conftest import MockKMSClient

TEST_KEY_ID = "arn:aws:kms:us-east-1:111122223333:key/test-ed25519"


def _new_signer(mock: MockKMSClient) -> KMSSigner:
    return KMSSigner(TEST_KEY_ID, client=mock)


class TestConstruction:
    def test_rejects_empty_key_id(self) -> None:
        with pytest.raises(ValueError, match="key_id must not be empty"):
            KMSSigner("", client=MockKMSClient())

    def test_rejects_negative_timeout(self) -> None:
        with pytest.raises(ValueError, match="timeout must not be negative"):
            KMSSigner(TEST_KEY_ID, region="us-east-1", timeout=-1.0)

    def test_rejects_client_with_region_or_timeout(self) -> None:
        with pytest.raises(ValueError, match="omit them when injecting a client"):
            KMSSigner(TEST_KEY_ID, client=MockKMSClient(), region="us-east-1")


class TestSign:
    def test_signature_verifies_against_public_key(self) -> None:
        mock = MockKMSClient()
        signer = _new_signer(mock)

        message = b"canonical receipt bytes"
        sig = signer.sign(message)

        mock.pub.verify(sig, message)  # raises InvalidSignature on mismatch

    def test_passes_ed25519_algorithm_raw_message_type_and_key_id(self) -> None:
        mock = MockKMSClient()
        signer = _new_signer(mock)

        signer.sign(b"msg")

        assert len(mock.sign_calls) == 1
        call = mock.sign_calls[0]
        assert call["SigningAlgorithm"] == SIGNING_ALGORITHM == "ED25519_SHA_512"
        assert call["MessageType"] == MESSAGE_TYPE == "RAW"
        assert call["KeyId"] == TEST_KEY_ID

    def test_propagates_kms_errors_unchanged(self) -> None:
        sentinel = RuntimeError("AccessDeniedException: not authorized")
        mock = MockKMSClient()

        def boom(_call: dict[str, object]) -> dict[str, object]:
            raise sentinel

        mock.sign_hook = boom
        signer = _new_signer(mock)

        with pytest.raises(RuntimeError) as exc_info:
            signer.sign(b"msg")
        assert exc_info.value is sentinel

    def test_missing_signature_raises_adapter_error(self) -> None:
        mock = MockKMSClient()
        mock.sign_hook = lambda _call: {}
        signer = _new_signer(mock)

        with pytest.raises(KMSSignerError, match="returned no signature"):
            signer.sign(b"msg")


class TestGetPublicKey:
    def test_returns_raw_32_byte_public_key(self) -> None:
        mock = MockKMSClient()
        signer = _new_signer(mock)

        got = signer.get_public_key()

        assert len(got) == 32
        assert got == mock.raw_public_key()

    def test_caches_after_first_call(self) -> None:
        mock = MockKMSClient()
        signer = _new_signer(mock)

        first = signer.get_public_key()
        second = signer.get_public_key()

        assert mock.get_pub_calls == 1
        assert first == second

    def test_propagates_kms_errors_unchanged(self) -> None:
        sentinel = RuntimeError("NotFoundException: key does not exist")
        mock = MockKMSClient()

        def boom(_key_id: str) -> dict[str, object]:
            raise sentinel

        mock.get_pub_hook = boom
        signer = _new_signer(mock)

        with pytest.raises(RuntimeError) as exc_info:
            signer.get_public_key()
        assert exc_info.value is sentinel

    def test_does_not_cache_a_failed_fetch(self) -> None:
        mock = MockKMSClient()
        calls = {"n": 0}
        good = {"PublicKey": mock.spki_der()}

        def hook(_key_id: str) -> dict[str, object]:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("ThrottlingException")
            return good

        mock.get_pub_hook = hook
        signer = _new_signer(mock)

        with pytest.raises(RuntimeError, match="ThrottlingException"):
            signer.get_public_key()
        assert signer.get_public_key() == mock.raw_public_key()

    def test_rejects_non_ed25519_key(self) -> None:
        rsa_der = (
            generate_private_key(public_exponent=65537, key_size=2048)
            .public_key()
            .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        )
        mock = MockKMSClient()
        mock.get_pub_hook = lambda _key_id: {"PublicKey": rsa_der}
        signer = _new_signer(mock)

        with pytest.raises(KMSSignerError, match="not Ed25519"):
            signer.get_public_key()

    def test_fetches_public_key_once_under_concurrency(self) -> None:
        mock = MockKMSClient()
        signer = _new_signer(mock)
        results: list[bytes] = []
        results_lock = threading.Lock()

        def worker() -> None:
            signer.sign(b"msg")
            key = signer.get_public_key()
            with results_lock:
                results.append(key)

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert mock.get_pub_calls == 1
        expected = mock.raw_public_key()
        assert all(r == expected for r in results)

    def test_returned_key_round_trips_a_signature(self) -> None:
        mock = MockKMSClient()
        signer = _new_signer(mock)

        raw = signer.get_public_key()
        pub = Ed25519PublicKey.from_public_bytes(raw)
        message = b"verify me"
        sig = signer.sign(message)

        pub.verify(sig, message)
        with pytest.raises(InvalidSignature):
            pub.verify(sig, b"tampered")
