"""Cross-language compatibility tests: TypeScript SDK.

Verifies that the Python SDK can verify receipts signed by the TypeScript SDK
and produces identical canonicalization and hashing outputs.

This file is narrower than ``test_cross_language_go.py`` because
``ts_vectors.json`` predates v0.2.0 and does not carry response_hash,
chain.terminal, or parameters_disclosure fields. Extending the TS vector
generator to v0.2.0 is tracked separately.
"""

from __future__ import annotations

import json
from pathlib import Path

from obsigna.receipt.hash import canonicalize, hash_receipt, sha256
from obsigna.receipt.signing import generate_key_pair, verify_receipt
from obsigna.receipt.types import AgentReceipt

VECTORS = Path(__file__).parent / "fixtures" / "ts_vectors.json"


def _load_vectors() -> dict:
    with open(VECTORS) as f:
        return json.load(f)


class TestCanonicalizeMatchesTS:
    """Verify RFC 8785 canonicalization matches TypeScript SDK output."""

    def test_simple_object(self) -> None:
        vectors = _load_vectors()
        input_data = vectors["canonicalization"]["simpleInput"]
        expected = vectors["canonicalization"]["simpleExpected"]
        assert canonicalize(input_data) == expected

    def test_unsigned_receipt(self) -> None:
        vectors = _load_vectors()
        input_data = vectors["canonicalization"]["receiptInput"]
        expected = vectors["canonicalization"]["receiptExpected"]
        assert canonicalize(input_data) == expected


class TestSha256MatchesTS:
    """Verify SHA-256 hashing matches TypeScript SDK output."""

    def test_simple_string(self) -> None:
        vectors = _load_vectors()
        input_data = vectors["hashing"]["simpleInput"]
        expected = vectors["hashing"]["simpleExpected"]
        assert sha256(input_data) == expected

    def test_receipt_hash(self) -> None:
        vectors = _load_vectors()
        signed_data = vectors["signing"]["signed"]
        expected_hash = vectors["hashing"]["receiptExpected"]
        receipt = AgentReceipt(**signed_data)
        assert hash_receipt(receipt) == expected_hash


class TestVerifyTSSignature:
    """Verify that receipts signed by the TypeScript SDK verify in Python."""

    def test_ts_signature_verifies(self) -> None:
        vectors = _load_vectors()
        signed_data = vectors["signing"]["signed"]
        public_key = vectors["keys"]["publicKey"]
        receipt = AgentReceipt(**signed_data)
        assert verify_receipt(receipt, public_key) is True

    def test_ts_signature_fails_with_wrong_key(self) -> None:
        vectors = _load_vectors()
        signed_data = vectors["signing"]["signed"]
        receipt = AgentReceipt(**signed_data)
        other_keys = generate_key_pair()
        assert verify_receipt(receipt, other_keys.public_key) is False

    def test_ts_signature_fails_when_tampered(self) -> None:
        vectors = _load_vectors()
        signed_data = vectors["signing"]["signed"]
        public_key = vectors["keys"]["publicKey"]
        receipt = AgentReceipt(**signed_data)
        receipt.credentialSubject.action.type = "filesystem.file.delete"
        assert verify_receipt(receipt, public_key) is False
