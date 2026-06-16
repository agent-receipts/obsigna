"""Cross-SDK v0.4.0 vectors (action.idempotency_key, #480).

Asserts that the Python SDK reproduces the pinned ``expectedReceiptHash`` for
the receipt carrying ``action.idempotency_key`` and agrees with Go and TS on
the verifier semantics for a duplicate-key chain (valid + exactly one warning).
Vectors live at ``cross-sdk-tests/v040_vectors.json``.

If the hash diverges, the Python SDK has a wire-format incompatibility with Go
(#480) and TS — almost always a Pydantic serialization / alias / omit-when-None
issue on the new optional field.
"""

from __future__ import annotations

import json
from pathlib import Path

from obsigna.receipt.chain import verify_chain
from obsigna.receipt.hash import hash_receipt
from obsigna.receipt.signing import verify_receipt
from obsigna.receipt.types import AgentReceipt

VECTORS = (
    Path(__file__).parent.parent.parent.parent / "cross-sdk-tests" / "v040_vectors.json"
)


def _load_vectors() -> dict:
    with open(VECTORS, encoding="utf-8") as f:
        return json.load(f)


class TestV040Vectors:
    """Byte-identical reproduction + verifier agreement for v0.4.0 vectors."""

    def test_idempotency_receipt_hash_matches(self) -> None:
        vectors = _load_vectors()
        section = vectors["idempotencyKeyReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert hash_receipt(receipt) == section["expectedReceiptHash"]

    def test_idempotency_receipt_signature_verifies(self) -> None:
        vectors = _load_vectors()
        public_key = vectors["keys"]["publicKey"]
        section = vectors["idempotencyKeyReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert verify_receipt(receipt, public_key) is True

    def test_idempotency_key_round_trips(self) -> None:
        vectors = _load_vectors()
        section = vectors["idempotencyKeyReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert (
            receipt.credentialSubject.action.idempotency_key
            == section["idempotencyKey"]
        )

    def test_duplicate_chain_valid_with_one_warning(self) -> None:
        vectors = _load_vectors()
        public_key = vectors["keys"]["publicKey"]
        section = vectors["duplicateIdempotencyChain"]
        receipts = [AgentReceipt.model_validate(r) for r in section["receipts"]]
        result = verify_chain(receipts, public_key)
        assert result.valid is section["expectedValid"]
        assert len(result.warnings) == section["expectedWarningCount"]
        assert section["duplicateKey"] in result.warnings[0]
