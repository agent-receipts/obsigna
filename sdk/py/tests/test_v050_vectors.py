"""Cross-SDK v0.5.0 vectors (issuer.runtime open sub-object, ADR-0026).

Asserts that the Python SDK reproduces the pinned ``expectedReceiptHash`` for a
receipt whose issuer carries ``runtime.agent_id`` / ``runtime.agent_type`` and
for a root-agent receipt that omits ``runtime``. Vectors live at
``cross-sdk-tests/v050_vectors.json``.

If a hash diverges, the Python SDK has a wire-format incompatibility with Go and
TS on the new issuer.runtime sub-object — almost always a Pydantic
serialization / alias / omit-when-None issue.
"""

from __future__ import annotations

import json
from pathlib import Path

from obsigna.receipt.hash import hash_receipt
from obsigna.receipt.signing import verify_receipt
from obsigna.receipt.types import AgentReceipt

VECTORS = (
    Path(__file__).parent.parent.parent.parent / "cross-sdk-tests" / "v050_vectors.json"
)


def _load_vectors() -> dict:
    with open(VECTORS, encoding="utf-8") as f:
        return json.load(f)


class TestV050Vectors:
    """Byte-identical reproduction + runtime round-trip for v0.5.0 vectors."""

    def test_runtime_receipt_hash_matches(self) -> None:
        vectors = _load_vectors()
        section = vectors["runtimeReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert hash_receipt(receipt) == section["expectedReceiptHash"]

    def test_runtime_receipt_signature_verifies(self) -> None:
        vectors = _load_vectors()
        public_key = vectors["keys"]["publicKey"]
        section = vectors["runtimeReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert verify_receipt(receipt, public_key) is True

    def test_runtime_members_round_trip(self) -> None:
        vectors = _load_vectors()
        section = vectors["runtimeReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert receipt.issuer.runtime is not None
        assert receipt.issuer.runtime.agent_id == "a3e49db54342a92d4"
        assert receipt.issuer.runtime.agent_type == "general-purpose"

    def test_extended_runtime_preserves_unknown_key(self) -> None:
        # Open-container gate: a runtime key the SDK does not model (trace_id)
        # must survive model round-trip and still hash to the pinned digest
        # (ADR-0026). extra="allow" on Runtime keeps it; model_dump re-emits it.
        vectors = _load_vectors()
        section = vectors["extendedRuntimeReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert receipt.issuer.runtime is not None
        assert (
            getattr(receipt.issuer.runtime, "trace_id", None)
            == "4bf92f3577b34da6a3ce929d0e0e4736"
        )
        assert hash_receipt(receipt) == section["expectedReceiptHash"]

    def test_root_agent_receipt_hash_matches(self) -> None:
        vectors = _load_vectors()
        section = vectors["rootAgentReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert hash_receipt(receipt) == section["expectedReceiptHash"]

    def test_root_agent_receipt_omits_runtime(self) -> None:
        vectors = _load_vectors()
        section = vectors["rootAgentReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert receipt.issuer.runtime is None
