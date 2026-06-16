"""Cross-SDK v0.3.0 vectors (PR #499, parameters_disclosure Phase 2).

Asserts that the Python SDK reproduces the pinned ``expectedReceiptHash``
values for the v0.3.0 cross-SDK test vectors at
``cross-sdk-tests/v030_vectors.json``. The vectors exercise:

- ``parametersDisclosureEnvelopeReceipt`` — receipt whose
  ``action.parameters_disclosure`` is the HPKE asymmetric envelope, with the
  envelope bytes taken from spec/test-vectors vector-1 (RFC 9180 §A.1.1
  ``pkEm`` cross-check).
- ``peerCredentialEmitterMetadataReceipt`` — receipt exercising the new
  daemon-attested typed fields ``action.peer_credential`` and
  ``action.emitter_metadata.drop_count``.
- ``peerCredentialRootReceipt`` — receipt with ``peer_credential.uid=0`` and
  ``gid=0`` (root). Pins that zero values are present on the wire as
  ``"uid":0`` rather than being dropped — fixes issue #511.

If any hash diverges, the Python SDK has a wire-format incompatibility
with Go (#468/#499) and TS (#472/#503) — almost always a Pydantic
serialization / alias / omit-when-None issue.
"""

from __future__ import annotations

import json
from pathlib import Path

from obsigna.receipt.hash import hash_receipt
from obsigna.receipt.signing import verify_receipt
from obsigna.receipt.types import AgentReceipt

VECTORS = (
    Path(__file__).parent.parent.parent.parent / "cross-sdk-tests" / "v030_vectors.json"
)


def _load_vectors() -> dict:
    with open(VECTORS, encoding="utf-8") as f:
        return json.load(f)


class TestV030Vectors:
    """Byte-identical reproduction of the v0.3.0 cross-SDK vectors."""

    def test_envelope_receipt_hash_matches(self) -> None:
        """Envelope-shape parameters_disclosure receipt hashes identically."""
        vectors = _load_vectors()
        section = vectors["parametersDisclosureEnvelopeReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert hash_receipt(receipt) == section["expectedReceiptHash"]

    def test_envelope_receipt_signature_verifies(self) -> None:
        """Go-signed envelope-shape receipt verifies under the Python SDK."""
        vectors = _load_vectors()
        public_key = vectors["keys"]["publicKey"]
        section = vectors["parametersDisclosureEnvelopeReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert verify_receipt(receipt, public_key) is True

    def test_peer_credential_receipt_hash_matches(self) -> None:
        """peer_credential + emitter_metadata receipt hashes identically."""
        vectors = _load_vectors()
        section = vectors["peerCredentialEmitterMetadataReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert hash_receipt(receipt) == section["expectedReceiptHash"]

    def test_peer_credential_receipt_signature_verifies(self) -> None:
        """Go-signed peer_credential receipt verifies under the Python SDK."""
        vectors = _load_vectors()
        public_key = vectors["keys"]["publicKey"]
        section = vectors["peerCredentialEmitterMetadataReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert verify_receipt(receipt, public_key) is True

    def test_root_receipt_hash_matches(self) -> None:
        """peer_credential uid=0/gid=0 (root) receipt hashes identically."""
        vectors = _load_vectors()
        section = vectors["peerCredentialRootReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert hash_receipt(receipt) == section["expectedReceiptHash"]

    def test_root_receipt_signature_verifies(self) -> None:
        """Go-signed root peer_credential receipt verifies under the Python SDK."""
        vectors = _load_vectors()
        public_key = vectors["keys"]["publicKey"]
        section = vectors["peerCredentialRootReceipt"]
        receipt = AgentReceipt.model_validate(section["receipt"])
        assert verify_receipt(receipt, public_key) is True
