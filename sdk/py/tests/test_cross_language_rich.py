"""Cross-language check for a receipt with action.target and parameters_hash.

``cross-sdk-tests/py_vectors.json`` carries a rich receipt signed by this SDK.
The minimal receipt in the same file leaves target and parameters_hash out, so
without this test a Python normalization drift on those fields would pass CI.
"""

from __future__ import annotations

import json
from pathlib import Path

from obsigna.receipt.signing import sign_receipt, verify_receipt
from obsigna.receipt.types import AgentReceipt, UnsignedAgentReceipt

VECTORS = Path(__file__).parents[3] / "cross-sdk-tests" / "py_vectors.json"


def _load_rich() -> dict:
    with open(VECTORS) as f:
        return json.load(f)["signingRich"]


class TestRichReceiptVector:
    def test_committed_rich_receipt_verifies(self) -> None:
        rich = _load_rich()
        vectors = json.loads(VECTORS.read_text())
        receipt = AgentReceipt(**rich["signed"])
        assert verify_receipt(receipt, vectors["keys"]["publicKey"]) is True

    def test_resigning_unsigned_rich_receipt_reproduces_proof(self) -> None:
        rich = _load_rich()
        vectors = json.loads(VECTORS.read_text())
        unsigned = UnsignedAgentReceipt.model_validate(rich["unsigned"])
        signed = sign_receipt(
            unsigned, vectors["keys"]["privateKey"], rich["verificationMethod"]
        )
        assert signed.proof.proofValue == rich["signed"]["proof"]["proofValue"]

    def test_rich_receipt_fails_when_target_is_changed(self) -> None:
        rich = _load_rich()
        vectors = json.loads(VECTORS.read_text())
        receipt = AgentReceipt(**rich["signed"])
        receipt.credentialSubject.action.target.resource = "payments/pay_other"
        assert verify_receipt(receipt, vectors["keys"]["publicKey"]) is False


TS_RICH_VECTORS = Path(__file__).parents[3] / "cross-sdk-tests" / "ts_rich_vectors.json"


class TestTSRichReceiptVector:
    """The receipt TypeScript signed must verify here and carry the same proof."""

    def test_ts_signed_rich_receipt_verifies(self) -> None:
        ts = json.loads(TS_RICH_VECTORS.read_text())
        receipt = AgentReceipt(**ts["signed"])
        assert verify_receipt(receipt, ts["keys"]["publicKey"]) is True

    def test_ts_and_python_produce_the_same_proof_value(self) -> None:
        ts = json.loads(TS_RICH_VECTORS.read_text())
        py = _load_rich()
        assert (
            ts["signed"]["proof"]["proofValue"] == py["signed"]["proof"]["proofValue"]
        )
