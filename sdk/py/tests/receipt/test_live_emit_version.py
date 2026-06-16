"""Cross-SDK live-emit version invariant.

Every SDK's ``createReceipt()`` (Go: ``Create``) MUST stamp the literal
``LIVE_EMIT_VERSION`` string into the receipt's ``version`` field. The Go, TS,
and Python SDKs each carry their own copy of this test pinned to the same
literal — drift in any single SDK's VERSION constant breaks that SDK's test
in isolation, closing the gap surfaced by issue #512 where the existing
v030 cross-SDK byte-identicality tests load a pre-built JSON fixture and
never consult the SDK's ``VERSION`` constant.

Parallel files:

- ``sdk/go/receipt/live_emit_version_test.go``
- ``sdk/ts/src/receipt/live-emit-version.test.ts``
"""

from __future__ import annotations

from obsigna.receipt.create import (
    ActionInput,
    CreateReceiptInput,
    create_receipt,
)
from obsigna.receipt.types import (
    VERSION,
    Chain,
    Issuer,
    Outcome,
    Principal,
)

LIVE_EMIT_VERSION = "0.5.0"


class TestCreateReceiptCrossSDKVersion:
    def _make_input(self) -> CreateReceiptInput:
        return CreateReceiptInput(
            issuer=Issuer(id="did:agent:test"),
            principal=Principal(id="did:user:test"),
            action=ActionInput(
                type="filesystem.file.read",
                risk_level="low",
            ),
            outcome=Outcome(status="success"),
            chain=Chain(
                sequence=1,
                previous_receipt_hash=None,
                chain_id="chain_test",
            ),
        )

    def test_create_receipt_stamps_cross_sdk_literal(self) -> None:
        receipt = create_receipt(self._make_input())
        assert receipt.version == LIVE_EMIT_VERSION

    def test_version_constant_matches_cross_sdk_literal(self) -> None:
        assert VERSION == LIVE_EMIT_VERSION
