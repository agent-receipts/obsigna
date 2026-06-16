"""Verify receipt chains stored in a ReceiptStore."""

from __future__ import annotations

from typing import TYPE_CHECKING

from obsigna.receipt.chain import verify_chain

if TYPE_CHECKING:
    from obsigna.receipt.chain import ChainVerification
    from obsigna.store.store import ReceiptStore


def verify_stored_chain(
    store: ReceiptStore,
    chain_id: str,
    public_key: str,
) -> ChainVerification:
    """Load a chain from the store and verify its integrity."""
    receipts = store.get_chain(chain_id)
    return verify_chain(receipts, public_key)
