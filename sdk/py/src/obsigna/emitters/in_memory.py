"""InMemoryEmitter — array-backed test double (ADR-0020).

Performs no I/O and provides no delivery guarantee. Use in unit and
integration tests where the assertion is against the receipts that
passed through the emitter, not against a remote collector.

NOT for production use.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from obsigna.receipt.types import AgentReceipt


class InMemoryEmitter:
    """Captures emitted receipts in an exposed list. Test double only."""

    def __init__(self) -> None:
        self._received: list[AgentReceipt] = []
        self._lock = threading.Lock()

    @property
    def received(self) -> Sequence[AgentReceipt]:
        """All receipts passed to :meth:`emit`, in arrival order.

        Returns an independent snapshot — mutating it does not affect
        future deliveries, matching the snapshot semantics of the Go SDK
        (``Received()`` returns a copy). Safe to call concurrently with
        :meth:`emit`.
        """
        with self._lock:
            return list(self._received)

    def emit(self, receipt: AgentReceipt) -> None:
        with self._lock:
            self._received.append(receipt)

    def clear(self) -> None:
        """Drop all recorded receipts. Useful between test cases."""
        with self._lock:
            self._received.clear()
