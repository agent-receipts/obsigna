"""CompositeEmitter — sequential fan-out with error aggregation (ADR-0020).

Every child is attempted, in order. If a child raises, the exception is
captured and the remaining children are still attempted. When at least
one child raised, :meth:`emit` raises a :class:`CompositeEmitError`
holding the captured exceptions in the order they were thrown.

Use cases: writing to a primary collector plus an offsite archive, or
dual-writing during an endpoint migration.

Per ADR-0020 every child must implement the :class:`Emitter` Protocol;
:class:`DaemonEmitter` does not (yet) — it accepts unsigned event
frames, not signed receipts.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from obsigna.emitters.types import CompositeEmitError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from obsigna.emitters.types import Emitter
    from obsigna.receipt.types import AgentReceipt


class CompositeEmitter:
    """Forwards each receipt to a list of child emitters sequentially."""

    def __init__(self, children: Sequence[Emitter]) -> None:
        # Defensive copy: mutating the input later must not change behaviour.
        self._children: tuple[Emitter, ...] = tuple(children)

    def emit(self, receipt: AgentReceipt) -> None:
        errors: list[BaseException] = []
        for child in self._children:
            try:
                child.emit(receipt)
            except (
                Exception  # noqa: BLE001 — aggregating arbitrary downstream errors is the contract
            ) as exc:
                errors.append(exc)
        if errors:
            raise CompositeEmitError(
                f"CompositeEmitter: {len(errors)} of {len(self._children)} "
                "child emitters failed",
                errors,
            )
