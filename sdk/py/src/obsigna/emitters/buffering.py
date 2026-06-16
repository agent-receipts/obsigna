"""BufferingEmitter — in-memory batch buffer with timer flush (ADR-0020).

Wraps a downstream :class:`Emitter` and buffers receipts in memory,
flushing on a configurable interval or batch size.

The contract with the downstream emitter is per-receipt, NOT batched:
a flush calls ``inner.emit(receipt)`` once per buffered receipt.

!!! CRASH-LOSS RISK !!!
Buffered receipts are lost if the process exits before :meth:`flush`
completes. This emitter is NOT suitable for environments where audit
completeness is critical. Use a synchronous :class:`HttpEmitter` (or a
persistent WAL — tracked separately) when every receipt must reach the
collector.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

from obsigna.emitters.types import BufferingFlushError

if TYPE_CHECKING:
    from obsigna.emitters.types import Emitter
    from obsigna.receipt.types import AgentReceipt


logger = logging.getLogger(__name__)


class BufferingEmitter:
    """Per-receipt batching wrapper around a downstream :class:`Emitter`.

    Parameters
    ----------
    inner:
        Downstream emitter. Each buffered receipt is delivered with a
        separate ``inner.emit(receipt)`` call when the buffer flushes.
    max_batch_size:
        Flush when the buffer reaches this many receipts. Must be >= 1.
    flush_interval_ms:
        Flush every N milliseconds while receipts are buffered. Must be
        >= 1. The interval timer only runs when at least one receipt is
        buffered — there is no idle-process tick.
    """

    def __init__(
        self,
        *,
        inner: Emitter,
        max_batch_size: int,
        flush_interval_ms: int,
    ) -> None:
        if max_batch_size < 1:
            raise ValueError("BufferingEmitter: max_batch_size must be >= 1")
        if flush_interval_ms < 1:
            raise ValueError("BufferingEmitter: flush_interval_ms must be >= 1")
        self._inner = inner
        self._max_batch_size = max_batch_size
        self._flush_interval = flush_interval_ms / 1000.0

        self._lock = threading.Lock()
        # Held across every delivery loop so concurrent emit() callers
        # (or an emit racing with the timer) cannot interleave batches at
        # the inner emitter. The two locks must NEVER be held together:
        # always release self._lock before acquiring self._delivery_lock.
        self._delivery_lock = threading.Lock()
        self._buffer: list[AgentReceipt] = []
        self._timer: threading.Timer | None = None
        self._closed = False

    def emit(self, receipt: AgentReceipt) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("BufferingEmitter: closed")
            self._buffer.append(receipt)
            if len(self._buffer) >= self._max_batch_size:
                # Drop the buffer lock before flushing — downstream
                # emit() may take a long time and we don't want
                # concurrent emit() callers to stall on it. Ordering is
                # preserved by self._delivery_lock around _deliver.
                batch = self._buffer[:]
                self._buffer.clear()
                self._cancel_timer_locked()
            else:
                self._schedule_timer_locked()
                return
        self._deliver(batch)

    def flush(self) -> None:
        """Drain the buffer through the downstream emitter.

        If one or more downstream calls raise, the rest of the batch is
        still attempted and a :class:`BufferingFlushError` carrying every
        failure is raised at the end. Retries are the inner emitter's
        responsibility — failed receipts are not re-queued.
        """
        with self._lock:
            self._cancel_timer_locked()
            batch = self._buffer[:]
            self._buffer.clear()
        self._deliver(batch)

    def close(self) -> None:
        """Stop the interval timer and flush the remaining buffer."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._cancel_timer_locked()
            batch = self._buffer[:]
            self._buffer.clear()
        self._deliver(batch)

    # ------------------------------------------------------------------

    def _deliver(self, batch: list[AgentReceipt]) -> None:
        # Per-receipt delivery serialised through self._delivery_lock so
        # concurrent emits / explicit flush / timer flush never
        # interleave batches at the inner emitter.
        if not batch:
            return
        with self._delivery_lock:
            errors: list[BaseException] = []
            for receipt in batch:
                try:
                    self._inner.emit(receipt)
                except (
                    Exception  # noqa: BLE001 — aggregate; surface every failure
                ) as exc:
                    errors.append(exc)
        if not errors:
            return
        if len(errors) == 1:
            raise errors[0]
        raise BufferingFlushError(
            f"BufferingEmitter: {len(errors)} of {len(batch)} receipts failed",
            errors,
        )

    def _schedule_timer_locked(self) -> None:
        # Caller must hold self._lock. Idempotent: a running timer is
        # not replaced — emit() relies on the existing tick.
        if self._timer is not None:
            return
        t = threading.Timer(self._flush_interval, self._on_timer)
        t.daemon = True
        self._timer = t
        t.start()

    def _cancel_timer_locked(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _on_timer(self) -> None:
        with self._lock:
            self._timer = None
            if self._closed:
                return
            batch = self._buffer[:]
            self._buffer.clear()
        if not batch:
            return
        # Log at debug — the timer thread must not crash on downstream
        # errors. Callers that need surfaced errors should rely on the
        # explicit flush()/close() path which raises.
        try:
            self._deliver(batch)
        except Exception as exc:  # noqa: BLE001 — timer must not crash
            logger.debug(
                "BufferingEmitter: timer flush failed",
                extra={"err": str(exc)},
            )
