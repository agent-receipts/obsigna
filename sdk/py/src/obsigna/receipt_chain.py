"""ReceiptChain — serialised, stateful receipt construction (ADR-0020, #488).

Client-side chaining requires that receipt N is fully signed and its hash
computed before receipt N+1 is constructed. A sequential agent satisfies this
automatically, but an agent that fires parallel tool calls would race on the
shared chain head (``sequence`` + ``previous_receipt_hash``), producing
colliding sequence numbers or a forked hash link.

:class:`ReceiptChain` owns that mutable head. It builds, signs, hashes, links,
and delivers each receipt under a single lock, so concurrent
:meth:`ReceiptChain.emit` calls are sequenced at the receipt layer even when
the tool calls that triggered them ran in parallel. Concurrent calls are not
an error — they block until the in-flight one completes — but the first time
overlap is detected a warning is logged, since concurrent emission usually
means the caller assumed parallel chains are supported. They are not in v1;
a future ADR may add forked sub-chains.

The head advances (sequence + previous hash) as soon as a receipt is signed
and hashed — *before* delivery — so a delivery failure leaves the chain intact
and linkable. Pair with a WAL-backed emitter for at-least-once delivery (see
ADR-0020 § "At-least-once delivery and the WAL").
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel

from obsigna.receipt.create import (
    ActionInput,
    CreateReceiptInput,
    create_receipt,
)
from obsigna.receipt.hash import hash_receipt
from obsigna.receipt.signing import sign_receipt
from obsigna.receipt.types import (
    Authorization,
    Chain,
    Intent,
    Issuer,
    Outcome,
    Principal,
)

if TYPE_CHECKING:
    from obsigna.emitters.types import Emitter
    from obsigna.receipt.types import AgentReceipt

logger = logging.getLogger(__name__)

_CONCURRENT_EMIT_MESSAGE = (
    "concurrent emit() detected on a ReceiptChain; receipt construction is "
    "serialised at the receipt layer (ADR-0020), parallel tool calls cannot "
    "build receipts concurrently in v1 — concurrent calls are serialised in an "
    "unspecified order under contention"
)


class ChainEmitInput(BaseModel):
    """Per-receipt inputs for :meth:`ReceiptChain.emit`.

    Mirrors :class:`CreateReceiptInput` minus ``chain``: the chain head
    (sequence, previous_receipt_hash, chain_id) is owned by the
    :class:`ReceiptChain` and must not be supplied per call.
    """

    issuer: Issuer
    principal: Principal
    action: ActionInput
    outcome: Outcome
    intent: Intent | None = None
    authorization: Authorization | None = None
    action_timestamp: str | None = None
    response_body: Any = None  # noqa: ANN401  # any JSON value, not just objects
    terminal: bool = False
    termination_status: Literal["complete", "interrupted"] | None = None


class ReceiptChain:
    """Stateful, serialised builder for a single hash-linked receipt chain.

    Construct one per chain (typically one per agent session, or one per
    serverless invocation — see the ephemeral-compute deployment guide), then
    call :meth:`emit` for each action. See the module docstring for the
    concurrency contract.
    """

    def __init__(
        self,
        *,
        chain_id: str,
        private_key: str,
        verification_method: str,
        emitter: Emitter,
        start_sequence: int = 1,
        previous_receipt_hash: str | None = None,
        warn_logger: logging.Logger | None = None,
    ) -> None:
        if not chain_id:
            msg = "ReceiptChain: chain_id is required"
            raise ValueError(msg)
        if not private_key:
            msg = "ReceiptChain: private_key is required"
            raise ValueError(msg)
        if not verification_method:
            msg = "ReceiptChain: verification_method is required"
            raise ValueError(msg)
        # Duck-typed rather than `is None` so the guard also rejects objects
        # that are not emitters, and so it holds even if a caller passes None
        # past the type checker (which `is None` would flag as unreachable).
        if not callable(getattr(emitter, "emit", None)):
            msg = "ReceiptChain: emitter is required (must provide an emit() method)"
            raise ValueError(msg)
        if start_sequence < 1:
            msg = "ReceiptChain: start_sequence must be a positive integer (>= 1)"
            raise ValueError(msg)
        self._chain_id = chain_id
        self._private_key = private_key
        self._verification_method = verification_method
        self._emitter = emitter
        self._logger = warn_logger or logger
        self._sequence = start_sequence
        self._previous_hash = previous_receipt_hash
        # Serialises build + sign + hash + advance + deliver.
        self._lock = threading.Lock()
        # Guards the in-flight counter and the warn-once flag.
        self._state_lock = threading.Lock()
        self._active = 0
        self._warned = False
        # Set once a terminal receipt is signed; rejects further emit().
        self._closed = False

    @property
    def chain_id(self) -> str:
        """The ``chain_id`` stamped on every receipt this chain emits."""
        return self._chain_id

    @property
    def next_sequence(self) -> int:
        """Sequence number the next emitted receipt will carry."""
        with self._lock:
            return self._sequence

    @property
    def previous_receipt_hash(self) -> str | None:
        """Hash the next receipt will link to (``None`` before the first)."""
        with self._lock:
            return self._previous_hash

    def emit(self, input: ChainEmitInput) -> AgentReceipt:  # noqa: A002
        """Build, sign, hash-link, and deliver one receipt.

        Returns the signed :class:`AgentReceipt`. Calls are serialised: receipt
        N is fully constructed and its head committed before receipt N+1
        begins, even when :meth:`emit` is invoked from multiple threads.

        Raises (after the head has advanced) if the underlying emitter raises:
        the receipt was signed and the chain head moved on, so use a WAL-backed
        emitter when delivery durability matters.

        Emitting a receipt with ``terminal=True`` closes the chain: any later
        :meth:`emit` raises :class:`RuntimeError` rather than linking a receipt
        after the terminal one (which :func:`verify_chain` would reject).
        """
        with self._state_lock:
            self._active += 1
            warn = self._active > 1 and not self._warned
            if warn:
                self._warned = True
        if warn:
            self._logger.warning(_CONCURRENT_EMIT_MESSAGE)
        try:
            with self._lock:
                if self._closed:
                    msg = (
                        "ReceiptChain: terminal receipt already emitted; "
                        "chain is closed"
                    )
                    raise RuntimeError(msg)
                chain = Chain(
                    sequence=self._sequence,
                    previous_receipt_hash=self._previous_hash,
                    chain_id=self._chain_id,
                )
                unsigned = create_receipt(
                    CreateReceiptInput(
                        issuer=input.issuer,
                        principal=input.principal,
                        action=input.action,
                        outcome=input.outcome,
                        chain=chain,
                        intent=input.intent,
                        authorization=input.authorization,
                        action_timestamp=input.action_timestamp,
                        response_body=input.response_body,
                        terminal=input.terminal,
                        termination_status=input.termination_status,
                    )
                )
                signed = sign_receipt(
                    unsigned, self._private_key, self._verification_method
                )
                # Advance the head from the just-signed receipt before delivery
                # so a delivery failure cannot fork or stall the chain
                # (ADR-0020 WAL model).
                self._previous_hash = hash_receipt(signed)
                self._sequence += 1
                # A terminal receipt closes the chain: nothing links after it.
                if input.terminal:
                    self._closed = True
                self._emitter.emit(signed)
                return signed
        finally:
            with self._state_lock:
                self._active -= 1
