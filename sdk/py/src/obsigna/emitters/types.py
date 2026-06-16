"""Emitter abstraction for delivering signed agent receipts (ADR-0020).

The :class:`Emitter` Protocol is responsible only for delivery of a
fully-signed, already-chained :class:`AgentReceipt`. Construction,
signing, and chaining stay client-side and upstream of this layer.

The legacy :class:`obsigna.daemon_emitter.DaemonEmitter` forwards
*unsigned* tool-call frames to the agent-receipts daemon and does NOT
implement this Protocol — see ADR-0020 step 2 (tracked separately).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    import threading

    from obsigna.receipt.types import AgentReceipt


@runtime_checkable
class Emitter(Protocol):
    """Delivers a signed :class:`AgentReceipt`.

    Implementations handle transport (HTTPS, in-memory, composite,
    buffered) but never construction, signing, or chaining.
    """

    def emit(self, receipt: AgentReceipt) -> None:
        """Deliver one receipt to the configured downstream.

        Implementations override this; calling it on the Protocol itself
        signals a programming error (the Protocol is structural and
        never meant to be instantiated).
        """
        raise NotImplementedError


class EmitError(Exception):
    """Raised when an :class:`Emitter`'s retry budget is exhausted or a
    non-retryable status is returned.

    Attributes
    ----------
    status:
        HTTP status code from the last attempt, if one was received.
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class CompositeEmitError(Exception):
    """Raised by :class:`CompositeEmitter` when at least one child fails.

    The :attr:`errors` attribute carries the underlying exceptions in the
    order they were thrown. ``CompositeEmitter`` always attempts every
    child even when earlier children fail, so this exception's presence
    does NOT mean delivery to later children was skipped.
    """

    def __init__(self, message: str, errors: list[BaseException]) -> None:
        super().__init__(message)
        self.errors = errors


class BufferingFlushError(Exception):
    """Raised by :class:`BufferingEmitter` when one or more receipts in a
    flushed batch fail downstream.

    The :attr:`errors` attribute carries the per-receipt exceptions in
    the order they were thrown. ``BufferingEmitter`` always attempts
    every receipt in the batch even when earlier ones fail — receipts
    that fail are not requeued (retries are the inner emitter's
    responsibility).
    """

    def __init__(self, message: str, errors: list[BaseException]) -> None:
        super().__init__(message)
        self.errors = errors


# --- HttpEmitter configuration -----------------------------------------------


@dataclass(frozen=True)
class ApiKeyAuth:
    """API key auth: ``header: value`` sent on every request."""

    header: str
    value: str
    type: str = "api-key"


@dataclass(frozen=True)
class BearerAuth:
    """Bearer auth: ``Authorization: Bearer <token>``."""

    token: str
    type: str = "bearer"


@dataclass(frozen=True)
class MtlsAuth:
    """Mutual-TLS auth: client cert + private key in PEM bytes."""

    cert: bytes
    key: bytes
    type: str = "mtls"


@dataclass(frozen=True)
class NoAuth:
    """No authentication (default)."""

    type: str = "none"


HttpEmitterAuth = ApiKeyAuth | BearerAuth | MtlsAuth | NoAuth


@dataclass(frozen=True)
class RetryConfig:
    """Exponential-backoff retry policy used by :class:`HttpEmitter`.

    ``max_attempts`` includes the first attempt.
    """

    max_attempts: int = 5
    base_delay_ms: int = 100
    max_delay_ms: int = 10_000


@dataclass(frozen=True)
class HttpEmitterConfig:
    """Configuration for :class:`HttpEmitter`.

    The ``auth`` field controls authentication; for standard
    ``Authorization: Bearer …`` tokens use :class:`BearerAuth`. The
    :class:`ApiKeyAuth` variant is meant for custom non-``Authorization``
    headers (e.g. ``X-Api-Key``) — collectors that expect a bearer scheme
    should be configured via :class:`BearerAuth` so the wire shape stays
    canonical.

    Pass a :class:`threading.Event` as ``cancel_event`` to short-circuit
    retry sleeps. When the event is set, the emitter aborts the retry
    loop with :class:`EmitError` instead of waiting out the backoff.
    """

    endpoint: str
    auth: HttpEmitterAuth = field(default_factory=NoAuth)
    strategy: str = "sync"  # "sync" | "fire-and-forget"
    retry: RetryConfig = field(default_factory=RetryConfig)
    timeout_ms: int = 5_000
    cancel_event: threading.Event | None = None
