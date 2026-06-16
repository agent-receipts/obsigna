"""HttpEmitter — POSTs signed receipts to a collector endpoint (ADR-0020).

Wire contract (per ADR-0020 §"Collector contract"):

    POST <endpoint>
    Content-Type: application/ld+json
    Body: JSON-serialised AgentReceipt

    201 Created    -> resolve
    409 Conflict   -> resolve (duplicate id is idempotent re-delivery)
    400 Bad Request-> raise EmitError immediately (no retry)
    5xx / network  -> retry with exponential backoff + jitter

Strategy:
    - "sync" (default): emit() waits for the collector ack and respects
      the full retry budget.
    - "fire-and-forget": emit() schedules the POST on a background
      thread and returns immediately; the background thread's error is
      logged at debug and never raised to the caller. Background
      deliveries are tracked so :meth:`HttpEmitter.drain` can wait for
      them on graceful shutdown.

!!! FIRE-AND-FORGET CRASH-LOSS RISK !!!
``"fire-and-forget"`` does not guarantee the receipt reached the wire
before the process exits. Call :meth:`drain` before shutdown when you
need a best-effort flush of in-flight background deliveries.

mTLS support uses :func:`ssl.SSLContext.load_cert_chain` which requires
file paths. The PEM-encoded bytes are written to per-instance tempfiles
(mode 0600, created atomically) at construction. A
:func:`weakref.finalize` callback removes them on GC even if the caller
forgets to call :meth:`close` — so the PEM-encoded private key never
lingers on disk past the emitter's lifetime.
"""

from __future__ import annotations

import logging
import os
import random
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.request
import weakref
from typing import TYPE_CHECKING, Any

from obsigna.emitters.types import (
    ApiKeyAuth,
    BearerAuth,
    EmitError,
    HttpEmitterConfig,
    MtlsAuth,
    NoAuth,
    RetryConfig,
)

if TYPE_CHECKING:
    from obsigna.receipt.types import AgentReceipt

logger = logging.getLogger(__name__)


class HttpEmitter:
    """POSTs signed receipts to a collector endpoint over HTTP(S)."""

    def __init__(self, config: HttpEmitterConfig) -> None:
        if not config.endpoint:
            raise ValueError("HttpEmitter: endpoint is required")
        # Validate retry budget up front — max_attempts < 1 would make
        # _deliver() loop zero times and raise "attempts exhausted" without
        # ever issuing the request.
        if config.retry.max_attempts < 1:
            raise ValueError(
                "HttpEmitter: retry.max_attempts must be >= 1 "
                f"(got {config.retry.max_attempts})"
            )
        if config.retry.base_delay_ms < 0 or config.retry.max_delay_ms < 0:
            raise ValueError(
                "HttpEmitter: retry delays must be non-negative "
                f"(base_delay_ms={config.retry.base_delay_ms}, "
                f"max_delay_ms={config.retry.max_delay_ms})"
            )
        if config.retry.base_delay_ms > config.retry.max_delay_ms:
            raise ValueError(
                "HttpEmitter: retry.base_delay_ms "
                f"({config.retry.base_delay_ms}) must be <= "
                f"retry.max_delay_ms ({config.retry.max_delay_ms})"
            )
        self._endpoint = config.endpoint
        self._auth = config.auth
        self._strategy = config.strategy
        if self._strategy not in ("sync", "fire-and-forget"):
            raise ValueError(
                f"HttpEmitter: invalid strategy {config.strategy!r} "
                "(want 'sync' or 'fire-and-forget')"
            )
        self._retry = config.retry
        self._timeout = config.timeout_ms / 1000.0
        self._cancel_event = config.cancel_event

        if not self._endpoint.startswith("https://"):
            # ADR-0020 requires HTTPS in production. We accept http:// for
            # tests and local-loopback usage but warn so misconfigurations
            # don't reach prod silently.
            logger.warning(
                "HttpEmitter: endpoint %s is not HTTPS; "
                "receipts will travel unencrypted",
                self._endpoint,
            )

        # Track fire-and-forget background threads so callers can drain
        # them on shutdown. Guarded by a dedicated lock so emit() and
        # drain() can race safely.
        self._pending_lock = threading.Lock()
        self._pending: set[threading.Thread] = set()

        # mTLS bytes -> on-disk PEM files -> SSLContext. We keep the
        # tempfiles alive for the emitter's lifetime so the SSL handshake
        # can load them on every request. Cleanup is via weakref.finalize
        # so the private key on disk goes away on GC even if the caller
        # forgets to call close().
        self._mtls_cert_file: str | None = None
        self._mtls_key_file: str | None = None
        self._ssl_context: ssl.SSLContext | None = None
        # weakref.finalize is generic over the finalised object's type, but
        # we never read its return type — typing it as Any is more honest.
        self._finalizer: weakref.finalize[..., Any] | None = None
        if isinstance(self._auth, MtlsAuth):
            cert_path, key_path = _write_mtls_files(self._auth.cert, self._auth.key)
            self._mtls_cert_file = cert_path
            self._mtls_key_file = key_path
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            self._ssl_context = ctx
            # Capture only the paths (not `self`) so the finalizer doesn't
            # keep the emitter alive.
            self._finalizer = weakref.finalize(
                self, _cleanup_paths, [cert_path, key_path]
            )

    def emit(self, receipt: AgentReceipt) -> None:
        body = receipt.model_dump_json(by_alias=True).encode()

        if self._strategy == "fire-and-forget":
            # Schedule on a daemon thread so the worker doesn't keep the
            # interpreter alive past the caller's exit. Errors are
            # swallowed because the caller explicitly opted in to no
            # guarantee.
            thread = threading.Thread(
                target=self._fire_and_forget,
                args=(body,),
                daemon=True,
            )
            with self._pending_lock:
                self._pending.add(thread)
            thread.start()
            return

        self._deliver(body)

    def drain(self, timeout: float | None = None) -> None:
        """Wait for fire-and-forget background deliveries to finish.

        Call this on graceful shutdown to give in-flight receipts a
        chance to land. With no ``timeout`` argument blocks until every
        pending thread has joined; with a timeout the total wait time is
        capped at ``timeout`` seconds across ALL threads (overall
        deadline, not per-thread). Safe to call when there are no pending
        threads.
        """
        with self._pending_lock:
            snapshot = list(self._pending)
        if timeout is None:
            for thread in snapshot:
                thread.join()
            return
        deadline = time.monotonic() + timeout
        for thread in snapshot:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            thread.join(timeout=remaining)

    def close(self) -> None:
        """Release the mTLS temp files, if any. Safe to call multiple times."""
        if self._finalizer is not None and self._finalizer.alive:
            # Explicit cleanup — also detach so GC doesn't double-unlink.
            self._finalizer()
            self._finalizer.detach()
        self._mtls_cert_file = None
        self._mtls_key_file = None

    # Allow `with HttpEmitter(...) as e:` for clean cleanup in tests.
    def __enter__(self) -> HttpEmitter:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------

    def _fire_and_forget(self, body: bytes) -> None:
        current = threading.current_thread()
        try:
            self._deliver(body)
        except Exception as exc:  # noqa: BLE001 — fire-and-forget swallows everything
            logger.debug(
                "HttpEmitter dropped receipt (fire-and-forget)",
                extra={"endpoint": self._endpoint, "err": str(exc)},
            )
        finally:
            with self._pending_lock:
                self._pending.discard(current)

    def _deliver(self, body: bytes) -> None:
        last_error: BaseException | None = None
        last_status: int | None = None

        for attempt in range(1, self._retry.max_attempts + 1):
            if self._cancel_event is not None and self._cancel_event.is_set():
                raise EmitError(
                    f"HttpEmitter: cancelled before attempt {attempt} to "
                    f"{self._endpoint}",
                    status=last_status,
                ) from last_error
            try:
                status = self._do_request(body)
            except urllib.error.HTTPError as exc:
                # urllib raises HTTPError for any non-2xx; treat it as a
                # transport-level result so we can apply the status-mapping
                # logic uniformly. HTTPError is file-like and holds the
                # underlying socket open — close it once we have the status
                # so the connection is not leaked across retries.
                status = exc.code
                exc.close()
            except (urllib.error.URLError, TimeoutError) as exc:
                last_error = exc
                last_status = None
                if attempt >= self._retry.max_attempts:
                    break
                if self._wait_backoff(attempt):
                    raise EmitError(
                        f"HttpEmitter: cancelled while waiting to retry "
                        f"{self._endpoint}",
                        status=None,
                    ) from exc
                continue

            if status in (201, 409):
                return
            if status == 400:
                raise EmitError(
                    f"HttpEmitter: 400 Bad Request from {self._endpoint}",
                    status=400,
                )
            if 500 <= status < 600:
                last_error = EmitError(
                    f"HttpEmitter: HTTP {status} from {self._endpoint}",
                    status=status,
                )
                last_status = status
                if attempt >= self._retry.max_attempts:
                    break
                if self._wait_backoff(attempt):
                    raise EmitError(
                        f"HttpEmitter: cancelled while waiting to retry "
                        f"{self._endpoint}",
                        status=status,
                    ) from last_error
                continue
            # Any other status (401/403/404/4xx) is non-retryable.
            raise EmitError(
                f"HttpEmitter: unexpected HTTP {status} from {self._endpoint}",
                status=status,
            )

        raise EmitError(
            f"HttpEmitter: {self._retry.max_attempts} attempts exhausted for "
            f"{self._endpoint}",
            status=last_status,
        ) from last_error

    def _wait_backoff(self, attempt: int) -> bool:
        """Sleep before the next retry. Returns True if cancellation fired."""
        delay = _backoff_delay(self._retry, attempt) / 1000.0
        if self._cancel_event is not None:
            # Event.wait returns True iff the event was set during the
            # wait — that's our "cancellation fired" signal.
            return self._cancel_event.wait(timeout=delay)
        time.sleep(delay)
        return False

    def _do_request(self, body: bytes) -> int:
        headers: dict[str, str] = {"Content-Type": "application/ld+json"}
        if isinstance(self._auth, ApiKeyAuth):
            headers[self._auth.header] = self._auth.value
        elif isinstance(self._auth, BearerAuth):
            headers["Authorization"] = f"Bearer {self._auth.token}"
        # NoAuth and MtlsAuth contribute no headers; mTLS goes via SSLContext.

        req = urllib.request.Request(  # noqa: S310 — endpoint is caller-controlled, by design
            self._endpoint,
            data=body,
            headers=headers,
            method="POST",
        )

        open_kwargs: dict[str, Any] = {"timeout": self._timeout}
        if self._ssl_context is not None:
            open_kwargs["context"] = self._ssl_context

        with urllib.request.urlopen(req, **open_kwargs) as resp:  # noqa: S310 — same justification
            return int(resp.status)


def _backoff_delay(retry: RetryConfig, attempt: int) -> int:
    """Exponential backoff with full jitter, capped at max_delay_ms."""
    exp = min(retry.max_delay_ms, retry.base_delay_ms * (2 ** (attempt - 1)))
    return random.randint(0, exp)  # noqa: S311 — jitter, not crypto


def _write_mtls_files(cert: bytes, key: bytes) -> tuple[str, str]:
    """Write PEM cert+key to per-instance tempfiles. Returns (cert_path, key_path).

    Python's SSLContext.load_cert_chain requires file paths up through
    3.12; in-memory loading was added in 3.13. We target 3.11+ so the
    tempfile path is required.
    """
    # os.write can perform a partial write, which would truncate the PEM and
    # cause intermittent load_cert_chain failures. Wrap each fd in a file
    # object whose write() loops until every byte is flushed; the with-block
    # also owns and closes the fd. Writing the cert before creating the key
    # tempfile means a failed cert write leaves no orphaned key fd.
    cert_fd, cert_path = tempfile.mkstemp(prefix="ar-mtls-cert-", suffix=".pem")
    with os.fdopen(cert_fd, "wb") as cert_file:
        cert_file.write(cert)
    key_fd, key_path = tempfile.mkstemp(prefix="ar-mtls-key-", suffix=".pem")
    with os.fdopen(key_fd, "wb") as key_file:
        key_file.write(key)
    # Tighten permissions on the private key — mkstemp already opens at
    # 0600 on POSIX, but be explicit so reviewers don't have to check.
    os.chmod(key_path, 0o600)
    return cert_path, key_path


def _cleanup_paths(paths: list[str]) -> None:
    """Remove each path on the filesystem, ignoring missing files.

    Used both by :meth:`HttpEmitter.close` and by the weakref finalizer
    so the PEM tempfiles are removed deterministically on GC even if the
    caller forgets to call ``close()``. ``FileNotFoundError`` is expected
    when cleanup runs twice (close() then GC, or vice versa); other
    ``OSError`` instances are logged at debug since cleanup is non-fatal
    but should not be invisible.
    """
    for path in paths:
        try:
            os.unlink(path)
        except FileNotFoundError:
            # Already cleaned up — close() and GC both run _cleanup_paths.
            continue
        except OSError as exc:
            logger.debug(
                "HttpEmitter mTLS tempfile cleanup failed",
                extra={"path": path, "err": str(exc)},
            )


# Convenience re-exports so callers can do `from obsigna.emitters
# import NoAuth` without pulling from a deeply nested module.
__all__ = [
    "ApiKeyAuth",
    "BearerAuth",
    "EmitError",
    "HttpEmitter",
    "HttpEmitterConfig",
    "MtlsAuth",
    "NoAuth",
    "RetryConfig",
]
