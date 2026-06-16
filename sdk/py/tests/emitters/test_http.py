"""Tests for HttpEmitter.

Exercises the collector POST contract, auth headers, retry/backoff, and the
fire-and-forget strategy against an in-process http.server.
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

import pytest

from obsigna.emitters import (
    ApiKeyAuth,
    BearerAuth,
    EmitError,
    HttpEmitter,
    HttpEmitterConfig,
    MtlsAuth,
    RetryConfig,
)
from tests.conftest import make_receipt

if TYPE_CHECKING:
    from collections.abc import Callable


# ---------------------------------------------------------------------------
# In-process collector
# ---------------------------------------------------------------------------


class _CollectorState:
    """Shared state observable by both the server thread and the test."""

    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []
        self.attempt = 0
        self.responder: Callable[[dict[str, object], int], int] = lambda _r, _a: 201
        self.lock = threading.Lock()


class _Handler(BaseHTTPRequestHandler):
    state: _CollectorState  # set by start_collector()

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode() if length else ""
        captured: dict[str, object] = {
            "method": "POST",
            "path": self.path,
            "headers": dict(self.headers.items()),
            "body": body,
        }
        with self.state.lock:
            self.state.requests.append(captured)
            self.state.attempt += 1
            status = self.state.responder(captured, self.state.attempt)
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:  # noqa: D401
        # Silence the default stderr access log so pytest output stays clean.
        return


def _start_collector() -> tuple[_CollectorState, HTTPServer, threading.Thread, str]:
    state = _CollectorState()
    Handler = type("Handler", (_Handler,), {"state": state})
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/receipts"
    return state, server, thread, url


@pytest.fixture
def collector() -> object:
    state, server, thread, url = _start_collector()
    try:
        yield (state, url)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_posts_application_ld_json_on_201(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    emitter = HttpEmitter(HttpEmitterConfig(endpoint=url))
    emitter.emit(make_receipt(id="urn:r:1"))
    assert len(state.requests) == 1
    req = state.requests[0]
    assert req["method"] == "POST"
    assert req["headers"]["Content-Type"] == "application/ld+json"
    assert '"urn:r:1"' in req["body"]


def test_409_conflict_resolves_as_success(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    state.responder = lambda _r, _a: 409
    emitter = HttpEmitter(HttpEmitterConfig(endpoint=url))
    emitter.emit(make_receipt(id="urn:r:1"))
    assert len(state.requests) == 1


def test_400_throws_immediately_without_retry(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    state.responder = lambda _r, _a: 400
    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint=url,
            retry=RetryConfig(max_attempts=5, base_delay_ms=1, max_delay_ms=1),
        )
    )
    with pytest.raises(EmitError) as info:
        emitter.emit(make_receipt(id="urn:r:1"))
    assert info.value.status == 400
    assert len(state.requests) == 1


def test_5xx_then_success(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    state.responder = lambda _r, attempt: 201 if attempt >= 3 else 503
    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint=url,
            retry=RetryConfig(max_attempts=5, base_delay_ms=1, max_delay_ms=1),
        )
    )
    emitter.emit(make_receipt(id="urn:r:1"))
    assert len(state.requests) >= 3


def test_5xx_exhausts_budget(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    state.responder = lambda _r, _a: 502
    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint=url,
            retry=RetryConfig(max_attempts=3, base_delay_ms=1, max_delay_ms=1),
        )
    )
    with pytest.raises(EmitError) as info:
        emitter.emit(make_receipt(id="urn:r:1"))
    assert info.value.status == 502
    assert len(state.requests) == 3


def test_api_key_auth_header(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint=url,
            auth=ApiKeyAuth(header="X-Api-Key", value="secret"),
        )
    )
    emitter.emit(make_receipt(id="urn:r:1"))
    assert state.requests[0]["headers"]["X-Api-Key"] == "secret"


def test_bearer_auth_header(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    emitter = HttpEmitter(
        HttpEmitterConfig(endpoint=url, auth=BearerAuth(token="tok-xyz"))
    )
    emitter.emit(make_receipt(id="urn:r:1"))
    assert state.requests[0]["headers"]["Authorization"] == "Bearer tok-xyz"


def test_no_auth_header_when_none(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    emitter = HttpEmitter(HttpEmitterConfig(endpoint=url))
    emitter.emit(make_receipt(id="urn:r:1"))
    assert "Authorization" not in state.requests[0]["headers"]


def _make_mtls_pair() -> tuple[bytes, bytes]:
    """Return (cert_pem, key_pem) — self-signed for test fixtures only."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ar-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(
            __import__("datetime").datetime.now(tz=__import__("datetime").UTC)
        )
        .not_valid_after(
            __import__("datetime").datetime.now(tz=__import__("datetime").UTC)
            + __import__("datetime").timedelta(days=1)
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def test_mtls_config_loads_certificate_files() -> None:
    """Pin that mTLS config produces a valid SSLContext without throwing."""
    cert_pem, key_pem = _make_mtls_pair()
    with HttpEmitter(
        HttpEmitterConfig(
            endpoint="https://example.invalid/receipts",
            auth=MtlsAuth(cert=cert_pem, key=key_pem),
        )
    ) as emitter:
        # The SSLContext is built lazily at request time; here we just
        # assert construction did not raise.
        assert emitter._ssl_context is not None  # noqa: SLF001 — internal state


def test_mtls_tempfiles_removed_on_close() -> None:
    """close() must remove the cert+key tempfiles immediately."""
    import os

    cert_pem, key_pem = _make_mtls_pair()
    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint="https://example.invalid/receipts",
            auth=MtlsAuth(cert=cert_pem, key=key_pem),
        )
    )
    cert_path = emitter._mtls_cert_file  # noqa: SLF001 — internal state
    key_path = emitter._mtls_key_file  # noqa: SLF001 — internal state
    assert cert_path is not None
    assert key_path is not None
    assert os.path.exists(cert_path)
    assert os.path.exists(key_path)
    emitter.close()
    assert not os.path.exists(cert_path)
    assert not os.path.exists(key_path)


def test_mtls_tempfiles_removed_on_gc_without_close() -> None:
    """weakref.finalize must clean up the PEM tempfiles when the emitter
    is GC'd, even if close() is never called. This is the load-bearing
    test for B2 — private keys must not linger on disk past the
    emitter's lifetime.
    """
    import gc
    import os

    cert_pem, key_pem = _make_mtls_pair()
    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint="https://example.invalid/receipts",
            auth=MtlsAuth(cert=cert_pem, key=key_pem),
        )
    )
    cert_path = emitter._mtls_cert_file  # noqa: SLF001 — internal state
    key_path = emitter._mtls_key_file  # noqa: SLF001 — internal state
    assert cert_path is not None
    assert key_path is not None
    assert os.path.exists(cert_path)
    assert os.path.exists(key_path)
    # Drop the only reference; force a collection cycle. The finalizer
    # registered with weakref.finalize must fire and remove both files.
    del emitter
    gc.collect()
    assert not os.path.exists(cert_path)
    assert not os.path.exists(key_path)


def test_mtls_keyfile_has_0600_permissions() -> None:
    """The on-disk key tempfile must be readable only by the owner."""
    import os
    import stat

    cert_pem, key_pem = _make_mtls_pair()
    with HttpEmitter(
        HttpEmitterConfig(
            endpoint="https://example.invalid/receipts",
            auth=MtlsAuth(cert=cert_pem, key=key_pem),
        )
    ) as emitter:
        key_path = emitter._mtls_key_file  # noqa: SLF001 — internal state
        assert key_path is not None
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        # 0o600: owner read+write only.
        assert mode == 0o600, f"key file mode = {oct(mode)}; want 0o600"


def test_http_url_warns_on_construction(caplog: object) -> None:
    """http:// endpoints log a warning (ADR-0020 requires HTTPS)."""
    import logging

    caplog.set_level(  # type: ignore[attr-defined]
        logging.WARNING, logger="obsigna.emitters.http"
    )
    HttpEmitter(HttpEmitterConfig(endpoint="http://example.com/receipts"))
    msgs = [r.getMessage() for r in caplog.records]  # type: ignore[attr-defined]
    assert any("not HTTPS" in m for m in msgs), f"no HTTPS warning in {msgs}"


def test_https_url_does_not_warn(caplog: object) -> None:
    import logging

    caplog.set_level(  # type: ignore[attr-defined]
        logging.WARNING, logger="obsigna.emitters.http"
    )
    HttpEmitter(HttpEmitterConfig(endpoint="https://example.com/receipts"))
    msgs = [r.getMessage() for r in caplog.records]  # type: ignore[attr-defined]
    assert not any("not HTTPS" in m for m in msgs), f"unexpected warning: {msgs}"


def test_cancel_event_short_circuits_retry_backoff(collector: object) -> None:
    """Setting cancel_event mid-flight aborts the retry loop without
    waiting out the backoff budget."""
    state, url = collector  # type: ignore[misc]
    state.responder = lambda _r, _a: 502
    cancel = threading.Event()
    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint=url,
            retry=RetryConfig(
                max_attempts=10, base_delay_ms=10_000, max_delay_ms=10_000
            ),
            cancel_event=cancel,
        )
    )
    # Cancel 50ms in — long before the 10s backoff would elapse.
    threading.Timer(0.05, cancel.set).start()
    start = time.monotonic()
    with pytest.raises(EmitError):
        emitter.emit(make_receipt(id="urn:r:1"))
    elapsed_ms = (time.monotonic() - start) * 1000
    assert elapsed_ms < 2_000, (
        f"retry not cancelled; took {elapsed_ms:.0f}ms (want <2000ms)"
    )


def test_drain_waits_for_fire_and_forget(collector: object) -> None:
    """drain() blocks until every background fire-and-forget thread finishes."""
    state, url = collector  # type: ignore[misc]
    gate = threading.Event()

    def gated(_r: dict[str, object], _a: int) -> int:
        # Hold the collector until drain() unblocks the gate.
        gate.wait(timeout=2.0)
        return 201

    state.responder = gated
    emitter = HttpEmitter(HttpEmitterConfig(endpoint=url, strategy="fire-and-forget"))
    emitter.emit(make_receipt(id="urn:r:1"))
    # Background thread is in flight but blocked on the collector.
    assert len(state.requests) == 0
    # Release the responder right after drain() starts. drain() must wait.
    threading.Timer(0.05, gate.set).start()
    emitter.drain()
    assert len(state.requests) == 1


def test_fire_and_forget_returns_immediately(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    # Slow responder: hold the lock briefly so a sync call would take >100ms.
    barrier = threading.Event()

    def slow_responder(_r: dict[str, object], _a: int) -> int:
        barrier.wait(timeout=2.0)
        return 201

    state.responder = slow_responder

    emitter = HttpEmitter(
        HttpEmitterConfig(endpoint=url, strategy="fire-and-forget"),
    )
    start = time.monotonic()
    emitter.emit(make_receipt(id="urn:r:1"))
    elapsed_ms = (time.monotonic() - start) * 1000
    # Background thread is started; the call returns essentially instantly.
    assert elapsed_ms < 100, f"fire-and-forget blocked for {elapsed_ms:.0f}ms"
    # Release the slow responder so the test cleanup doesn't hang.
    barrier.set()


def test_fire_and_forget_swallows_errors(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    state.responder = lambda _r, _a: 500
    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint=url,
            strategy="fire-and-forget",
            retry=RetryConfig(max_attempts=1, base_delay_ms=1, max_delay_ms=1),
        )
    )
    # Must not raise even though delivery will fail.
    emitter.emit(make_receipt(id="urn:r:1"))
    # Give the background thread a chance to finish.
    time.sleep(0.1)


def test_empty_endpoint_rejected() -> None:
    with pytest.raises(ValueError, match="endpoint"):
        HttpEmitter(HttpEmitterConfig(endpoint=""))


def test_invalid_strategy_rejected() -> None:
    with pytest.raises(ValueError, match="strategy"):
        HttpEmitter(HttpEmitterConfig(endpoint="http://example", strategy="lol"))


def test_rejects_max_attempts_below_one() -> None:
    with pytest.raises(ValueError, match="max_attempts"):
        HttpEmitter(
            HttpEmitterConfig(
                endpoint="https://example.invalid/receipts",
                retry=RetryConfig(max_attempts=0),
            )
        )


def test_rejects_negative_backoff_delays() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        HttpEmitter(
            HttpEmitterConfig(
                endpoint="https://example.invalid/receipts",
                retry=RetryConfig(max_attempts=3, base_delay_ms=-1, max_delay_ms=10),
            )
        )


def test_rejects_base_delay_greater_than_max() -> None:
    with pytest.raises(ValueError, match="base_delay_ms"):
        HttpEmitter(
            HttpEmitterConfig(
                endpoint="https://example.invalid/receipts",
                retry=RetryConfig(
                    max_attempts=3, base_delay_ms=2000, max_delay_ms=1000
                ),
            )
        )


def test_timeout_treated_as_retryable(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    # Block the responder past the emitter timeout.
    block = threading.Event()
    call_count = {"n": 0}

    def slow_responder(_r: dict[str, object], _a: int) -> int:
        call_count["n"] += 1
        if call_count["n"] == 1:
            # First call: hang past the timeout.
            block.wait(timeout=2.0)
            return 503
        return 201

    state.responder = slow_responder

    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint=url,
            timeout_ms=50,
            retry=RetryConfig(max_attempts=3, base_delay_ms=1, max_delay_ms=1),
        )
    )
    # Release the responder shortly so the second attempt can succeed.
    threading.Timer(0.1, block.set).start()
    emitter.emit(make_receipt(id="urn:r:1"))
