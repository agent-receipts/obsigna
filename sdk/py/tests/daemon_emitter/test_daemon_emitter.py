"""Tests for the fire-and-forget emitter (ADR-0010).

End-to-end tests start the obsigna-daemon as a subprocess.  The
daemon binary is resolved via the AGENT_RECEIPTS_DAEMON env var, falling
back to /tmp/obsigna-daemon.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from obsigna.daemon_emitter import (
    DaemonEmitter,
    EmitTransportError,
    default_socket_path,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

# ---------------------------------------------------------------------------
# Helpers shared by daemon-backed tests
# ---------------------------------------------------------------------------

_DAEMON_BIN = os.environ.get(
    "AGENT_RECEIPTS_DAEMON",
    "/tmp/obsigna-daemon",
)

_DAEMON_AVAILABLE = Path(_DAEMON_BIN).is_file() and os.access(_DAEMON_BIN, os.X_OK)


def _short_tmp() -> str:
    """Return a temp dir short enough for AF_UNIX sun_path (104-byte limit on macOS)."""
    base = "/tmp" if Path("/tmp").exists() else tempfile.gettempdir()
    d = tempfile.mkdtemp(prefix="ar", dir=base)
    return d


def _write_test_key(path: str) -> None:
    """Write a fresh Ed25519 private key in PKCS8 PEM format."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    Path(path).write_bytes(pem)
    Path(path).chmod(0o600)


class DaemonHandle:
    """Manages a daemon subprocess for testing."""

    def __init__(self, tmpdir: str) -> None:
        self.socket_path = os.path.join(tmpdir, "events.sock")
        self.db_path = os.path.join(tmpdir, "receipts.db")
        self.key_path = os.path.join(tmpdir, "signing.key")
        self.chain_id = "py-emitter-test-chain"
        self._proc: subprocess.Popen[bytes] | None = None

        if not Path(self.key_path).exists():
            _write_test_key(self.key_path)

    def start(self) -> None:
        # Remove any stale socket file left by a previous run so the
        # file-existence readiness check below cannot false-positive.
        try:
            Path(self.socket_path).unlink()
        except FileNotFoundError:
            pass  # No stale socket to remove — that's fine.
        # Strip AGENTRECEIPTS_* from the child env — not all daemon settings
        # have CLI flag overrides (e.g. AGENTRECEIPTS_PUBLIC_KEY), so the only
        # safe approach is to remove them at the subprocess boundary.
        env = {
            k: v for k, v in os.environ.items() if not k.startswith("AGENTRECEIPTS_")
        }
        self._proc = subprocess.Popen(
            [
                _DAEMON_BIN,
                "--socket",
                self.socket_path,
                "--db",
                self.db_path,
                "--key",
                self.key_path,
                "--chain-id",
                self.chain_id,
                "--issuer-id",
                "did:agent-receipts-daemon:py-test",
                "--verification-method",
                "did:agent-receipts-daemon:py-test#k1",
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        # Wait for the socket to appear (up to 2s).
        deadline = time.monotonic() + 2.0
        while True:
            if Path(self.socket_path).exists():
                break
            if time.monotonic() > deadline:
                proc = self._proc
                self.stop()
                stderr_out = b""
                if proc is not None and proc.stderr is not None:
                    stderr_out = proc.stderr.read()
                msg = f"daemon socket {self.socket_path!r} did not appear within 2s"
                if stderr_out:
                    msg += f"\ndaemon stderr:\n{stderr_out.decode(errors='replace')}"
                raise RuntimeError(msg)
            time.sleep(0.01)

    def stop(self) -> None:
        if self._proc is None:
            return
        self._proc.terminate()
        try:
            self._proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait()
        self._proc = None

    def wait_for_receipts(
        self, want: int, timeout: float = 5.0
    ) -> list[dict[str, Any]]:
        """Poll the SQLite DB until at least ``want`` receipts appear."""
        deadline = time.monotonic() + timeout
        while True:
            rows = self._query_receipts()
            if len(rows) >= want:
                return rows
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"timed out waiting for {want} receipts; got {len(rows)}"
                )
            time.sleep(0.02)

    def _query_receipts(self) -> list[dict[str, Any]]:
        if not Path(self.db_path).exists():
            return []
        try:
            conn = sqlite3.connect(self.db_path)
        except sqlite3.OperationalError:
            return []
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT receipt_json FROM receipts"
                " WHERE chain_id = ? ORDER BY sequence",
                (self.chain_id,),
            )
            return [json.loads(r["receipt_json"]) for r in cur.fetchall()]
        except sqlite3.OperationalError:
            return []
        finally:
            conn.close()


@pytest.fixture()
def daemon() -> Iterator[DaemonHandle]:
    """Start a fresh daemon for one test; stop it on teardown."""
    tmpdir = _short_tmp()
    d = DaemonHandle(tmpdir)
    d.start()
    try:
        yield d
    finally:
        d.stop()
        shutil.rmtree(tmpdir, ignore_errors=True)


_DAEMON_SKIP_REASON = (
    f"daemon binary not found at {_DAEMON_BIN}; "
    "build with: cd daemon && go build"
    " -o /tmp/obsigna-daemon ./cmd/obsigna-daemon"
    " (or set AGENT_RECEIPTS_DAEMON to a custom path)"
)
requires_daemon = pytest.mark.skipif(not _DAEMON_AVAILABLE, reason=_DAEMON_SKIP_REASON)


def _session_id_from_receipt(r: dict[str, Any]) -> str:
    """Read session_id from a receipt dict, tolerating camelCase or snake_case key."""
    return r["issuer"].get("sessionId") or r["issuer"].get("session_id", "")


# ---------------------------------------------------------------------------
# Unit tests — no daemon required
# ---------------------------------------------------------------------------


class TestDefaultSocketPath:
    def test_env_var_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENTRECEIPTS_SOCKET", "/custom/path.sock")
        assert default_socket_path() == "/custom/path.sock"

    def test_env_var_cleared(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AGENTRECEIPTS_SOCKET", raising=False)
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        path = default_socket_path()
        # On macOS or Linux we get a non-empty path; on other platforms empty.
        # Directory name differs by platform: macOS uses the hyphenated
        # ``agent-receipts/`` directory (shared with receipts.db / signing
        # key after issue #545), Linux keeps the legacy ``agentreceipts/``
        # under XDG_RUNTIME_DIR or /run.
        import platform

        system = platform.system()
        if system in ("Darwin", "Linux"):
            assert path.endswith("events.sock")
        # Other platforms: may be empty — just don't crash.

    def test_macos_uses_home_based_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Issue #545: on macOS the default must resolve against HOME, not
        TMPDIR, so a process spawned without TMPDIR (Claude Desktop's
        MCP children, for example) still finds the same socket the
        daemon is listening on. We stub ``platform.system`` so the
        assertion is meaningful on Linux CI too — without this guard the
        regression that originally caused #545 would only surface on a
        macOS developer machine.
        """
        monkeypatch.delenv("AGENTRECEIPTS_SOCKET", raising=False)
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        monkeypatch.delenv("TMPDIR", raising=False)
        monkeypatch.setenv("HOME", "/Users/testuser")

        import platform as platform_module

        monkeypatch.setattr(platform_module, "system", lambda: "Darwin")
        assert (
            default_socket_path()
            == "/Users/testuser/.local/share/agent-receipts/events.sock"
        )

    def test_macos_ignores_tmpdir(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Regression guard for #545: a fake TMPDIR must not leak into the
        resolved path on macOS. If this assertion ever flips, the
        env-divergence bug has been reintroduced.
        """
        monkeypatch.delenv("AGENTRECEIPTS_SOCKET", raising=False)
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        monkeypatch.setenv("HOME", "/Users/testuser")
        monkeypatch.setenv("TMPDIR", "/fake-tmpdir")

        import platform as platform_module

        monkeypatch.setattr(platform_module, "system", lambda: "Darwin")
        assert "/fake-tmpdir" not in default_socket_path()


class TestDaemonEmitterConstruction:
    def test_generates_session_id(self) -> None:
        e = DaemonEmitter(socket_path="/tmp/nonexistent.sock")
        assert e.session_id
        assert len(e.session_id) == 36  # UUID v4 canonical form

    def test_accepts_host_session_id(self) -> None:
        sid = "host-session-abc123"
        e = DaemonEmitter(socket_path="/tmp/nonexistent.sock", session_id=sid)
        assert e.session_id == sid

    def test_session_id_unique_per_instance(self) -> None:
        e1 = DaemonEmitter(socket_path="/tmp/nonexistent.sock")
        e2 = DaemonEmitter(socket_path="/tmp/nonexistent.sock")
        assert e1.session_id != e2.session_id  # each gets a fresh UUID

    def test_raises_on_unsupported_platform_without_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AGENTRECEIPTS_SOCKET", raising=False)
        monkeypatch.setattr("platform.system", lambda: "Windows")
        with pytest.raises(ValueError, match="no default socket path"):
            DaemonEmitter()

    def test_context_manager(self) -> None:
        with DaemonEmitter(socket_path="/tmp/nonexistent.sock") as e:
            assert e.session_id

    def test_close_idempotent(self) -> None:
        e = DaemonEmitter(socket_path="/tmp/nonexistent.sock")
        e.close()
        e.close()  # should not raise


class TestDaemonEmitterValidation:
    """Validation errors are raised before any dial attempt."""

    def setup_method(self) -> None:
        self.e = DaemonEmitter(socket_path="/tmp/nonexistent-validation.sock")

    def teardown_method(self) -> None:
        self.e.close()

    def test_missing_channel(self) -> None:
        with pytest.raises(ValueError, match="missing channel"):
            self.e.emit(channel="", tool_name="noop", decision="allowed")

    def test_missing_tool_name(self) -> None:
        with pytest.raises(ValueError, match="missing tool_name"):
            self.e.emit(channel="sdk", tool_name="", decision="allowed")

    def test_empty_decision(self) -> None:
        with pytest.raises(ValueError, match="invalid decision"):
            self.e.emit(channel="sdk", tool_name="noop", decision="")

    def test_unknown_decision(self) -> None:
        with pytest.raises(ValueError, match="invalid decision"):
            self.e.emit(channel="sdk", tool_name="noop", decision="maybe")

    def test_non_str_channel(self) -> None:
        with pytest.raises(ValueError, match="channel must be a str"):
            self.e.emit(channel=42, tool_name="noop", decision="allowed")  # type: ignore[arg-type]

    def test_non_str_tool_name(self) -> None:
        with pytest.raises(ValueError, match="tool_name must be a str"):
            self.e.emit(channel="sdk", tool_name=42, decision="allowed")  # type: ignore[arg-type]

    def test_non_str_tool_server(self) -> None:
        with pytest.raises(ValueError, match="tool_server must be a str"):
            self.e.emit(  # type: ignore[arg-type]
                channel="sdk", tool_name="noop", decision="allowed", tool_server=42
            )

    def test_non_str_error(self) -> None:
        with pytest.raises(ValueError, match="error must be a str"):
            self.e.emit(channel="sdk", tool_name="noop", decision="allowed", error=42)  # type: ignore[arg-type]

    def test_invalid_input_json(self) -> None:
        with pytest.raises(ValueError, match="input is not valid JSON"):
            self.e.emit(
                channel="sdk",
                tool_name="noop",
                decision="allowed",
                input=b"{bad}",
            )

    def test_invalid_output_json(self) -> None:
        with pytest.raises(ValueError, match="output is not valid JSON"):
            self.e.emit(
                channel="sdk",
                tool_name="noop",
                decision="allowed",
                output="[unclosed",
            )

    def test_error_after_close(self) -> None:
        self.e.close()
        with pytest.raises(RuntimeError, match="closed"):
            self.e.emit(channel="sdk", tool_name="noop", decision="allowed")

    def test_oversized_frame(self) -> None:
        big = json.dumps({"x": "a" * (1 << 20)})
        with pytest.raises(ValueError, match="frame too large"):
            self.e.emit(
                channel="sdk",
                tool_name="noop",
                decision="allowed",
                input=big,
            )

    def test_non_utf8_input_bytes_raises(self) -> None:
        with pytest.raises(ValueError, match="not UTF-8 encoded"):
            self.e.emit(
                channel="sdk",
                tool_name="noop",
                decision="allowed",
                input=b"\xff",
            )

    def test_non_utf8_output_bytes_raises(self) -> None:
        with pytest.raises(ValueError, match="not UTF-8 encoded"):
            self.e.emit(
                channel="sdk",
                tool_name="noop",
                decision="allowed",
                output=b"\x80\x81",
            )

    def test_non_finite_input_raises(self) -> None:
        # json.loads parses 1e400 as float('inf'); _check_finite rejects it
        with pytest.raises(ValueError, match="non-finite number"):
            self.e.emit(
                channel="sdk",
                tool_name="noop",
                decision="allowed",
                input='{"x": 1e400}',
            )

    def test_non_finite_output_raises(self) -> None:
        with pytest.raises(ValueError, match="non-finite number"):
            self.e.emit(
                channel="sdk",
                tool_name="noop",
                decision="allowed",
                output='{"score": 1e400}',
            )


class TestSurfacesTransportFailureByDefault:
    """ADR-0025: emit raises EmitTransportError when the daemon is absent,
    without blocking the caller longer than the dial/write budget."""

    def test_raises_quickly_on_dial_failure(self) -> None:
        e = DaemonEmitter(socket_path="/tmp/no-such-daemon-py-test.sock")
        start = time.monotonic()
        with pytest.raises(EmitTransportError):
            e.emit(channel="sdk", tool_name="noop", decision="allowed")
        elapsed = time.monotonic() - start
        assert elapsed < 0.050, f"emit blocked for {elapsed:.3f}s, want <50ms"
        e.close()

    def test_transport_error_distinct_from_caller_bug(self) -> None:
        e = DaemonEmitter(socket_path="/tmp/no-such-daemon-py-test.sock")
        # A caller bug raises ValueError before any dial; the exception raised
        # must NOT be an EmitTransportError, so callers can tell the two apart.
        with pytest.raises(ValueError, match="invalid decision") as caller_bug:
            e.emit(channel="sdk", tool_name="noop", decision="maybe")
        assert not isinstance(caller_bug.value, EmitTransportError)

        # A transport failure raises EmitTransportError, which is not a
        # ValueError — the two error classes are disjoint.
        with pytest.raises(EmitTransportError) as transport:
            e.emit(channel="sdk", tool_name="noop", decision="allowed")
        assert not isinstance(transport.value, ValueError)
        e.close()


class TestBestEffortWhenDaemonDown:
    """best_effort=True opts out of the contract: emit returns None quickly."""

    def test_returns_none_quickly(self) -> None:
        e = DaemonEmitter(
            socket_path="/tmp/no-such-daemon-py-test.sock", best_effort=True
        )
        start = time.monotonic()
        result = e.emit(channel="sdk", tool_name="noop", decision="allowed")
        elapsed = time.monotonic() - start
        assert result is None
        assert elapsed < 0.050, f"emit blocked for {elapsed:.3f}s, want <50ms"
        e.close()

    def test_multiple_emits_all_return_none(self) -> None:
        e = DaemonEmitter(
            socket_path="/tmp/no-such-daemon-py-test.sock", best_effort=True
        )
        for _ in range(5):
            result = e.emit(channel="sdk", tool_name="noop", decision="allowed")
            assert result is None
        e.close()


class TestThreadSafety:
    """Concurrent emit() calls must not corrupt frames or raise spuriously."""

    def test_concurrent_emit_no_data_races(self) -> None:
        """Many threads emit concurrently; all frames arrive intact."""
        tmpdir = _short_tmp()
        sock_path = os.path.join(tmpdir, "concurrent.sock")

        n_threads = 8
        n_per_thread = 10
        total = n_threads * n_per_thread

        frames: list[bytes] = []
        frames_lock = threading.Lock()
        accept_done = threading.Event()
        bind_ready = threading.Event()

        def _server() -> None:
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                srv.bind(sock_path)
                srv.listen(n_threads + 1)
                bind_ready.set()
                deadline = time.monotonic() + 5.0
                received = 0
                while received < total and time.monotonic() < deadline:
                    srv.settimeout(0.5)
                    try:
                        conn, _ = srv.accept()
                    except TimeoutError:
                        continue
                    # Drain every frame this connection sends until EOF.
                    with conn:
                        while True:
                            hdr = b""
                            while len(hdr) < 4:
                                chunk = conn.recv(4 - len(hdr))
                                if not chunk:
                                    break
                                hdr += chunk
                            if len(hdr) < 4:
                                break
                            length = struct.unpack(">I", hdr)[0]
                            body = b""
                            while len(body) < length:
                                chunk = conn.recv(length - len(body))
                                if not chunk:
                                    break
                                body += chunk
                            with frames_lock:
                                frames.append(body)
                            received += 1
            finally:
                srv.close()
                accept_done.set()

        srv_thread = threading.Thread(target=_server, daemon=True)
        srv_thread.start()
        bind_ready.wait(timeout=2.0)

        try:
            e = DaemonEmitter(socket_path=sock_path)

            def _producer(idx: int) -> None:
                for j in range(n_per_thread):
                    e.emit(
                        channel="sdk",
                        tool_name=f"t{idx}-{j}",
                        decision="allowed",
                    )

            workers = [
                threading.Thread(target=_producer, args=(i,), daemon=True)
                for i in range(n_threads)
            ]
            for w in workers:
                w.start()
            for w in workers:
                w.join(timeout=5)
            e.close()
            srv_thread.join(timeout=5)
            assert accept_done.is_set(), "server did not finish in time"

            with frames_lock:
                # All emitted frames must round-trip as valid JSON.
                assert len(frames) == total, (
                    f"expected {total} frames, got {len(frames)}"
                )
                tool_names: set[str] = set()
                for raw in frames:
                    decoded = json.loads(raw)
                    tool_names.add(decoded["tool"]["name"])
                # Every tool name produced by the workers should be present.
                expected = {
                    f"t{i}-{j}" for i in range(n_threads) for j in range(n_per_thread)
                }
                assert tool_names == expected
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestRawJSONPassthrough:
    """The emitter must forward input/output bytes verbatim (no re-serialisation)."""

    def test_frame_contains_raw_input(self) -> None:
        """Round-trip a frame through a mini echo server and verify input verbatim."""
        frames: list[bytes] = []
        ready = threading.Event()
        tmpdir = _short_tmp()
        sock_path = os.path.join(tmpdir, "raw.sock")

        def _server() -> None:
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(sock_path)
            srv.listen(1)
            ready.set()
            conn, _ = srv.accept()
            hdr = b""
            while len(hdr) < 4:
                chunk = conn.recv(4 - len(hdr))
                if not chunk:
                    break
                hdr += chunk
            if len(hdr) == 4:
                length = struct.unpack(">I", hdr)[0]
                body = b""
                while len(body) < length:
                    chunk = conn.recv(length - len(body))
                    if not chunk:
                        break
                    body += chunk
                frames.append(body)
            conn.close()
            srv.close()

        t = threading.Thread(target=_server, daemon=True)
        t.start()
        ready.wait(timeout=2)

        try:
            e = DaemonEmitter(socket_path=sock_path)
            # Whitespace and key-order variation — must travel verbatim.
            raw_input = b'{ "b":  2 , "a" : 1 }'
            e.emit(
                channel="sdk",
                tool_name="hash-fixture",
                decision="allowed",
                input=raw_input,
            )
            e.close()
            t.join(timeout=2)

            assert frames, "no frame received by echo server"
            frame = json.loads(frames[0])
            # The input field in the frame must be valid JSON with values b=2, a=1.
            assert frame["input"] == {"b": 2, "a": 1}
            # And the raw bytes must be present verbatim (not re-encoded).
            raw_frame = frames[0]
            assert b'{ "b":  2 , "a" : 1 }' in raw_frame
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# End-to-end tests — require the daemon binary
# ---------------------------------------------------------------------------


@requires_daemon
def test_emit_frame_round_trip(daemon: DaemonHandle) -> None:
    """Three events materialise as three signed receipts in the daemon's chain."""
    e = DaemonEmitter(socket_path=daemon.socket_path)

    e.emit(channel="sdk", tool_name="alpha", tool_server="fixture", decision="allowed")
    e.emit(channel="sdk", tool_name="beta", tool_server="fixture", decision="denied")
    e.emit(channel="sdk", tool_name="gamma", decision="pending")
    e.close()

    receipts = daemon.wait_for_receipts(3)
    assert len(receipts) == 3

    want_types = ["sdk.fixture.alpha", "sdk.fixture.beta", "sdk.gamma"]
    want_tool_names = ["alpha", "beta", "gamma"]
    want_status = ["success", "failure", "pending"]
    for i, r in enumerate(receipts):
        subj = r["credentialSubject"]
        assert subj["chain"]["sequence"] == i + 1
        assert subj["action"]["type"] == want_types[i], f"receipt {i}: wrong type"
        assert subj["action"]["tool_name"] == want_tool_names[i]
        assert subj["outcome"]["status"] == want_status[i]


@requires_daemon
def test_emit_session_id_stable(daemon: DaemonHandle) -> None:
    """session_id is generated once and reused across all emits (ADR-0010 OQ4)."""
    e = DaemonEmitter(socket_path=daemon.socket_path)
    want_session = e.session_id
    assert want_session  # non-empty

    for _ in range(3):
        e.emit(channel="sdk", tool_name="noop", decision="allowed")
    e.close()

    receipts = daemon.wait_for_receipts(3)
    for i, r in enumerate(receipts):
        got = _session_id_from_receipt(r)
        assert got == want_session, (
            f"receipt {i}: sessionId={got!r}, want {want_session!r}"
        )


@requires_daemon
def test_emit_with_host_session_id(daemon: DaemonHandle) -> None:
    """WithSessionID forwards a host-supplied id to the daemon."""
    host_session = "host-supplied-session-py-9f3a"
    e = DaemonEmitter(socket_path=daemon.socket_path, session_id=host_session)
    assert e.session_id == host_session

    e.emit(channel="sdk", tool_name="noop", decision="allowed")
    e.close()

    receipts = daemon.wait_for_receipts(1)
    got = _session_id_from_receipt(receipts[0])
    assert got == host_session


@requires_daemon
def test_emit_reconnect_after_daemon_restart() -> None:
    """The emitter re-dials after the daemon restarts, session_id stays stable."""
    tmpdir = _short_tmp()
    try:
        d1 = DaemonHandle(tmpdir)
        d1.start()

        e = DaemonEmitter(socket_path=d1.socket_path)
        want_session = e.session_id

        # Round 1: two emits to the first daemon.
        for _ in range(2):
            e.emit(channel="sdk", tool_name="before-restart", decision="allowed")
        d1.wait_for_receipts(2)

        # Stop daemon 1.
        d1.stop()

        # Start daemon 2 reusing the same dir (same socket path + DB).
        d2 = DaemonHandle(tmpdir)
        d2.start()

        # Loop until reconnect succeeds.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            e.emit(channel="sdk", tool_name="after-restart", decision="allowed")
            rows = d2._query_receipts()
            if len(rows) >= 3:
                # Verify session_id is still stable on post-restart receipts.
                for r in rows[2:]:
                    got = _session_id_from_receipt(r)
                    assert got == want_session
                    subj = r["credentialSubject"]
                    assert subj["action"]["tool_name"] == "after-restart"
                e.close()
                d2.stop()
                return
            time.sleep(0.05)

        e.close()
        d2.stop()
        pytest.fail("emitter did not reconnect to the restarted daemon within 5s")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@requires_daemon
def test_emit_returns_error_after_close(daemon: DaemonHandle) -> None:
    """emit() raises RuntimeError after close(); close() is idempotent."""
    e = DaemonEmitter(socket_path=daemon.socket_path)
    e.close()
    e.close()  # idempotent

    with pytest.raises(RuntimeError, match="closed"):
        e.emit(channel="sdk", tool_name="noop", decision="allowed")
