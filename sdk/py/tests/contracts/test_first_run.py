"""First-run contracts and happy-path tests for the agent-receipts Python SDK.

These tests pin behaviours that a brand-new adopter encounters on day one of
using the SDK. They run against the in-tree package and need no daemon or
network — except `test_daemon_emitter_roundtrip_against_live_daemon`, which is
SKIPPED unless AGENTRECEIPTS_SOCKET points at a running agent-receipts daemon.

Targets sdk/py >= 0.10.0. The socket emitter is `DaemonEmitter` (renamed from
`Emitter` in ADR-0020); the top-level `Emitter` name is now an un-instantiable
Protocol.

- `test_daemon_emitter_no_daemon_surfaces_transport_error` — pins the emit
  failure contract (#599 / ADR-0025): emit raises `EmitTransportError` when the
  daemon is unreachable, with `best_effort=True` opting back into silent drop.
- `test_wal_emitter_cannot_wrap_daemon_emitter` — pins the runtime_checkable
  Protocol/DaemonEmitter arity mismatch, tracked as PY-P4 in
  docs/operations/current.md. ADR-0025 §3 decoupled PY-P4 from #599 (the emit
  failure contract makes surfacing the base obligation and durability opt-in),
  so it stays with ADR-0020 step-2 work. When that lands, replace this with a
  positive assertion that `WalEmitter` wraps `DaemonEmitter` correctly.
"""

from __future__ import annotations

import os
import socket

import pytest

from obsigna import (
    ActionInput,
    Chain,
    CreateReceiptInput,
    Issuer,
    Outcome,
    Principal,
    create_receipt,
    generate_key_pair,
    hash_receipt,
    sign_receipt,
    verify_chain,
    verify_receipt,
)

KEY_ID = "did:agent:my-agent#key-1"


def _sign_at(keys, sequence, previous_hash):
    """Create and sign one receipt at a given chain position."""
    unsigned = create_receipt(
        CreateReceiptInput(
            issuer=Issuer(id="did:agent:my-agent"),
            principal=Principal(id="did:user:alice"),
            action=ActionInput(type="filesystem.file.read", risk_level="low"),
            outcome=Outcome(status="success"),
            chain=Chain(
                sequence=sequence,
                previous_receipt_hash=previous_hash,
                chain_id="chain_session-1",
            ),
        )
    )
    return sign_receipt(unsigned, keys.private_key, KEY_ID)


def test_in_process_happy_path():
    """README Quick Start: generate key, create, sign, hash, verify."""
    keys = generate_key_pair()

    receipt = _sign_at(keys, sequence=1, previous_hash=None)

    receipt_hash = hash_receipt(receipt)
    assert receipt_hash.startswith("sha256:")
    assert len(receipt_hash) == len("sha256:") + 64

    assert verify_receipt(receipt, keys.public_key) is True

    other = generate_key_pair()
    assert verify_receipt(receipt, other.public_key) is False


def test_two_receipt_chain():
    """A 2-link chain verifies, and tampering with the link is detected."""
    keys = generate_key_pair()

    r1 = _sign_at(keys, sequence=1, previous_hash=None)
    r2 = _sign_at(keys, sequence=2, previous_hash=hash_receipt(r1))

    result = verify_chain([r1, r2], keys.public_key)
    assert result.valid is True
    assert result.length == 2

    broken = verify_chain([r2, r1], keys.public_key)
    assert broken.valid is False


def _daemon_is_live(path: str) -> bool:
    if not path:
        return False
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(0.1)
    try:
        s.connect(path)
        return True
    except OSError:
        return False
    finally:
        s.close()


@pytest.mark.skipif(
    not _daemon_is_live(os.environ.get("AGENTRECEIPTS_SOCKET", "")),
    reason="no live daemon at AGENTRECEIPTS_SOCKET",
)
def test_daemon_emitter_roundtrip_against_live_daemon():
    """Emit one event to a running daemon (fire-and-forget).

    The contract: a successful emit returns None and raises nothing.
    Confirming the receipt landed needs `agent-receipts verify`/`show` against
    the daemon DB (out of band).
    """
    from obsigna import DaemonEmitter

    socket_path = os.environ["AGENTRECEIPTS_SOCKET"]
    with DaemonEmitter(socket_path=socket_path, session_id="contracts-e2e") as e:
        assert e.session_id == "contracts-e2e"
        ret = e.emit(
            channel="py-sdk",
            tool_name="filesystem.file.read",
            decision="allowed",
            input='{"path":"/etc/hosts"}',
            output='{"bytes":42}',
        )
        assert ret is None


def test_daemon_emitter_no_daemon_surfaces_transport_error(tmp_path):
    """First-run-without-daemon: emit raises EmitTransportError (ADR-0025).

    The emit failure contract (#599) requires transport failure to surface
    rather than drop silently. best_effort=True opts back into the old
    loss-tolerant behaviour for callers that knowingly accept dropped events.
    """
    from obsigna import DaemonEmitter, EmitTransportError

    dead_socket = str(tmp_path / "nope.sock")
    with DaemonEmitter(socket_path=dead_socket, session_id="contracts-drop") as e:
        with pytest.raises(EmitTransportError):
            e.emit(channel="py-sdk", tool_name="x.y", decision="allowed")

    with DaemonEmitter(
        socket_path=dead_socket, session_id="contracts-drop", best_effort=True
    ) as best_effort:
        assert (
            best_effort.emit(channel="py-sdk", tool_name="x.y", decision="allowed")
            is None
        )


def test_top_level_emitter_is_now_a_protocol():
    """v0.10.0 breaking rename: `obsigna.Emitter` cannot be instantiated.

    0.9.0 code `Emitter(socket_path=...)` now raises TypeError because Emitter
    is a Protocol. Asserts the behavioural contract — that instantiation
    raises — without pinning private `typing` internals or exact error
    messages, both of which can drift across Python versions.
    """
    from obsigna import Emitter

    with pytest.raises(TypeError):
        Emitter(socket_path="/tmp/whatever.sock")  # type: ignore[call-arg]


def _signed_receipt():
    keys = generate_key_pair()
    return _sign_at(keys, sequence=1, previous_hash=None)


def test_wal_emitter_retains_on_failure_and_replays(tmp_path):
    """v0.10.0 WAL: durable at-least-once for the HTTP/Protocol path.

    A failed delivery is retained in the WAL and replayed once the collector
    recovers — no silent loss on the remote path.
    """
    from obsigna.emitters import FileWal, InMemoryEmitter, WalEmitter

    class _FailingEmitter:
        def emit(self, receipt):  # noqa: ANN001
            raise RuntimeError("collector down")

    wal_dir = str(tmp_path / "wal")
    receipt = _signed_receipt()

    down = WalEmitter(inner=_FailingEmitter(), wal=FileWal(wal_dir))
    with pytest.raises(RuntimeError):
        down.emit(receipt)
    assert down.pending() == 1

    sink = InMemoryEmitter()
    up = WalEmitter(inner=sink, wal=FileWal(wal_dir))
    result = up.replay()
    assert result.delivered == 1
    assert result.remaining == 0
    assert up.pending() == 0


def test_wal_emitter_cannot_wrap_daemon_emitter(tmp_path):
    """Footgun: DaemonEmitter passes the runtime_checkable isinstance but its
    emit() signature is incompatible, so the WAL cannot protect the local path.

    Tracked as PY-P4 in docs/operations/current.md, gated on #599. When the
    fix lands, replace this with a positive assertion that WalEmitter wrapped
    around DaemonEmitter composes correctly.
    """
    from obsigna import DaemonEmitter
    from obsigna.emitters import Emitter, FileWal, WalEmitter

    d = DaemonEmitter(socket_path=str(tmp_path / "x.sock"))
    assert isinstance(d, Emitter) is True
    wrapped = WalEmitter(inner=d, wal=FileWal(str(tmp_path / "wal")))
    with pytest.raises(TypeError):
        wrapped.emit(_signed_receipt())
