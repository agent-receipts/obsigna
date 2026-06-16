"""Tests for ReceiptChain — serialised receipt construction (ADR-0020, #488)."""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING

import pytest

from obsigna import (
    ChainEmitInput,
    InMemoryEmitter,
    ReceiptChain,
    generate_key_pair,
    hash_receipt,
    verify_chain,
)
from obsigna.receipt.create import ActionInput
from obsigna.receipt.types import AgentReceipt, Issuer, Outcome, Principal

if TYPE_CHECKING:
    from obsigna.emitters.types import Emitter

_KEYS = generate_key_pair()
_VERIFICATION_METHOD = "did:agent:test#key-1"


def _make_input(resource: str) -> ChainEmitInput:
    return ChainEmitInput(
        issuer=Issuer(id="did:agent:test"),
        principal=Principal(id="did:user:alice"),
        action=ActionInput(type="filesystem.file.read", risk_level="low"),
        outcome=Outcome(status="success"),
    )


def _make_chain(emitter: Emitter | None = None, **overrides: object) -> ReceiptChain:
    return ReceiptChain(
        chain_id="chain_test",
        private_key=_KEYS.private_key,
        verification_method=_VERIFICATION_METHOD,
        emitter=emitter if emitter is not None else InMemoryEmitter(),
        **overrides,  # type: ignore[arg-type]
    )


class _GateEmitter:
    """Emitter whose emit() blocks until ``release()`` is called."""

    def __init__(self) -> None:
        self.inner = InMemoryEmitter()
        self._gate = threading.Event()

    def release(self) -> None:
        self._gate.set()

    def emit(self, receipt: AgentReceipt) -> None:
        self._gate.wait(timeout=5)
        self.inner.emit(receipt)


def test_requires_core_options() -> None:
    with pytest.raises(ValueError, match="chain_id"):
        ReceiptChain(
            chain_id="",
            private_key=_KEYS.private_key,
            verification_method=_VERIFICATION_METHOD,
            emitter=InMemoryEmitter(),
        )
    with pytest.raises(ValueError, match="private_key"):
        ReceiptChain(
            chain_id="c",
            private_key="",
            verification_method=_VERIFICATION_METHOD,
            emitter=InMemoryEmitter(),
        )
    with pytest.raises(ValueError, match="verification_method"):
        ReceiptChain(
            chain_id="c",
            private_key=_KEYS.private_key,
            verification_method="",
            emitter=InMemoryEmitter(),
        )
    with pytest.raises(ValueError, match="emitter"):
        ReceiptChain(
            chain_id="c",
            private_key=_KEYS.private_key,
            verification_method=_VERIFICATION_METHOD,
            emitter=None,  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="start_sequence"):
        ReceiptChain(
            chain_id="c",
            private_key=_KEYS.private_key,
            verification_method=_VERIFICATION_METHOD,
            emitter=InMemoryEmitter(),
            start_sequence=0,
        )


def test_builds_signs_links_and_delivers_sequentially() -> None:
    emitter = InMemoryEmitter()
    chain = _make_chain(emitter)

    assert chain.next_sequence == 1
    assert chain.previous_receipt_hash is None

    r1 = chain.emit(_make_input("/a"))
    r2 = chain.emit(_make_input("/b"))
    r3 = chain.emit(_make_input("/c"))

    assert r1.credentialSubject.chain.sequence == 1
    assert r1.credentialSubject.chain.previous_receipt_hash is None
    assert r2.credentialSubject.chain.sequence == 2
    assert r2.credentialSubject.chain.previous_receipt_hash == hash_receipt(r1)
    assert r3.credentialSubject.chain.previous_receipt_hash == hash_receipt(r2)

    assert chain.next_sequence == 4
    assert chain.previous_receipt_hash == hash_receipt(r3)

    result = verify_chain(list(emitter.received), _KEYS.public_key)
    assert result.valid
    assert result.length == 3


def test_no_warning_when_called_sequentially(
    caplog: pytest.LogCaptureFixture,
) -> None:
    chain = _make_chain()
    with caplog.at_level(logging.WARNING, logger="obsigna.receipt_chain"):
        chain.emit(_make_input("/a"))
        chain.emit(_make_input("/b"))
    assert "concurrent emit()" not in caplog.text


def test_serialises_concurrent_emits_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    gate = _GateEmitter()
    chain = _make_chain(gate)

    n = 5
    threads = [
        threading.Thread(target=lambda i=i: chain.emit(_make_input(f"/{i}")))
        for i in range(n)
    ]

    with caplog.at_level(logging.WARNING, logger="obsigna.receipt_chain"):
        for t in threads:
            t.start()
        # Wait until the warning has fired — proof that ≥2 emits overlapped —
        # before releasing the gate. Bounded so a bug fails the test instead
        # of hanging.
        deadline = time.monotonic() + 5
        while "concurrent emit()" not in caplog.text:
            if time.monotonic() > deadline:
                pytest.fail("expected a concurrency warning")
            time.sleep(0.001)
        gate.release()
        for t in threads:
            t.join(timeout=5)

    received = list(gate.inner.received)
    assert len(received) == n
    # Serialised: contiguous sequence numbers and a chain that verifies.
    assert [r.credentialSubject.chain.sequence for r in received] == list(
        range(1, n + 1)
    )
    assert verify_chain(received, _KEYS.public_key).valid
    # Warned exactly once.
    assert caplog.text.count("concurrent emit()") == 1


def test_head_advances_before_delivery() -> None:
    state = {"fail_next": True}

    class FailingEmitter:
        def __init__(self) -> None:
            self.inner = InMemoryEmitter()

        def emit(self, receipt: AgentReceipt) -> None:
            if state["fail_next"]:
                state["fail_next"] = False
                msg = "collector unreachable"
                raise RuntimeError(msg)
            self.inner.emit(receipt)

    chain = _make_chain(FailingEmitter())

    with pytest.raises(RuntimeError, match="collector unreachable"):
        chain.emit(_make_input("/a"))
    # Head advanced even though delivery failed.
    assert chain.next_sequence == 2

    r2 = chain.emit(_make_input("/b"))
    assert r2.credentialSubject.chain.sequence == 2
    # r2 links to the signed-but-undelivered r1, not back to None.
    assert r2.credentialSubject.chain.previous_receipt_hash is not None


def test_rejects_emit_after_terminal() -> None:
    chain = _make_chain()
    terminal = _make_input("/done")
    terminal.terminal = True
    chain.emit(terminal)
    with pytest.raises(RuntimeError, match="closed"):
        chain.emit(_make_input("/after"))


def test_resumes_existing_chain() -> None:
    chain = _make_chain(start_sequence=7, previous_receipt_hash="sha256:deadbeef")
    r = chain.emit(_make_input("/a"))
    assert r.credentialSubject.chain.sequence == 7
    assert r.credentialSubject.chain.previous_receipt_hash == "sha256:deadbeef"
    assert chain.next_sequence == 8
