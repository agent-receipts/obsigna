"""Tests for CompositeEmitter: sequential fan-out with error aggregation."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from obsigna.emitters import (
    CompositeEmitError,
    CompositeEmitter,
    InMemoryEmitter,
)
from tests.conftest import make_receipt

if TYPE_CHECKING:
    from obsigna.receipt.types import AgentReceipt


class FailingEmitter:
    """Emitter that always raises — used to assert aggregation."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.calls: list[AgentReceipt] = []

    def emit(self, receipt: AgentReceipt) -> None:
        self.calls.append(receipt)
        raise self.exc


def test_forwards_each_receipt_to_every_child() -> None:
    a, b, c = InMemoryEmitter(), InMemoryEmitter(), InMemoryEmitter()
    composite = CompositeEmitter([a, b, c])
    composite.emit(make_receipt(id="urn:r:1"))
    composite.emit(make_receipt(id="urn:r:2"))
    for child in (a, b, c):
        assert [r.id for r in child.received] == ["urn:r:1", "urn:r:2"]


def test_continues_past_failing_child() -> None:
    before = InMemoryEmitter()
    failing = FailingEmitter(RuntimeError("boom"))
    after = InMemoryEmitter()
    composite = CompositeEmitter([before, failing, after])

    with pytest.raises(CompositeEmitError):
        composite.emit(make_receipt(id="urn:r:1"))

    assert [r.id for r in before.received] == ["urn:r:1"]
    assert [r.id for r in failing.calls] == ["urn:r:1"]
    assert [r.id for r in after.received] == ["urn:r:1"]


def test_aggregates_errors_in_thrown_order() -> None:
    err1 = RuntimeError("first")
    err2 = RuntimeError("second")
    composite = CompositeEmitter(
        [FailingEmitter(err1), InMemoryEmitter(), FailingEmitter(err2)],
    )
    with pytest.raises(CompositeEmitError) as info:
        composite.emit(make_receipt(id="urn:r:1"))
    assert info.value.errors == [err1, err2]


def test_no_children_resolves_cleanly() -> None:
    composite = CompositeEmitter([])
    composite.emit(make_receipt(id="urn:r:1"))


def test_all_children_succeed() -> None:
    a, b = InMemoryEmitter(), InMemoryEmitter()
    composite = CompositeEmitter([a, b])
    composite.emit(make_receipt(id="urn:r:1"))
    assert [r.id for r in a.received] == ["urn:r:1"]
    assert [r.id for r in b.received] == ["urn:r:1"]
