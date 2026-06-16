"""Tests for the write-ahead log emitter (ADR-0020 at-least-once delivery).

Covers both WAL backends (MemoryWal, FileWal) and the WalEmitter contract:
write-ahead before delivery, clear on ack, retain on failure, replay after a
simulated crash, and deadline-bounded flush for ephemeral shutdown.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest

from obsigna.emitters import (
    EmitError,
    FileWal,
    MemoryWal,
    Wal,
    WalDrainResult,
    WalEmitter,
)
from tests.conftest import make_receipt

if TYPE_CHECKING:
    from pathlib import Path

    from obsigna.receipt.types import AgentReceipt


def receipt(id: str, sequence: int = 1) -> AgentReceipt:
    return make_receipt(id=id, sequence=sequence)


class FlakyEmitter:
    """Inner emitter whose behaviour is scriptable per receipt id.

    Default is to succeed; ids passed to :meth:`fail_on` raise until cleared
    via :meth:`heal`. Optionally delays each delivery to drive deadline tests.
    """

    def __init__(self) -> None:
        self.delivered: list[str] = []
        self._failing: set[str] = set()
        self._delay_s = 0.0

    def fail_on(self, *ids: str) -> None:
        self._failing.update(ids)

    def heal(self, *ids: str) -> None:
        self._failing.difference_update(ids)

    def set_delay(self, ms: int) -> None:
        self._delay_s = ms / 1000.0

    def emit(self, r: AgentReceipt) -> None:
        if self._delay_s > 0:
            time.sleep(self._delay_s)
        if r.id in self._failing:
            raise EmitError(f"flaky: refusing {r.id}", status=503)
        self.delivered.append(r.id)


def _ids(receipts: list[AgentReceipt]) -> list[str]:
    return [r.id for r in receipts]


class TestMemoryWal:
    def test_appends_lists_in_order_and_removes(self) -> None:
        wal = MemoryWal()
        wal.append(receipt("a"))
        wal.append(receipt("b"))
        wal.append(receipt("c"))
        assert _ids(wal.list()) == ["a", "b", "c"]

        wal.remove("b")
        assert _ids(wal.list()) == ["a", "c"]

    def test_reappend_is_idempotent_overwrite_keeping_position(self) -> None:
        wal = MemoryWal()
        wal.append(receipt("a", 1))
        wal.append(receipt("b", 2))
        wal.append(receipt("a", 99))  # re-append keeps position
        listed = wal.list()
        assert _ids(listed) == ["a", "b"]
        assert listed[0].credentialSubject.chain.sequence == 99

    def test_remove_unknown_id_is_no_op(self) -> None:
        wal = MemoryWal()
        wal.append(receipt("a"))
        wal.remove("missing")
        assert _ids(wal.list()) == ["a"]


class TestFileWal:
    def test_persists_entries_and_lists_in_append_order(self, tmp_path: Path) -> None:
        wal = FileWal(tmp_path)
        wal.append(receipt("a"))
        wal.append(receipt("b"))
        assert _ids(wal.list()) == ["a", "b"]
        # One JSON file per entry, no leftover temp files.
        files = list(tmp_path.iterdir())
        assert len(files) == 2
        assert all(f.name.endswith(".json") for f in files)

    def test_removes_entries_and_deletes_their_files(self, tmp_path: Path) -> None:
        wal = FileWal(tmp_path)
        wal.append(receipt("a"))
        wal.append(receipt("b"))
        wal.remove("a")
        assert _ids(wal.list()) == ["b"]
        assert len(list(tmp_path.iterdir())) == 1

    def test_survives_a_restart_by_reloading_from_disk(self, tmp_path: Path) -> None:
        first = FileWal(tmp_path)
        first.append(receipt("a", 1))
        first.append(receipt("b", 2))
        first.remove("a")

        # Simulate a fresh process: a new FileWal over the same directory.
        second = FileWal(tmp_path)
        listed = second.list()
        assert _ids(listed) == ["b"]
        assert listed[0].credentialSubject.chain.sequence == 2

    def test_preserves_order_across_restart_for_new_entry(self, tmp_path: Path) -> None:
        first = FileWal(tmp_path)
        first.append(receipt("a"))
        first.append(receipt("b"))

        second = FileWal(tmp_path)
        second.append(receipt("c"))
        assert _ids(second.list()) == ["a", "b", "c"]

    def test_reappend_rewrites_in_place_without_reordering(
        self, tmp_path: Path
    ) -> None:
        wal = FileWal(tmp_path)
        wal.append(receipt("a", 1))
        wal.append(receipt("b", 2))
        wal.append(receipt("a", 50))
        listed = wal.list()
        assert _ids(listed) == ["a", "b"]
        assert listed[0].credentialSubject.chain.sequence == 50
        json_files = [f for f in tmp_path.iterdir() if f.name.endswith(".json")]
        assert len(json_files) == 2

    def test_drops_a_torn_entry_rather_than_failing_load(self, tmp_path: Path) -> None:
        wal = FileWal(tmp_path)
        wal.append(receipt("a"))
        wal.append(receipt("b"))
        # Corrupt the first entry as a hard-crash mid-write would.
        json_files = sorted(f for f in tmp_path.iterdir() if f.name.endswith(".json"))
        json_files[0].write_text("{ not valid json", encoding="utf-8")

        reloaded = FileWal(tmp_path)
        # The readable entry survives; the torn one is dropped.
        assert _ids(reloaded.list()) == ["b"]


class TestWalEmitter:
    def test_clears_entry_once_delivery_acknowledged(self) -> None:
        wal: Wal = MemoryWal()
        inner = FlakyEmitter()
        emitter = WalEmitter(inner=inner, wal=wal)

        emitter.emit(receipt("a"))

        assert inner.delivered == ["a"]
        assert emitter.pending() == 0

    def test_retains_entry_and_reraises_when_delivery_fails(self) -> None:
        wal: Wal = MemoryWal()
        inner = FlakyEmitter()
        inner.fail_on("a")
        emitter = WalEmitter(inner=inner, wal=wal)

        with pytest.raises(EmitError):
            emitter.emit(receipt("a"))
        assert inner.delivered == []
        assert emitter.pending() == 1

    def test_replay_redelivers_everything_unacknowledged(self) -> None:
        wal: Wal = MemoryWal()
        inner = FlakyEmitter()
        inner.fail_on("a", "b")
        emitter = WalEmitter(inner=inner, wal=wal)

        with pytest.raises(EmitError):
            emitter.emit(receipt("a"))
        with pytest.raises(EmitError):
            emitter.emit(receipt("b"))
        assert emitter.pending() == 2

        # Collector recovers; replay drains the backlog.
        inner.heal("a", "b")
        result = emitter.replay()
        assert result == WalDrainResult(delivered=2, remaining=0)
        assert inner.delivered == ["a", "b"]
        assert emitter.pending() == 0

    def test_replay_leaves_failing_entries_without_blocking_rest(self) -> None:
        wal: Wal = MemoryWal()
        inner = FlakyEmitter()
        inner.fail_on("a", "b", "c")
        emitter = WalEmitter(inner=inner, wal=wal)
        for rid in ("a", "b", "c"):
            with pytest.raises(EmitError):
                emitter.emit(receipt(rid))

        # Only the middle entry stays broken.
        inner.heal("a", "c")
        result = emitter.replay()
        assert result == WalDrainResult(delivered=2, remaining=1)
        assert sorted(inner.delivered) == ["a", "c"]
        assert _ids(wal.list()) == ["b"]

    def test_replays_durable_backlog_after_simulated_restart(
        self, tmp_path: Path
    ) -> None:
        # Process 1: delivery fails, entry persists to disk, then the process
        # "crashes" (we drop the emitter).
        wal1 = FileWal(tmp_path)
        inner1 = FlakyEmitter()
        inner1.fail_on("a")
        emitter1 = WalEmitter(inner=inner1, wal=wal1)
        with pytest.raises(EmitError):
            emitter1.emit(receipt("a"))

        # Process 2: fresh emitter over the same WAL dir; collector is healthy.
        wal2 = FileWal(tmp_path)
        inner2 = FlakyEmitter()
        emitter2 = WalEmitter(inner=inner2, wal=wal2)
        assert emitter2.pending() == 1

        result = emitter2.replay()
        assert result == WalDrainResult(delivered=1, remaining=0)
        assert inner2.delivered == ["a"]
        json_files = [f for f in tmp_path.iterdir() if f.name.endswith(".json")]
        assert len(json_files) == 0

    def test_flush_returns_zero_after_clean_drain(self) -> None:
        wal: Wal = MemoryWal()
        inner = FlakyEmitter()
        inner.fail_on("a")
        emitter = WalEmitter(inner=inner, wal=wal)
        with pytest.raises(EmitError):
            emitter.emit(receipt("a"))

        inner.heal("a")
        remaining = emitter.flush(1_000)
        assert remaining == 0
        assert inner.delivered == ["a"]

    def test_flush_respects_deadline_and_reports_pending(self) -> None:
        wal: Wal = MemoryWal()
        inner = FlakyEmitter()
        # Deliveries are healthy but slow; the deadline cuts the drain short.
        inner.set_delay(200)
        emitter = WalEmitter(inner=inner, wal=wal)
        wal.append(receipt("a"))
        wal.append(receipt("b"))

        remaining = emitter.flush(50)
        assert remaining > 0
