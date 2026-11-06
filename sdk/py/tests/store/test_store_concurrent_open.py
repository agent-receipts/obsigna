"""Simultaneous first opens of a fresh store must not fail with SQLITE_BUSY.

The WAL switch and schema creation can hit lock-upgrade paths where SQLite
does not invoke the busy handler, so the store retries within a deadline.
"""

from __future__ import annotations

import sqlite3
import threading
from typing import TYPE_CHECKING

from obsigna.store.store import open_store

if TYPE_CHECKING:
    from pathlib import Path

_OPENERS = 8
_ROUNDS = 10


def _journal_mode(db_path: str) -> str:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("PRAGMA journal_mode").fetchone()
        return str(row[0]).lower()
    finally:
        conn.close()


def _race_first_opens(db_path: str) -> list[BaseException]:
    barrier = threading.Barrier(_OPENERS)
    errors: list[BaseException] = []
    lock = threading.Lock()

    def open_once() -> None:
        barrier.wait()
        try:
            open_store(db_path).close()
        except BaseException as exc:
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=open_once) for _ in range(_OPENERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return errors


def test_simultaneous_first_opens_succeed(tmp_path: Path) -> None:
    for round_no in range(_ROUNDS):
        db_path = str(tmp_path / f"receipts-{round_no}.db")
        assert _race_first_opens(db_path) == []
        assert _journal_mode(db_path) == "wal"
