"""Tests for SQLite journal-mode and busy-timeout parity with the Go store.

ADR-0004: WAL journal mode is part of the shared store contract across the
Go, Python and TypeScript SDKs, so readers (e.g. the CLI opened read-only)
can read while a writer holds a write transaction.
"""

from __future__ import annotations

import sqlite3
import threading
from typing import TYPE_CHECKING

from obsigna.receipt.hash import hash_receipt
from obsigna.store.store import ReceiptQuery, open_store
from tests.conftest import make_receipt

if TYPE_CHECKING:
    from pathlib import Path

# Schema as written by the TypeScript SDK (sdk/ts/src/store/store.ts). It
# lacks idx_receipts_status, which the Python store adds.
_TS_SCHEMA = """\
CREATE TABLE IF NOT EXISTS receipts (
  id TEXT PRIMARY KEY,
  chain_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  action_type TEXT NOT NULL,
  tool_name TEXT NOT NULL DEFAULT '',
  risk_level TEXT NOT NULL,
  status TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  issuer_id TEXT NOT NULL,
  principal_id TEXT,
  receipt_json TEXT NOT NULL,
  receipt_hash TEXT NOT NULL,
  previous_receipt_hash TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_chain ON receipts(chain_id, sequence);
CREATE INDEX IF NOT EXISTS idx_receipts_action ON receipts(action_type);
CREATE INDEX IF NOT EXISTS idx_receipts_risk ON receipts(risk_level);
CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp);
"""


def _journal_mode(db_path: str) -> str:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("PRAGMA journal_mode").fetchone()
        return str(row[0]).lower()
    finally:
        conn.close()


def test_file_backed_store_uses_wal(tmp_path: Path) -> None:
    db_path = str(tmp_path / "receipts.db")
    store = open_store(db_path)
    try:
        # journal_mode=WAL is persistent in the database file, so a second,
        # independent connection observes it.
        assert _journal_mode(db_path) == "wal"
    finally:
        store.close()


def test_wal_persists_after_close(tmp_path: Path) -> None:
    db_path = str(tmp_path / "receipts.db")
    store = open_store(db_path)
    receipt = make_receipt()
    store.insert(receipt, hash_receipt(receipt))
    store.close()

    assert _journal_mode(db_path) == "wal"


def test_in_memory_store_still_works() -> None:
    store = open_store(":memory:")
    try:
        receipt = make_receipt(id="urn:receipt:mem-1")
        store.insert(receipt, hash_receipt(receipt))
        result = store.get_by_id("urn:receipt:mem-1")
        assert result is not None
        assert result.id == "urn:receipt:mem-1"
    finally:
        store.close()


def test_reader_not_blocked_by_open_write_transaction(tmp_path: Path) -> None:
    db_path = str(tmp_path / "receipts.db")
    store = open_store(db_path)
    receipt = make_receipt(id="urn:receipt:rw-1")
    store.insert(receipt, hash_receipt(receipt))

    writer = sqlite3.connect(db_path, isolation_level=None, timeout=0)
    # timeout=0 so a blocked read surfaces SQLITE_BUSY immediately instead
    # of waiting out a busy handler.
    reader = sqlite3.connect(db_path, timeout=0)
    try:
        # BEGIN EXCLUSIVE blocks all readers in rollback-journal mode; in WAL
        # mode readers continue to see the last committed snapshot.
        writer.execute("BEGIN EXCLUSIVE")
        writer.execute("DELETE FROM receipts")

        rows = reader.execute("SELECT id FROM receipts").fetchall()
        assert [r[0] for r in rows] == ["urn:receipt:rw-1"]

        writer.execute("ROLLBACK")
    finally:
        reader.close()
        writer.close()
        store.close()


def test_insert_waits_for_competing_writer(tmp_path: Path) -> None:
    db_path = str(tmp_path / "receipts.db")
    store = open_store(db_path)

    locked = threading.Event()
    release_after_s = 0.3

    def hold_write_lock() -> None:
        conn = sqlite3.connect(db_path, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            locked.set()
            threading.Event().wait(release_after_s)
            conn.execute("COMMIT")
        finally:
            conn.close()

    holder = threading.Thread(target=hold_write_lock)
    holder.start()
    try:
        assert locked.wait(5)
        # With a busy timeout comparable to Go's (5000 ms) the insert waits
        # for the competing writer instead of failing with SQLITE_BUSY.
        receipt = make_receipt(id="urn:receipt:busy-1")
        store.insert(receipt, hash_receipt(receipt))
    finally:
        holder.join()

    try:
        assert store.get_by_id("urn:receipt:busy-1") is not None
    finally:
        store.close()


def test_opens_wal_db_created_with_ts_schema(tmp_path: Path) -> None:
    db_path = str(tmp_path / "receipts.db")
    seed = sqlite3.connect(db_path)
    seed.execute("PRAGMA journal_mode=WAL")
    seed.executescript(_TS_SCHEMA)
    seed.close()

    store = open_store(db_path)
    try:
        receipt = make_receipt(id="urn:receipt:ts-1")
        store.insert(receipt, hash_receipt(receipt))
        results = store.query(ReceiptQuery())
        assert [r.id for r in results] == ["urn:receipt:ts-1"]
    finally:
        store.close()

    assert _journal_mode(db_path) == "wal"
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT id, tool_name FROM receipts").fetchall()
        assert [r[0] for r in rows] == ["urn:receipt:ts-1"]
    finally:
        conn.close()
