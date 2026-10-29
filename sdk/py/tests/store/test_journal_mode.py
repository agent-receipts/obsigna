"""Tests for the store's SQLite journal mode (ADR-0004 shared contract: WAL)."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

from obsigna.receipt.hash import hash_receipt
from obsigna.store.store import ReceiptQuery, open_store
from tests.conftest import make_receipt

if TYPE_CHECKING:
    from pathlib import Path

_FOREIGN_SCHEMA = """\
CREATE TABLE receipts (
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
CREATE UNIQUE INDEX idx_receipts_chain ON receipts(chain_id, sequence);
CREATE INDEX idx_receipts_action ON receipts(action_type);
CREATE INDEX idx_receipts_risk ON receipts(risk_level);
CREATE INDEX idx_receipts_timestamp ON receipts(timestamp);
"""


def _journal_mode(conn: sqlite3.Connection) -> str:
    row = conn.execute("PRAGMA journal_mode").fetchone()
    return str(row[0])


def _raw(path: Path) -> sqlite3.Connection:
    # Autocommit mode so BEGIN/COMMIT are explicit and under test control.
    return sqlite3.connect(str(path), isolation_level=None, timeout=0)


def test_file_backed_store_uses_wal(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    store = open_store(str(db_path))
    observer = _raw(db_path)
    try:
        assert _journal_mode(observer) == "wal"
    finally:
        observer.close()
        store.close()


def test_wal_persists_across_reopen(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    open_store(str(db_path)).close()
    open_store(str(db_path)).close()

    observer = _raw(db_path)
    try:
        assert _journal_mode(observer) == "wal"
    finally:
        observer.close()


def test_in_memory_store_still_works() -> None:
    store = open_store(":memory:")
    try:
        receipt = make_receipt(id="urn:receipt:mem-1")
        store.insert(receipt, hash_receipt(receipt))
        result = store.get_by_id(receipt.id)
        assert result is not None
        assert result.id == receipt.id
    finally:
        store.close()


def test_store_reads_while_another_connection_holds_write_transaction(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "receipts.db"
    store = open_store(str(db_path))
    seeded = make_receipt(id="urn:receipt:busy-1", sequence=1)
    store.insert(seeded, hash_receipt(seeded))

    writer = _raw(db_path)
    writer.execute("BEGIN EXCLUSIVE")
    writer.execute("UPDATE receipts SET status = status WHERE id = 'urn:none'")
    reader = _raw(db_path)
    try:
        # Neither the store nor an independent reader may see SQLITE_BUSY.
        result = store.get_by_id(seeded.id)
        assert result is not None
        assert result.id == seeded.id
        count = reader.execute("SELECT count(*) FROM receipts").fetchone()[0]
        assert count == 1
    finally:
        reader.close()
        writer.execute("ROLLBACK")
        writer.close()
        store.close()


def test_store_writes_while_another_connection_holds_read_transaction(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "receipts.db"
    store = open_store(str(db_path))
    first = make_receipt(id="urn:receipt:rd-1", sequence=1)
    store.insert(first, hash_receipt(first))

    reader = _raw(db_path)
    reader.execute("BEGIN")
    reader.execute("SELECT count(*) FROM receipts").fetchone()
    try:
        second = make_receipt(
            id="urn:receipt:rd-2", sequence=2, previous_hash=hash_receipt(first)
        )
        store.insert(second, hash_receipt(second))
        assert store.get_by_id(second.id) is not None
    finally:
        reader.execute("COMMIT")
        reader.close()
        store.close()


def test_reads_wal_database_written_by_another_sdk(tmp_path: Path) -> None:
    # Emulate the TypeScript/Go writer: same shared schema, WAL mode, and a
    # connection that stays open so the row lives only in the -wal file.
    db_path = tmp_path / "receipts.db"
    foreign = _raw(db_path)
    foreign.execute("PRAGMA journal_mode=WAL")
    foreign.executescript(_FOREIGN_SCHEMA)
    receipt = make_receipt(id="urn:receipt:foreign-1")
    subject = receipt.credentialSubject
    foreign.execute(
        """
        INSERT INTO receipts
            (id, chain_id, sequence, action_type, tool_name, risk_level, status,
             timestamp, issuer_id, principal_id, receipt_json, receipt_hash,
             previous_receipt_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            receipt.id,
            subject.chain.chain_id,
            subject.chain.sequence,
            subject.action.type,
            subject.action.tool_name or "",
            subject.action.risk_level,
            subject.outcome.status,
            subject.action.timestamp,
            receipt.issuer.id,
            subject.principal.id if subject.principal else None,
            receipt.model_dump_json(by_alias=True),
            hash_receipt(receipt),
            subject.chain.previous_receipt_hash,
        ),
    )

    store = open_store(str(db_path))
    try:
        results = store.query(ReceiptQuery())
        assert [r.id for r in results] == [receipt.id]
        assert _journal_mode(foreign) == "wal"
    finally:
        store.close()
        foreign.close()
