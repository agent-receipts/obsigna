"""Tests for the store's SQLite journal mode (WAL, per the ADR-0004 contract)."""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING

from obsigna.receipt.hash import hash_receipt
from obsigna.store.store import ReceiptQuery, open_store
from tests.conftest import make_receipt

if TYPE_CHECKING:
    from pathlib import Path

# Schema as written by the TypeScript SDK (no idx_receipts_status), used to
# simulate a database created by another SDK.
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
    """Read the persistent journal mode through an independent connection."""
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("PRAGMA journal_mode").fetchone()
        return str(row[0]).lower()
    finally:
        conn.close()


def test_open_store_enables_wal_on_file_db(tmp_path: Path) -> None:
    db_path = str(tmp_path / "receipts.db")
    store = open_store(db_path)
    try:
        assert _journal_mode(db_path) == "wal"
    finally:
        store.close()


def test_wal_persists_after_close(tmp_path: Path) -> None:
    db_path = str(tmp_path / "receipts.db")
    store = open_store(db_path)
    store.close()
    assert _journal_mode(db_path) == "wal"


def test_reopen_existing_wal_db_is_idempotent(tmp_path: Path) -> None:
    db_path = str(tmp_path / "receipts.db")
    receipt = make_receipt(id="urn:receipt:reopen")

    first = open_store(db_path)
    first.insert(receipt, hash_receipt(receipt))
    first.close()
    assert _journal_mode(db_path) == "wal"

    second = open_store(db_path)
    try:
        assert _journal_mode(db_path) == "wal"
        result = second.get_by_id("urn:receipt:reopen")
        assert result is not None
        assert result.id == receipt.id
    finally:
        second.close()

    third = open_store(db_path)
    third.close()
    assert _journal_mode(db_path) == "wal"


def test_in_memory_store_still_works() -> None:
    store = open_store(":memory:")
    try:
        receipt = make_receipt(id="urn:receipt:mem")
        store.insert(receipt, hash_receipt(receipt))
        results = store.query(ReceiptQuery())
        assert [r.id for r in results] == ["urn:receipt:mem"]
    finally:
        store.close()


def test_reader_not_blocked_by_open_write_transaction(tmp_path: Path) -> None:
    """A reader must not see SQLITE_BUSY while another connection writes."""
    db_path = str(tmp_path / "receipts.db")
    store = open_store(db_path)
    seed = make_receipt(id="urn:receipt:seed")
    store.insert(seed, hash_receipt(seed))

    writer = sqlite3.connect(db_path, timeout=0, isolation_level=None)
    try:
        writer.execute("BEGIN EXCLUSIVE")
        writer.execute("DELETE FROM receipts WHERE id = ?", ("urn:receipt:seed",))

        results = store.query(ReceiptQuery())
        assert [r.id for r in results] == ["urn:receipt:seed"]
        assert store.get_by_id("urn:receipt:seed") is not None

        writer.execute("ROLLBACK")
    finally:
        writer.close()
        store.close()


def test_writer_not_blocked_by_open_read_transaction(tmp_path: Path) -> None:
    """A long-lived reader must not make the store's writes fail."""
    db_path = str(tmp_path / "receipts.db")
    store = open_store(db_path)
    seed = make_receipt(id="urn:receipt:seed", sequence=1)
    store.insert(seed, hash_receipt(seed))

    reader = sqlite3.connect(db_path, timeout=0, isolation_level=None)
    try:
        reader.execute("BEGIN")
        assert reader.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 1

        nxt = make_receipt(id="urn:receipt:next", sequence=2)
        store.insert(nxt, hash_receipt(nxt))
        assert store.get_by_id("urn:receipt:next") is not None

        reader.execute("COMMIT")
    finally:
        reader.close()
        store.close()


def test_reads_wal_db_created_by_another_sdk(tmp_path: Path) -> None:
    """A WAL database written with the TS SDK's schema is readable here."""
    db_path = str(tmp_path / "receipts.db")
    receipt = make_receipt(id="urn:receipt:foreign")
    receipt_data = receipt.model_dump(by_alias=True, exclude_none=True)
    receipt_data["credentialSubject"]["chain"]["previous_receipt_hash"] = None

    foreign = sqlite3.connect(db_path)
    try:
        mode = foreign.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        assert str(mode).lower() == "wal"
        foreign.executescript(_TS_SCHEMA)
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
                "",
                subject.action.risk_level,
                subject.outcome.status,
                subject.action.timestamp,
                receipt.issuer.id,
                None,
                json.dumps(receipt_data, default=str),
                hash_receipt(receipt),
                None,
            ),
        )
        foreign.commit()
    finally:
        foreign.close()

    store = open_store(db_path)
    try:
        result = store.get_by_id("urn:receipt:foreign")
        assert result is not None
        assert result.id == receipt.id
        assert _journal_mode(db_path) == "wal"
    finally:
        store.close()


def test_wal_db_written_here_is_readable_by_another_connection(
    tmp_path: Path,
) -> None:
    """Another SDK opening the file read-only sees our rows and WAL mode."""
    db_path = str(tmp_path / "receipts.db")
    store = open_store(db_path)
    receipt = make_receipt(id="urn:receipt:py")
    store.insert(receipt, hash_receipt(receipt))
    store.close()

    ro = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        mode = ro.execute("PRAGMA journal_mode").fetchone()[0]
        assert str(mode).lower() == "wal"
        row = ro.execute(
            "SELECT receipt_json FROM receipts WHERE id = ?", ("urn:receipt:py",)
        ).fetchone()
        assert row is not None
        assert json.loads(row[0])["id"] == "urn:receipt:py"
    finally:
        ro.close()
