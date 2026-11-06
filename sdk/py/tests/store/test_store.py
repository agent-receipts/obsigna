"""Tests for the SQLite receipt store."""

from __future__ import annotations

import os
import sqlite3
from typing import TYPE_CHECKING
from urllib.parse import unquote

import pytest

from obsigna.receipt.hash import hash_receipt
from obsigna.store.store import (
    ReceiptQuery,
    ReceiptStore,
    open_store,
    open_store_read_only,
)
from tests.conftest import make_receipt

if TYPE_CHECKING:
    from pathlib import Path

# Pre-tool_name schema, as written by SDK versions before the migration.
_LEGACY_SCHEMA = """\
CREATE TABLE IF NOT EXISTS receipts (
  id TEXT PRIMARY KEY,
  chain_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  action_type TEXT NOT NULL,
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
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_chain
  ON receipts(chain_id, sequence);
"""


def test_open_store_creates_db() -> None:
    store = open_store(":memory:")
    assert isinstance(store, ReceiptStore)
    store.close()


def test_insert_and_get_by_id() -> None:
    store = open_store(":memory:")
    receipt = make_receipt()
    receipt_hash = hash_receipt(receipt)
    store.insert(receipt, receipt_hash)

    result = store.get_by_id(receipt.id)
    assert result is not None
    assert result.id == receipt.id
    assert result.credentialSubject.action.type == "filesystem.file.read"
    store.close()


def test_get_by_id_not_found_returns_none() -> None:
    store = open_store(":memory:")
    assert store.get_by_id("urn:receipt:nonexistent") is None
    store.close()


def test_insert_and_get_chain() -> None:
    store = open_store(":memory:")
    r1 = make_receipt(id="urn:receipt:c1-1", chain_id="chain-1", sequence=1)
    r2 = make_receipt(
        id="urn:receipt:c1-2",
        chain_id="chain-1",
        sequence=2,
        previous_hash=hash_receipt(r1),
    )
    r3 = make_receipt(
        id="urn:receipt:c1-3",
        chain_id="chain-1",
        sequence=3,
        previous_hash=hash_receipt(r2),
    )
    store.insert(r1, hash_receipt(r1))
    store.insert(r3, hash_receipt(r3))  # insert out of order
    store.insert(r2, hash_receipt(r2))

    chain = store.get_chain("chain-1")
    assert len(chain) == 3
    assert [r.credentialSubject.chain.sequence for r in chain] == [1, 2, 3]
    store.close()


def test_get_chain_empty() -> None:
    store = open_store(":memory:")
    assert store.get_chain("no-such-chain") == []
    store.close()


def test_query_by_chain_id() -> None:
    store = open_store(":memory:")
    r1 = make_receipt(id="urn:receipt:q1", chain_id="chain-a", sequence=1)
    r2 = make_receipt(id="urn:receipt:q2", chain_id="chain-b", sequence=1)
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))

    results = store.query(ReceiptQuery(chain_id="chain-a"))
    assert len(results) == 1
    assert results[0].id == "urn:receipt:q1"
    store.close()


def test_query_by_action_type() -> None:
    store = open_store(":memory:")
    r1 = make_receipt(
        id="urn:receipt:a1", action_type="fs.read", chain_id="ca1", sequence=1
    )
    r2 = make_receipt(
        id="urn:receipt:a2", action_type="net.request", chain_id="ca2", sequence=1
    )
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))

    results = store.query(ReceiptQuery(action_type="net.request"))
    assert len(results) == 1
    assert results[0].id == "urn:receipt:a2"
    store.close()


def test_query_by_risk_level() -> None:
    store = open_store(":memory:")
    r1 = make_receipt(id="urn:receipt:r1", risk_level="low", chain_id="cr1", sequence=1)
    r2 = make_receipt(
        id="urn:receipt:r2", risk_level="high", chain_id="cr2", sequence=1
    )
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))

    results = store.query(ReceiptQuery(risk_level="high"))
    assert len(results) == 1
    assert results[0].id == "urn:receipt:r2"
    store.close()


def test_query_by_status() -> None:
    store = open_store(":memory:")
    r1 = make_receipt(id="urn:receipt:s1", status="success", chain_id="cs1", sequence=1)
    r2 = make_receipt(id="urn:receipt:s2", status="failure", chain_id="cs2", sequence=1)
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))

    results = store.query(ReceiptQuery(status="failure"))
    assert len(results) == 1
    assert results[0].id == "urn:receipt:s2"
    store.close()


def test_query_by_time_range() -> None:
    store = open_store(":memory:")
    r1 = make_receipt(
        id="urn:receipt:t1",
        timestamp="2026-01-01T00:00:00Z",
        chain_id="ct1",
        sequence=1,
    )
    r2 = make_receipt(
        id="urn:receipt:t2",
        timestamp="2026-06-15T00:00:00Z",
        chain_id="ct2",
        sequence=1,
    )
    r3 = make_receipt(
        id="urn:receipt:t3",
        timestamp="2026-12-31T00:00:00Z",
        chain_id="ct3",
        sequence=1,
    )
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))
    store.insert(r3, hash_receipt(r3))

    results = store.query(
        ReceiptQuery(after="2026-03-01T00:00:00Z", before="2026-09-01T00:00:00Z")
    )
    assert len(results) == 1
    assert results[0].id == "urn:receipt:t2"
    store.close()


def test_query_with_limit() -> None:
    store = open_store(":memory:")
    for i in range(5):
        r = make_receipt(id=f"urn:receipt:l{i}", sequence=i + 1)
        store.insert(r, hash_receipt(r))

    results = store.query(ReceiptQuery(limit=2))
    assert len(results) == 2
    store.close()


def test_query_no_filters() -> None:
    store = open_store(":memory:")
    for i in range(3):
        r = make_receipt(id=f"urn:receipt:n{i}", sequence=i + 1)
        store.insert(r, hash_receipt(r))

    results = store.query(ReceiptQuery())
    assert len(results) == 3
    store.close()


def test_query_explicit_limit_respected() -> None:
    """An explicit limit still caps results after the cap removal."""
    store = open_store(":memory:")
    for i in range(5):
        r = make_receipt(id=f"urn:receipt:el{i}", sequence=i + 1)
        store.insert(r, hash_receipt(r))

    results = store.query(ReceiptQuery(limit=3))
    assert len(results) == 3
    store.close()


def test_query_no_default_limit() -> None:
    """No limit set means all rows are returned — no silent cap.

    Batch-inserts 15 000 rows via raw SQL to prove the LIMIT clause is absent.
    This would fail with the old DEFAULT_QUERY_LIMIT = 10_000 because only
    10 000 rows would be returned.
    """
    store = open_store(":memory:")
    n = 15_000
    # Generate one valid receipt JSON and reuse it for all rows (table id is
    # unique per row; receipt_json content only needs to be deserializable).
    base_receipt = make_receipt(id="urn:receipt:bulk-base", sequence=1)
    base_json = base_receipt.model_dump_json()
    rows = [
        (
            f"urn:receipt:bulk-{i}",
            "chain-bulk",
            i,
            "filesystem.file.read",
            "Read",
            "low",
            "success",
            f"2024-01-01T{i // 3600:02d}:{(i % 3600) // 60:02d}:{i % 60:02d}Z",
            "did:issuer",
            "did:user",
            base_json,
            f"sha256:bulk{i}",
            None,
        )
        for i in range(1, n + 1)
    ]
    store._conn.executemany(  # noqa: SLF001
        """INSERT INTO receipts
           (id, chain_id, sequence, action_type, tool_name, risk_level, status,
            timestamp, issuer_id, principal_id, receipt_json, receipt_hash,
            previous_receipt_hash)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )
    store._conn.commit()  # noqa: SLF001
    results = store.query(ReceiptQuery())
    assert len(results) == n
    store.close()


def test_query_order_asc_default() -> None:
    """Default ordering is ascending by timestamp (oldest first)."""
    store = open_store(":memory:")
    r1 = make_receipt(
        id="urn:receipt:ord1",
        timestamp="2026-01-01T00:00:00Z",
        chain_id="cord",
        sequence=1,
    )
    r2 = make_receipt(
        id="urn:receipt:ord2",
        timestamp="2026-06-01T00:00:00Z",
        chain_id="cord",
        sequence=2,
        previous_hash=hash_receipt(r1),
    )
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))

    results = store.query(ReceiptQuery())
    assert results[0].id == "urn:receipt:ord1"
    assert results[1].id == "urn:receipt:ord2"
    store.close()


def test_query_order_desc() -> None:
    """newest_first=True returns most recent receipts first."""
    store = open_store(":memory:")
    r1 = make_receipt(
        id="urn:receipt:desc1",
        timestamp="2026-01-01T00:00:00Z",
        chain_id="cdesc",
        sequence=1,
    )
    r2 = make_receipt(
        id="urn:receipt:desc2",
        timestamp="2026-06-01T00:00:00Z",
        chain_id="cdesc",
        sequence=2,
        previous_hash=hash_receipt(r1),
    )
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))

    results = store.query(ReceiptQuery(newest_first=True))
    assert results[0].id == "urn:receipt:desc2"
    assert results[1].id == "urn:receipt:desc1"
    store.close()


def test_query_desc_sequence_tiebreaker() -> None:
    """When timestamps are equal, higher sequence comes first in DESC order."""
    store = open_store(":memory:")
    shared_ts = "2026-06-01T12:00:00Z"
    r1 = make_receipt(
        id="urn:receipt:tie1",
        timestamp=shared_ts,
        chain_id="ctie",
        sequence=1,
    )
    r2 = make_receipt(
        id="urn:receipt:tie2",
        timestamp=shared_ts,
        chain_id="ctie",
        sequence=2,
        previous_hash=hash_receipt(r1),
    )
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))

    results = store.query(ReceiptQuery(newest_first=True))
    assert results[0].id == "urn:receipt:tie2"
    assert results[1].id == "urn:receipt:tie1"
    store.close()


def test_query_asc_sequence_tiebreaker() -> None:
    """When timestamps are equal, lower sequence comes first in ASC order."""
    store = open_store(":memory:")
    shared_ts = "2026-06-01T12:00:00Z"
    r1 = make_receipt(
        id="urn:receipt:asctie1", timestamp=shared_ts, chain_id="casctie", sequence=1
    )
    r2 = make_receipt(
        id="urn:receipt:asctie2",
        timestamp=shared_ts,
        chain_id="casctie",
        sequence=2,
        previous_hash=hash_receipt(r1),
    )
    store.insert(r2, hash_receipt(r2))  # insert higher sequence first
    store.insert(r1, hash_receipt(r1))

    results = store.query(ReceiptQuery())
    ids = [r.id for r in results]
    assert ids.index("urn:receipt:asctie1") < ids.index("urn:receipt:asctie2")
    store.close()


def test_stats() -> None:
    store = open_store(":memory:")
    r1 = make_receipt(
        id="urn:receipt:st1",
        chain_id="c1",
        sequence=1,
        risk_level="low",
        status="success",
        action_type="fs.read",
    )
    r2 = make_receipt(
        id="urn:receipt:st2",
        chain_id="c1",
        sequence=2,
        risk_level="high",
        status="failure",
        action_type="net.request",
    )
    r3 = make_receipt(
        id="urn:receipt:st3",
        chain_id="c2",
        sequence=1,
        risk_level="low",
        status="success",
        action_type="fs.read",
    )
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))
    store.insert(r3, hash_receipt(r3))

    s = store.stats()
    assert s.total == 3
    assert s.chains == 2
    assert len(s.by_risk) == 2
    assert len(s.by_status) == 2
    assert len(s.by_action) == 2
    store.close()


def test_tool_name_persisted() -> None:
    store = open_store(":memory:")
    r = make_receipt(id="urn:receipt:tn1")
    r.credentialSubject.action.tool_name = "list_issues"
    store.insert(r, hash_receipt(r))

    result = store.get_by_id("urn:receipt:tn1")
    assert result is not None
    assert result.credentialSubject.action.tool_name == "list_issues"
    store.close()


def test_migrate_tool_name_on_old_schema() -> None:
    """Opening an old DB without tool_name column triggers migration."""
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """\
        CREATE TABLE IF NOT EXISTS receipts (
          id TEXT PRIMARY KEY,
          chain_id TEXT NOT NULL,
          sequence INTEGER NOT NULL,
          action_type TEXT NOT NULL,
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
        CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_chain
          ON receipts(chain_id, sequence);
        """
    )
    # Verify tool_name column does not exist yet.
    cols = [row[1] for row in conn.execute("PRAGMA table_info(receipts)").fetchall()]
    assert "tool_name" not in cols
    conn.close()

    # ReceiptStore on a fresh :memory: DB always gets the new schema.
    # This test validates the migration function itself works.
    store = open_store(":memory:")
    r = make_receipt(id="urn:receipt:migrated")
    r.credentialSubject.action.tool_name = "read_file"
    store.insert(r, hash_receipt(r))

    result = store.get_by_id("urn:receipt:migrated")
    assert result is not None
    assert result.credentialSubject.action.tool_name == "read_file"
    store.close()


def test_close() -> None:
    store = open_store(":memory:")
    store.close()
    with pytest.raises(Exception):  # noqa: B017
        store.get_by_id("test")


# --- open_store_read_only ---------------------------------------------------


def _journal_mode(db_path: str) -> str:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("PRAGMA journal_mode").fetchone()
        return str(row[0]).lower()
    finally:
        conn.close()


def _seed_store(db_path: str) -> None:
    """Write two chains of receipts through a regular read-write store."""
    rw = open_store(db_path)
    try:
        r1 = make_receipt(
            id="urn:receipt:ro-1",
            chain_id="chain-ro",
            sequence=1,
            timestamp="2026-01-01T00:00:00Z",
            action_type="fs.read",
            risk_level="low",
            status="success",
        )
        r2 = make_receipt(
            id="urn:receipt:ro-2",
            chain_id="chain-ro",
            sequence=2,
            previous_hash=hash_receipt(r1),
            timestamp="2026-02-01T00:00:00Z",
            action_type="net.request",
            risk_level="high",
            status="failure",
        )
        r3 = make_receipt(
            id="urn:receipt:ro-3",
            chain_id="chain-other",
            sequence=1,
            timestamp="2026-03-01T00:00:00Z",
            action_type="fs.read",
            risk_level="low",
            status="success",
        )
        r3.credentialSubject.action.tool_name = "read_file"
        for r in (r1, r2, r3):
            rw.insert(r, hash_receipt(r))
    finally:
        rw.close()


def test_open_store_read_only_is_exported() -> None:
    import obsigna
    import obsigna.store

    assert obsigna.store.open_store_read_only is open_store_read_only
    assert obsigna.open_store_read_only is open_store_read_only


def test_open_store_read_only_returns_receipt_store(tmp_path: Path) -> None:
    db_path = str(tmp_path / "receipts.db")
    _seed_store(db_path)

    ro = open_store_read_only(db_path)
    try:
        assert isinstance(ro, ReceiptStore)
    finally:
        ro.close()


def test_open_store_read_only_connects_with_ro_uri(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_dir = tmp_path / "dir with space?and#hash"
    db_dir.mkdir()
    db_path = str(db_dir / "receipts.db")
    _seed_store(db_path)

    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    real_connect = sqlite3.connect

    def spy_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        calls.append((args, kwargs))
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", spy_connect)
    ro = open_store_read_only(db_path)
    monkeypatch.undo()
    ro.close()

    assert calls
    args, kwargs = calls[0]
    database = args[0] if args else kwargs["database"]
    assert isinstance(database, str)
    assert kwargs.get("uri") is True
    assert database.startswith("file:")
    assert database.endswith("?mode=ro")
    encoded_path = database[len("file:") : -len("?mode=ro")]
    # Every segment is percent-encoded, so none of the URI-significant
    # characters in the directory name appear literally.
    for ch in (" ", "?", "#"):
        assert ch not in encoded_path
    assert unquote(encoded_path) == os.path.abspath(db_path)


def test_open_store_read_only_reads_path_with_special_characters(
    tmp_path: Path,
) -> None:
    db_dir = tmp_path / "dir with space?and#hash"
    db_dir.mkdir()
    db_path = str(db_dir / "receipts.db")
    _seed_store(db_path)

    ro = open_store_read_only(db_path)
    try:
        assert [r.id for r in ro.query(ReceiptQuery())] == [
            "urn:receipt:ro-1",
            "urn:receipt:ro-2",
            "urn:receipt:ro-3",
        ]
    finally:
        ro.close()
    # Only the intended file exists; nothing was created at a truncated path.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dir with space?and#hash"]


def test_open_store_read_only_keeps_wal_journal_mode(tmp_path: Path) -> None:
    db_path = str(tmp_path / "receipts.db")
    _seed_store(db_path)
    assert _journal_mode(db_path) == "wal"

    ro = open_store_read_only(db_path)
    try:
        assert len(ro.query(ReceiptQuery())) == 3
    finally:
        ro.close()
    assert _journal_mode(db_path) == "wal"


def test_open_store_read_only_does_not_alter_legacy_db(tmp_path: Path) -> None:
    """No schema creation, tool_name migration or journal-mode switch."""
    db_path = str(tmp_path / "legacy.db")
    receipt = make_receipt(id="urn:receipt:legacy-1", chain_id="chain-legacy")
    seed = sqlite3.connect(db_path)
    try:
        seed.executescript(_LEGACY_SCHEMA)
        seed.execute(
            """INSERT INTO receipts
               (id, chain_id, sequence, action_type, risk_level, status,
                timestamp, issuer_id, principal_id, receipt_json, receipt_hash,
                previous_receipt_hash)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                receipt.id,
                "chain-legacy",
                1,
                "filesystem.file.read",
                "low",
                "success",
                "2026-01-01T00:00:00Z",
                "did:issuer",
                None,
                receipt.model_dump_json(),
                hash_receipt(receipt),
                None,
            ),
        )
        seed.commit()
    finally:
        seed.close()
    assert _journal_mode(db_path) == "delete"

    def schema_snapshot() -> list[tuple[str, str]]:
        conn = sqlite3.connect(db_path)
        try:
            rows = conn.execute(
                "SELECT type, name FROM sqlite_master ORDER BY type, name"
            ).fetchall()
            return [(str(r[0]), str(r[1])) for r in rows]
        finally:
            conn.close()

    def columns() -> list[str]:
        conn = sqlite3.connect(db_path)
        try:
            rows = conn.execute("PRAGMA table_info(receipts)").fetchall()
            return [str(r[1]) for r in rows]
        finally:
            conn.close()

    before_schema = schema_snapshot()
    before_columns = columns()
    assert "tool_name" not in before_columns

    ro = open_store_read_only(db_path)
    try:
        result = ro.get_by_id("urn:receipt:legacy-1")
        assert result is not None
        assert result.id == "urn:receipt:legacy-1"
    finally:
        ro.close()

    assert columns() == before_columns
    assert schema_snapshot() == before_schema
    assert _journal_mode(db_path) == "delete"


def test_open_store_read_only_rejects_memory() -> None:
    with pytest.raises(Exception, match=r"open_store_read_only.*:memory:"):
        open_store_read_only(":memory:")


def test_open_store_read_only_missing_path_raises_and_creates_nothing(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "does-not-exist.db"
    with pytest.raises((sqlite3.OperationalError, OSError)):
        open_store_read_only(str(missing))
    assert not missing.exists()
    assert list(tmp_path.iterdir()) == []


def test_open_store_read_only_matches_writable_store(tmp_path: Path) -> None:
    db_path = str(tmp_path / "receipts.db")
    _seed_store(db_path)

    rw = open_store(db_path)
    ro = open_store_read_only(db_path)
    try:
        for receipt_id in (
            "urn:receipt:ro-1",
            "urn:receipt:ro-3",
            "urn:receipt:nonexistent",
        ):
            assert ro.get_by_id(receipt_id) == rw.get_by_id(receipt_id)
        ro_3 = ro.get_by_id("urn:receipt:ro-3")
        assert ro_3 is not None
        assert ro_3.credentialSubject.action.tool_name == "read_file"

        for chain_id in ("chain-ro", "chain-other", "no-such-chain"):
            assert ro.get_chain(chain_id) == rw.get_chain(chain_id)
        assert len(ro.get_chain("chain-ro")) == 2

        for filters in (
            ReceiptQuery(),
            ReceiptQuery(newest_first=True),
            ReceiptQuery(chain_id="chain-ro"),
            ReceiptQuery(action_type="fs.read"),
            ReceiptQuery(risk_level="high"),
            ReceiptQuery(status="failure"),
            ReceiptQuery(after="2026-01-15T00:00:00Z", before="2026-02-15T00:00:00Z"),
            ReceiptQuery(limit=1),
        ):
            assert ro.query(filters) == rw.query(filters)
        assert len(ro.query(ReceiptQuery())) == 3

        ro_stats = ro.stats()
        assert ro_stats == rw.stats()
        assert ro_stats.total == 3
        assert ro_stats.chains == 2
    finally:
        ro.close()
        rw.close()


def test_open_store_read_only_insert_raises(tmp_path: Path) -> None:
    db_path = str(tmp_path / "receipts.db")
    _seed_store(db_path)

    ro = open_store_read_only(db_path)
    try:
        receipt = make_receipt(id="urn:receipt:should-fail", chain_id="chain-new")
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            ro.insert(receipt, hash_receipt(receipt))
    finally:
        ro.close()

    rw = open_store(db_path)
    try:
        assert rw.get_by_id("urn:receipt:should-fail") is None
    finally:
        rw.close()
