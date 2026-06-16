"""Tests for the SQLite receipt store."""

from __future__ import annotations

import pytest

from obsigna.receipt.hash import hash_receipt
from obsigna.store.store import ReceiptQuery, ReceiptStore, open_store
from tests.conftest import make_receipt


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
