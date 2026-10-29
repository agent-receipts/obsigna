# ADR-0004: SQLite for Local Receipt Storage

## Status

Accepted

## Context

Each Agent Receipts SDK needs a local storage backend for signed receipts. Receipts are append-only, JSON-serialized W3C Verifiable Credentials that form hash-linked chains. The storage layer must support:

- Persistence across process restarts.
- Querying by chain ID, action type, risk level, and timestamp.
- Chain integrity verification (walking `previous_receipt_hash` links).
- Cross-platform operation with zero or minimal infrastructure.
- Identical semantics across three SDK languages (Go, Python, TypeScript).

The spec is explicitly storage-agnostic (spec v0.1, Design Principles) — it defines the receipt format and chain verification algorithm but does not prescribe a backend. This ADR covers the *SDK default*, not a protocol requirement.

We evaluated the following alternatives:

- **PostgreSQL / MySQL:** Full-featured, but require a running server process, connection configuration, and operational overhead (backups, upgrades, auth). For a local-first SDK that ships as a library, forcing users to run a separate database server is a significant adoption barrier. Network round-trips also add latency to every receipt write.
- **Flat files (JSON, JSONL, CSV):** Zero dependencies, but querying requires full scans. Filtering receipts by risk level, timestamp range, or action type — operations the CLI and dashboard use constantly — would degrade linearly with receipt count. Concurrent writes require manual file locking, and atomic multi-record operations (e.g., storing a receipt and updating chain state) are error-prone without transactions.
- **Embedded key-value stores (LevelDB, RocksDB, LMDB, BoltDB):** Low operational overhead and good write throughput, but querying on multiple fields requires maintaining secondary indexes manually. The SDK receipt stores index the common query dimensions (`chain_id`, `action_type`, `risk_level`, `timestamp`, with Python also indexing `status`); reimplementing those secondary indexes and query planning on top of a KV store adds complexity with no benefit over SQLite's built-in query engine.
- **In-memory only:** Useful for tests (all three SDKs support `:memory:` mode), but unsuitable as the default — receipts must survive process restarts to serve as an audit trail.

Related: #20 (parent issue).

## Decision

Use SQLite as the default local storage backend in all three SDK implementations, using each platform's most natural SQLite binding:

- **Go:** `modernc.org/sqlite` — pure Go, no CGO required.
- **Python:** `sqlite3` from the standard library.
- **TypeScript:** `node:sqlite` (`DatabaseSync`) from the Node.js built-in API.

All three implementations share a common schema: a `receipts` table with columns for chain ID, sequence number, action type, tool name, risk level, status, timestamp, issuer/principal IDs, the full receipt JSON, receipt hash, and previous receipt hash, plus indexes on the most common query dimensions. The journal mode is part of this shared contract: all three implementations (Go, Python `sqlite3`, TypeScript `node:sqlite`) open writable file-backed stores in WAL (Write-Ahead Logging) mode with a 5-second busy timeout, so read-only readers (the CLI, the dashboard, `store.OpenReadOnly` / `openStoreReadOnly`, see ADR-0010) can read while a writer is active. In-memory (`:memory:`) databases report the `memory` journal mode instead, and read-only opens never change the journal mode. WAL is not supported on network filesystems (NFS/SMB).

Key reasons:

- **Zero infrastructure** — SQLite is an embedded library, not a server. Users add the SDK to their project and get persistence immediately; there is nothing to install, configure, or operate.
- **Zero or near-zero external dependencies** — Python and TypeScript use platform built-ins. Go uses a pure-Go translation of the SQLite C source, avoiding CGO toolchain requirements.
- **SQL query support** — the CLI (`list`, `inspect`, `stats`, `timing`, `export`) and the web dashboard query receipts by multiple indexed fields. SQLite provides this out of the box without reimplementing indexes or query planning.
- **ACID transactions** — receipt writes and chain-state updates are atomic, eliminating partial-write corruption that plagues flat-file approaches.
- **Cross-platform** — SQLite runs on every OS and architecture the SDKs target, with a single-file database that is trivially copied, backed up, or inspected with standard tools (`sqlite3` CLI, DB Browser for SQLite).
- **Battle-tested at scale** — SQLite is the most widely deployed database engine in the world. Its reliability profile exceeds what this project could achieve with a custom storage layer.
- **Read-only access is safe** — the dashboard opens databases in read-only mode, allowing live inspection without risking corruption.

## Consequences

- All SDK users get local receipt persistence with no setup beyond importing the library.
- The identical schema across SDKs means databases are interchangeable — a database written by the Python SDK can be read by the Go CLI or the web dashboard.
- SQLite's single-writer model is sufficient for the expected workload (one agent process writing receipts), but would bottleneck under high-concurrency multi-writer scenarios. This is acceptable because the spec envisions receipts as a local-first artifact; high-throughput multi-writer use cases would warrant a different backend, which the storage-agnostic protocol design permits.
- Schema migrations must be coordinated across three SDK implementations. The project already handles this (e.g., the `tool_name` column migration exists in all three SDKs).
- Users who need a different backend (Postgres for a shared ledger, S3 for archival) can export receipts as portable W3C VCs — the protocol does not couple verification to any storage layer.
- The MCP proxy reuses the same SQLite approach for its audit store, keeping the operational model consistent.
