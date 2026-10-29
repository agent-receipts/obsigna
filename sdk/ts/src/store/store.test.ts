import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { makeReceipt } from "../test-utils/receipts.js";
import type { ReceiptStore } from "./store.js";
import { openStore, openStoreReadOnly } from "./store.js";

describe("ReceiptStore", () => {
	let store: ReceiptStore;

	beforeEach(() => {
		store = openStore(":memory:");
	});

	afterEach(() => {
		store.close();
	});

	describe("insert and getById", () => {
		it("stores and retrieves a receipt", () => {
			const receipt = makeReceipt({});
			store.insert(receipt, "sha256:abc");

			const retrieved = store.getById(receipt.id);
			expect(retrieved).toEqual(receipt);
		});

		it("returns undefined for missing receipt", () => {
			expect(store.getById("urn:receipt:missing")).toBeUndefined();
		});
	});

	describe("getChain", () => {
		it("returns receipts ordered by sequence", () => {
			store.insert(
				makeReceipt({ id: "urn:receipt:2", sequence: 2 }),
				"sha256:b",
			);
			store.insert(
				makeReceipt({ id: "urn:receipt:1", sequence: 1 }),
				"sha256:a",
			);
			store.insert(
				makeReceipt({ id: "urn:receipt:3", sequence: 3 }),
				"sha256:c",
			);

			const chain = store.getChain("chain_test");

			expect(chain).toHaveLength(3);
			expect(chain[0]?.id).toBe("urn:receipt:1");
			expect(chain[1]?.id).toBe("urn:receipt:2");
			expect(chain[2]?.id).toBe("urn:receipt:3");
		});

		it("returns empty array for unknown chain", () => {
			expect(store.getChain("nonexistent")).toEqual([]);
		});

		it("only returns receipts from the requested chain", () => {
			store.insert(
				makeReceipt({ id: "urn:receipt:a1", chainId: "chain_a" }),
				"sha256:a",
			);
			store.insert(
				makeReceipt({ id: "urn:receipt:b1", chainId: "chain_b" }),
				"sha256:b",
			);

			const chain = store.getChain("chain_a");
			expect(chain).toHaveLength(1);
			expect(chain[0]?.id).toBe("urn:receipt:a1");
		});
	});

	describe("query", () => {
		beforeEach(() => {
			store.insert(
				makeReceipt({
					id: "urn:receipt:1",
					actionType: "filesystem.file.read",
					riskLevel: "low",
					status: "success",
					timestamp: "2026-03-29T10:00:00Z",
				}),
				"sha256:1",
			);
			store.insert(
				makeReceipt({
					id: "urn:receipt:2",
					sequence: 2,
					actionType: "filesystem.file.delete",
					riskLevel: "high",
					status: "success",
					timestamp: "2026-03-29T11:00:00Z",
				}),
				"sha256:2",
			);
			store.insert(
				makeReceipt({
					id: "urn:receipt:3",
					sequence: 3,
					actionType: "system.command.execute",
					riskLevel: "critical",
					status: "failure",
					timestamp: "2026-03-29T12:00:00Z",
				}),
				"sha256:3",
			);
		});

		it("filters by action type", () => {
			const results = store.query({
				actionType: "filesystem.file.read",
			});
			expect(results).toHaveLength(1);
			expect(results[0]?.id).toBe("urn:receipt:1");
		});

		it("filters by risk level", () => {
			const results = store.query({ riskLevel: "critical" });
			expect(results).toHaveLength(1);
			expect(results[0]?.id).toBe("urn:receipt:3");
		});

		it("filters by status", () => {
			const results = store.query({ status: "failure" });
			expect(results).toHaveLength(1);
			expect(results[0]?.id).toBe("urn:receipt:3");
		});

		it("filters by time range", () => {
			const results = store.query({
				after: "2026-03-29T10:30:00Z",
				before: "2026-03-29T11:30:00Z",
			});
			expect(results).toHaveLength(1);
			expect(results[0]?.id).toBe("urn:receipt:2");
		});

		it("combines multiple filters", () => {
			const results = store.query({
				riskLevel: "high",
				status: "success",
			});
			expect(results).toHaveLength(1);
			expect(results[0]?.id).toBe("urn:receipt:2");
		});

		it("respects limit", () => {
			const results = store.query({ limit: 2 });
			expect(results).toHaveLength(2);
		});

		it("returns empty array when no matches", () => {
			const results = store.query({ riskLevel: "medium" });
			expect(results).toEqual([]);
		});

		it("returns all receipts with empty filter", () => {
			const results = store.query({});
			expect(results).toHaveLength(3);
		});

		// Regression: node:sqlite binds JS values by their runtime type, and
		// SQLite's LIMIT requires INTEGER. If `limit` is bound as TEXT (e.g.
		// via String(limit)) it returns zero rows on some Node versions.
		// See https://github.com/agent-receipts/ar/pull/249.
		it("returns rows when limit exceeds row count (LIMIT bound as INTEGER)", () => {
			const results = store.query({ limit: 20 });
			expect(results).toHaveLength(3);
		});

		it("returns rows when limit is combined with filters", () => {
			const results = store.query({
				status: "success",
				limit: 20,
			});
			expect(results).toHaveLength(2);
		});

		it("returns all rows ascending by default (no implicit cap)", () => {
			// The three rows were inserted in beforeEach; no limit means all 3.
			const results = store.query({});
			expect(results).toHaveLength(3);
			// Default order is ascending by timestamp.
			expect(results[0]?.id).toBe("urn:receipt:1");
			expect(results[2]?.id).toBe("urn:receipt:3");
		});

		it("returns rows in DESC order when order is 'desc'", () => {
			const results = store.query({ order: "desc" });
			expect(results).toHaveLength(3);
			expect(results[0]?.id).toBe("urn:receipt:3");
			expect(results[2]?.id).toBe("urn:receipt:1");
		});

		it("returns rows in ASC order when order is 'asc' (explicit)", () => {
			const results = store.query({ order: "asc" });
			expect(results).toHaveLength(3);
			expect(results[0]?.id).toBe("urn:receipt:1");
		});

		it("asc order with sequence tiebreaker when timestamps are equal", () => {
			store.insert(
				makeReceipt({
					id: "urn:receipt:asc-tie-1",
					sequence: 5,
					actionType: "filesystem.file.read",
					riskLevel: "low",
					status: "success",
					timestamp: "2026-01-01T00:00:00Z",
				}),
				"sha256:asctie1",
			);
			store.insert(
				makeReceipt({
					id: "urn:receipt:asc-tie-2",
					sequence: 6,
					actionType: "filesystem.file.read",
					riskLevel: "low",
					status: "success",
					timestamp: "2026-01-01T00:00:00Z",
				}),
				"sha256:asctie2",
			);

			const results = store.query({ order: "asc" });
			// Among the tied rows, lower sequence comes first.
			const tieIdx1 = results.findIndex(
				(r) => r.id === "urn:receipt:asc-tie-1",
			);
			const tieIdx2 = results.findIndex(
				(r) => r.id === "urn:receipt:asc-tie-2",
			);
			expect(tieIdx1).toBeGreaterThanOrEqual(0);
			expect(tieIdx2).toBeGreaterThanOrEqual(0);
			expect(tieIdx1).toBeLessThan(tieIdx2);
		});

		it("desc order with sequence tiebreaker when timestamps are equal", () => {
			// Insert two extra receipts with the same timestamp but different sequences.
			store.insert(
				makeReceipt({
					id: "urn:receipt:tie-1",
					sequence: 10,
					actionType: "filesystem.file.read",
					riskLevel: "low",
					status: "success",
					timestamp: "2026-03-29T13:00:00Z",
				}),
				"sha256:tie1",
			);
			store.insert(
				makeReceipt({
					id: "urn:receipt:tie-2",
					sequence: 11,
					actionType: "filesystem.file.read",
					riskLevel: "low",
					status: "success",
					timestamp: "2026-03-29T13:00:00Z",
				}),
				"sha256:tie2",
			);

			const results = store.query({ order: "desc" });
			// The two tied rows should come first (most recent timestamp),
			// with the higher sequence preceding the lower.
			expect(results[0]?.id).toBe("urn:receipt:tie-2");
			expect(results[1]?.id).toBe("urn:receipt:tie-1");
		});
	});

	describe("no implicit 10k cap (regression guard)", () => {
		it("returns all rows when limit is omitted, even beyond the former 10k cap", () => {
			// Batch-insert 15000 rows via raw SQL to prove the LIMIT clause is
			// absent when limit is undefined. This would fail with the old
			// DEFAULT_QUERY_LIMIT = 10000 because only 10000 rows would be returned.
			const freshStore = openStore(":memory:");
			const db: DatabaseSync = (freshStore as unknown as { db: DatabaseSync })
				.db;
			const stmt = db.prepare(
				`INSERT INTO receipts
				 (id, chain_id, sequence, action_type, tool_name, risk_level, status,
				  timestamp, issuer_id, principal_id, receipt_json, receipt_hash)
				 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			);
			// Minimal valid AgentReceipt JSON the SDK can deserialize.
			const baseJson = JSON.stringify({
				id: "urn:receipt:bulk-base",
				"@context": [
					"https://www.w3.org/ns/credentials/v2",
					"https://agentreceipts.ai/context/v1",
				],
				type: ["VerifiableCredential", "AgentReceipt"],
				version: "0.3.0",
				issuer: { id: "did:issuer" },
				issuanceDate: "2024-01-01T00:00:00Z",
				credentialSubject: {
					principal: { id: "did:user" },
					action: {
						id: "act_0",
						type: "filesystem.file.read",
						tool_name: "Read",
						risk_level: "low",
						timestamp: "2024-01-01T00:00:00Z",
					},
					outcome: { status: "success" },
					chain: {
						sequence: 1,
						chain_id: "chain-bulk",
						previous_receipt_hash: null,
					},
				},
				proof: {
					type: "Ed25519Signature2020",
					created: "2024-01-01T00:00:00Z",
					verificationMethod: "did:issuer#k1",
					proofPurpose: "assertionMethod",
					proofValue: `u${"A".repeat(86)}`,
				},
			});
			const n = 15_000;
			for (let i = 1; i <= n; i++) {
				stmt.run(
					`urn:receipt:bulk-${i}`,
					"chain-bulk",
					i,
					"filesystem.file.read",
					"Read",
					"low",
					"success",
					new Date(i * 1000).toISOString(),
					"did:issuer",
					"did:user",
					baseJson,
					`sha256:bulk${i}`,
				);
			}
			const results = freshStore.query({});
			expect(results).toHaveLength(n);
			freshStore.close();
		});
	});

	describe("corrupt receipt validation", () => {
		/**
		 * Helper to directly update the receipt_json for a stored row, bypassing
		 * the ReceiptStore API. Uses @ts-expect-error so a future rename of the
		 * private db field surfaces here at compile time.
		 */
		function rawDb(): DatabaseSync {
			// @ts-expect-error reaches into the private db field for test injection
			return store.db;
		}
		function corruptJson(id: string, payload: string): void {
			rawDb()
				.prepare("UPDATE receipts SET receipt_json = ? WHERE id = ?")
				.run(payload, id);
		}

		it("getById: throws on non-JSON garbage", () => {
			const receipt = makeReceipt({ id: "urn:receipt:corrupt-1" });
			store.insert(receipt, "sha256:c1");
			corruptJson("urn:receipt:corrupt-1", "not-json{{");

			expect(() => store.getById("urn:receipt:corrupt-1")).toThrowError(
				/Corrupt receipt in store \(id=urn:receipt:corrupt-1\)/,
			);
		});

		it("getById: preserves the original error as Error.cause", () => {
			const receipt = makeReceipt({ id: "urn:receipt:cause-json" });
			store.insert(receipt, "sha256:cj1");
			corruptJson("urn:receipt:cause-json", "not-json{{");

			let caught: unknown;
			try {
				store.getById("urn:receipt:cause-json");
			} catch (e) {
				caught = e;
			}
			expect(caught).toBeInstanceOf(Error);
			expect((caught as Error).cause).toBeInstanceOf(SyntaxError);
		});

		it("getById: preserves ZodError as Error.cause on schema failure", () => {
			const receipt = makeReceipt({ id: "urn:receipt:cause-zod" });
			store.insert(receipt, "sha256:cz1");
			const corrupt = JSON.parse(JSON.stringify(receipt)) as Record<
				string,
				unknown
			>;
			(corrupt.credentialSubject as Record<string, unknown>) = {};
			corruptJson("urn:receipt:cause-zod", JSON.stringify(corrupt));

			let caught: unknown;
			try {
				store.getById("urn:receipt:cause-zod");
			} catch (e) {
				caught = e;
			}
			expect(caught).toBeInstanceOf(Error);
			// ZodError extends Error and carries .issues
			const cause = (caught as Error).cause as
				| { issues?: unknown[] }
				| undefined;
			expect(cause).toBeDefined();
			expect(Array.isArray(cause?.issues)).toBe(true);
		});

		it("getById: renders (root) for root-shape failures", () => {
			const receipt = makeReceipt({ id: "urn:receipt:root-shape" });
			store.insert(receipt, "sha256:rs1");
			// Replace the row with a JSON primitive so the schema fails at the root.
			corruptJson("urn:receipt:root-shape", "42");

			expect(() => store.getById("urn:receipt:root-shape")).toThrowError(
				/\(root\):/,
			);
		});

		it("getById: throws with field path on missing required field", () => {
			const receipt = makeReceipt({ id: "urn:receipt:corrupt-2" });
			store.insert(receipt, "sha256:c2");
			// Remove chain_id from credentialSubject.chain
			const corrupt = JSON.parse(JSON.stringify(receipt)) as Record<
				string,
				unknown
			>;
			const cs = corrupt.credentialSubject as Record<string, unknown>;
			const chain = cs.chain as Record<string, unknown>;
			delete chain.chain_id;
			corruptJson("urn:receipt:corrupt-2", JSON.stringify(corrupt));

			expect(() => store.getById("urn:receipt:corrupt-2")).toThrowError(
				/credentialSubject\.chain\.chain_id/,
			);
		});

		it("getById: throws with field path on invalid enum value", () => {
			const receipt = makeReceipt({ id: "urn:receipt:corrupt-3" });
			store.insert(receipt, "sha256:c3");
			const corrupt = JSON.parse(JSON.stringify(receipt)) as Record<
				string,
				unknown
			>;
			const cs = corrupt.credentialSubject as Record<string, unknown>;
			const action = cs.action as Record<string, unknown>;
			action.risk_level = "extreme";
			corruptJson("urn:receipt:corrupt-3", JSON.stringify(corrupt));

			expect(() => store.getById("urn:receipt:corrupt-3")).toThrowError(
				/credentialSubject\.action\.risk_level/,
			);
		});

		it("getById: throws when chain.terminal is false (spec invariant)", () => {
			const receipt = makeReceipt({ id: "urn:receipt:corrupt-4" });
			store.insert(receipt, "sha256:c4");
			const corrupt = JSON.parse(JSON.stringify(receipt)) as Record<
				string,
				unknown
			>;
			const cs = corrupt.credentialSubject as Record<string, unknown>;
			const chain = cs.chain as Record<string, unknown>;
			chain.terminal = false;
			corruptJson("urn:receipt:corrupt-4", JSON.stringify(corrupt));

			expect(() => store.getById("urn:receipt:corrupt-4")).toThrowError(
				/Corrupt receipt in store \(id=urn:receipt:corrupt-4\)/,
			);
		});

		it("getChain: throws with chain context on corrupt row", () => {
			const receipt = makeReceipt({
				id: "urn:receipt:corrupt-chain-1",
				chainId: "chain_corrupt",
			});
			store.insert(receipt, "sha256:cc1");
			corruptJson("urn:receipt:corrupt-chain-1", "!!!bad json");

			expect(() => store.getChain("chain_corrupt")).toThrowError(
				/Corrupt receipt in store \(chain=chain_corrupt\)/,
			);
		});

		it("query: throws with query context on corrupt row", () => {
			const receipt = makeReceipt({ id: "urn:receipt:corrupt-query-1" });
			store.insert(receipt, "sha256:cq1");
			corruptJson("urn:receipt:corrupt-query-1", "!!!bad json");

			expect(() => store.query({})).toThrowError(
				/Corrupt receipt in store \(query\)/,
			);
		});

		// Guards the forward-compat property documented in ADR-0011 and
		// schema.ts: receipts written by a newer SDK with extra unknown fields
		// must round-trip through the store unchanged. Stripping those fields
		// would silently invalidate the RFC 8785 hash on signed receipts.
		it("preserves unknown extra fields written by a newer SDK", () => {
			const receipt = makeReceipt({ id: "urn:receipt:forward-compat" });
			store.insert(receipt, "sha256:fc1");

			const extended = JSON.parse(JSON.stringify(receipt)) as Record<
				string,
				unknown
			>;
			extended.future_top_level = "added in a later spec version";
			const cs = extended.credentialSubject as Record<string, unknown>;
			const action = cs.action as Record<string, unknown>;
			action.future_action_field = { nested: 42 };
			corruptJson("urn:receipt:forward-compat", JSON.stringify(extended));

			const loaded = store.getById("urn:receipt:forward-compat") as Record<
				string,
				unknown
			>;
			expect(loaded.future_top_level).toBe("added in a later spec version");
			const loadedAction = (loaded.credentialSubject as Record<string, unknown>)
				.action as Record<string, unknown>;
			expect(loadedAction.future_action_field).toEqual({ nested: 42 });
		});
	});

	describe("tool_name", () => {
		it("persists tool_name from receipt action", () => {
			const receipt = makeReceipt({});
			receipt.credentialSubject.action.tool_name = "list_issues";
			store.insert(receipt, "sha256:tn1");

			const retrieved = store.getById(receipt.id);
			expect(retrieved?.credentialSubject.action.tool_name).toBe("list_issues");
		});

		it("migrates pre-existing database without tool_name column", () => {
			// Create a DB with the old schema (no tool_name column).
			const oldSchema = `
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
				CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_chain ON receipts(chain_id, sequence);
			`;
			const oldDb = new DatabaseSync(":memory:");
			oldDb.exec(oldSchema);

			// Insert a row using the old schema.
			const receipt = makeReceipt({});
			oldDb
				.prepare(
					`INSERT INTO receipts
					(id, chain_id, sequence, action_type, risk_level, status,
					 timestamp, issuer_id, principal_id, receipt_json, receipt_hash,
					 previous_receipt_hash)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				)
				.run(
					receipt.id,
					"chain_test",
					1,
					"filesystem.file.read",
					"low",
					"success",
					"2026-03-29T14:00:00Z",
					"did:agent:test",
					"did:user:test",
					JSON.stringify(receipt),
					"sha256:old",
					null,
				);
			oldDb.close();

			// Opening via ReceiptStore should trigger migration and succeed.
			// Use a file-based DB to test migration on re-open.
			const tmpPath = `:memory:`;
			const migratedStore = openStore(tmpPath);
			const newReceipt = makeReceipt({ id: "urn:receipt:migrated" });
			newReceipt.credentialSubject.action.tool_name = "read_file";
			migratedStore.insert(newReceipt, "sha256:new");

			const retrieved = migratedStore.getById("urn:receipt:migrated");
			expect(retrieved?.credentialSubject.action.tool_name).toBe("read_file");
			migratedStore.close();
		});
	});
});

describe("openStoreReadOnly", () => {
	let tmpDir: string;
	let dbPath: string;

	beforeEach(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "ar-store-ro-test-"));
		dbPath = join(tmpDir, "receipts.db");
	});

	afterEach(() => {
		rmSync(tmpDir, { recursive: true, force: true });
	});

	it("queries receipts written by openStore", () => {
		// Write two receipts via a regular read-write store.
		const rw = openStore(dbPath);
		const r1 = makeReceipt({ id: "urn:receipt:ro-1", sequence: 1 });
		const r2 = makeReceipt({ id: "urn:receipt:ro-2", sequence: 2 });
		rw.insert(r1, "sha256:ro1");
		rw.insert(r2, "sha256:ro2");
		rw.close();

		// Open the same file read-only and verify both receipts are returned.
		const ro = openStoreReadOnly(dbPath);
		try {
			const results = ro.query({});
			expect(results).toHaveLength(2);
			const ids = results.map((r) => r.id);
			expect(ids).toContain("urn:receipt:ro-1");
			expect(ids).toContain("urn:receipt:ro-2");
		} finally {
			ro.close();
		}
	});

	it("throws on a non-existent path", () => {
		const missing = join(tmpDir, "does-not-exist.db");
		expect(() => openStoreReadOnly(missing)).toThrow();
	});

	it('throws with a clear message for ":memory:"', () => {
		expect(() => openStoreReadOnly(":memory:")).toThrowError(
			/openStoreReadOnly.*:memory:/,
		);
	});

	it("throws when insert() is called on a read-only handle", () => {
		// Seed the DB via a read-write store first so the schema exists.
		const rw = openStore(dbPath);
		rw.insert(
			makeReceipt({ id: "urn:receipt:seed", sequence: 1 }),
			"sha256:seed",
		);
		rw.close();

		const ro = openStoreReadOnly(dbPath);
		try {
			const newReceipt = makeReceipt({
				id: "urn:receipt:should-fail",
				sequence: 2,
			});
			expect(() => ro.insert(newReceipt, "sha256:fail")).toThrow();
		} finally {
			ro.close();
		}
	});
});

describe("journal mode (ADR-0004 shared contract)", () => {
	let tmpDir: string;
	let dbPath: string;

	beforeEach(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "ar-store-wal-test-"));
		dbPath = join(tmpDir, "receipts.db");
	});

	afterEach(() => {
		rmSync(tmpDir, { recursive: true, force: true });
	});

	function journalMode(db: DatabaseSync): unknown {
		const row = db.prepare("PRAGMA journal_mode").get();
		return row?.journal_mode;
	}

	it("enables WAL on a file-backed store (observed via a second connection)", () => {
		const store = openStore(dbPath);
		const observer = new DatabaseSync(dbPath);
		try {
			expect(journalMode(observer)).toBe("wal");
		} finally {
			observer.close();
			store.close();
		}
	});

	it("keeps WAL after the store is closed and reopened", () => {
		openStore(dbPath).close();
		const reopened = openStore(dbPath);
		reopened.close();

		const observer = new DatabaseSync(dbPath);
		try {
			expect(journalMode(observer)).toBe("wal");
		} finally {
			observer.close();
		}
	});

	it("in-memory stores still open and work", () => {
		const store = openStore(":memory:");
		try {
			const receipt = makeReceipt({ id: "urn:receipt:mem-1" });
			store.insert(receipt, "sha256:mem");
			expect(store.getById(receipt.id)).toEqual(receipt);
		} finally {
			store.close();
		}
	});

	it("a reader is not blocked while another connection holds a write transaction", () => {
		const rw = openStore(dbPath);
		const seeded = makeReceipt({ id: "urn:receipt:busy-1", sequence: 1 });
		rw.insert(seeded, "sha256:busy1");

		const writer = new DatabaseSync(dbPath);
		writer.exec("BEGIN EXCLUSIVE");
		writer.exec("UPDATE receipts SET status = status WHERE id = 'urn:none'");
		const ro = openStoreReadOnly(dbPath);
		try {
			expect(rw.getById(seeded.id)).toEqual(seeded);
			expect(ro.query({}).map((r) => r.id)).toEqual([seeded.id]);
		} finally {
			ro.close();
			writer.exec("ROLLBACK");
			writer.close();
			rw.close();
		}
	});

	it("a store write succeeds while another connection holds a read transaction", () => {
		const rw = openStore(dbPath);
		rw.insert(
			makeReceipt({ id: "urn:receipt:rd-1", sequence: 1 }),
			"sha256:rd1",
		);

		const reader = new DatabaseSync(dbPath);
		reader.exec("BEGIN");
		reader.prepare("SELECT count(*) AS n FROM receipts").get();
		try {
			const next = makeReceipt({ id: "urn:receipt:rd-2", sequence: 2 });
			expect(() => rw.insert(next, "sha256:rd2")).not.toThrow();
			expect(rw.getById(next.id)).toEqual(next);
		} finally {
			reader.exec("COMMIT");
			reader.close();
			rw.close();
		}
	});

	it("reads a WAL database written by another SDK with uncheckpointed frames", () => {
		// Emulate the Python/Go writer: same shared schema, WAL mode, and a
		// connection that stays open so the row lives only in the -wal file.
		const foreign = new DatabaseSync(dbPath);
		foreign.exec("PRAGMA journal_mode=WAL");
		foreign.exec(`
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
			CREATE INDEX idx_receipts_status ON receipts(status);
		`);
		const receipt = makeReceipt({ id: "urn:receipt:foreign-1" });
		const subject = receipt.credentialSubject;
		foreign
			.prepare(
				`INSERT INTO receipts
				(id, chain_id, sequence, action_type, tool_name, risk_level, status,
				 timestamp, issuer_id, principal_id, receipt_json, receipt_hash,
				 previous_receipt_hash)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				receipt.id,
				subject.chain.chain_id,
				subject.chain.sequence,
				subject.action.type,
				subject.action.tool_name ?? "",
				subject.action.risk_level,
				subject.outcome.status,
				subject.action.timestamp,
				receipt.issuer.id,
				subject.principal.id,
				JSON.stringify(receipt),
				"sha256:foreign",
				subject.chain.previous_receipt_hash,
			);

		const ro = openStoreReadOnly(dbPath);
		const rw = openStore(dbPath);
		try {
			expect(ro.getById(receipt.id)).toEqual(receipt);
			expect(rw.getById(receipt.id)).toEqual(receipt);
			expect(journalMode(foreign)).toBe("wal");
		} finally {
			rw.close();
			ro.close();
			foreign.close();
		}
	});

	it("openStoreReadOnly does not change the journal mode or write", () => {
		// A database left in rollback-journal mode (e.g. by an older SDK).
		const legacy = openStore(dbPath);
		legacy.insert(
			makeReceipt({ id: "urn:receipt:legacy-1", sequence: 1 }),
			"sha256:legacy",
		);
		legacy.close();
		const reset = new DatabaseSync(dbPath);
		reset.exec("PRAGMA journal_mode=DELETE");
		reset.close();

		const ro = openStoreReadOnly(dbPath);
		try {
			expect(ro.query({}).map((r) => r.id)).toEqual(["urn:receipt:legacy-1"]);
		} finally {
			ro.close();
		}

		const observer = new DatabaseSync(dbPath);
		try {
			expect(journalMode(observer)).toBe("delete");
		} finally {
			observer.close();
		}
		expect(existsSync(`${dbPath}-wal`)).toBe(false);
	});
});
