import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { ZodError } from "zod";
import { agentReceiptSchema } from "../receipt/schema.js";
import type {
	AgentReceipt,
	OutcomeStatus,
	RiskLevel,
} from "../receipt/types.js";

const SCHEMA = `
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
`;

/**
 * Filters for querying receipts.
 */
export interface ReceiptQuery {
	chainId?: string;
	actionType?: string;
	riskLevel?: RiskLevel;
	status?: OutcomeStatus;
	/** Return receipts with timestamp >= after (ISO 8601). */
	after?: string;
	/** Return receipts with timestamp <= before (ISO 8601). */
	before?: string;
	/**
	 * Maximum number of results. When omitted, all matching rows are returned
	 * (no default cap is applied).
	 */
	limit?: number;
	/**
	 * Sort order for results. Default is "asc" (oldest first) to preserve
	 * historical behavior. Use "desc" to get the most recent receipts first;
	 * ties on timestamp are broken by sequence descending.
	 */
	order?: "asc" | "desc";
}

/**
 * Summary statistics for the receipt store.
 */
export interface StoreStats {
	total: number;
	chains: number;
	byRisk: { risk_level: string; count: number }[];
	byStatus: { status: string; count: number }[];
	byAction: { action_type: string; count: number }[];
}

interface ReceiptRow {
	receipt_json: string;
}

/**
 * Parse a receipt JSON string from the store, with error context.
 */
function parseReceiptJson(json: string, context: string): AgentReceipt {
	let parsed: unknown;
	try {
		parsed = JSON.parse(json);
	} catch (cause) {
		throw new Error(`Corrupt receipt in store (${context}): ${cause}`, {
			cause,
		});
	}
	try {
		return agentReceiptSchema.parse(parsed);
	} catch (cause) {
		if (cause instanceof ZodError) {
			const fields = cause.issues
				.map((i) => {
					const path = i.path.length === 0 ? "(root)" : i.path.join(".");
					return `${path}: ${i.message}`;
				})
				.join("; ");
			throw new Error(`Corrupt receipt in store (${context}): ${fields}`, {
				cause,
			});
		}
		throw cause;
	}
}

/**
 * SQLite-backed receipt store.
 */
export class ReceiptStore {
	private db: DatabaseSync;

	/**
	 * @param dbPath Path to the SQLite database file, or `":memory:"` for
	 * an in-memory database. May also be a SQLite URI (e.g. for read-only
	 * mode); in that case pass `{ skipInit: true }` to suppress schema
	 * creation and migration.
	 * @param options.skipInit When true, skip schema creation and
	 * `tool_name` migration. Used by `openStoreReadOnly`.
	 */
	constructor(dbPath: string, options?: { skipInit?: boolean }) {
		this.db = new DatabaseSync(dbPath);
		if (!options?.skipInit) {
			// Enable WAL mode and set busy timeout for concurrent access.
			this.db.exec("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;");
			this.db.exec(SCHEMA);
			this.migrateToolName();
		}
	}

	/**
	 * Add tool_name column to pre-existing databases that lack it.
	 */
	private migrateToolName(): void {
		const rows = this.db
			.prepare("PRAGMA table_info(receipts)")
			.all() as unknown[];
		const hasColumn = rows.some(
			(r) =>
				typeof r === "object" &&
				r !== null &&
				"name" in r &&
				(r as Record<string, unknown>).name === "tool_name",
		);
		if (!hasColumn) {
			this.db.exec(
				"ALTER TABLE receipts ADD COLUMN tool_name TEXT NOT NULL DEFAULT ''",
			);
		}
	}

	/**
	 * Insert a signed receipt into the store.
	 */
	insert(receipt: AgentReceipt, receiptHash: string): void {
		const subject = receipt.credentialSubject;
		this.db
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
				receiptHash,
				subject.chain.previous_receipt_hash,
			);
	}

	/**
	 * Retrieve a receipt by its id.
	 */
	getById(id: string): AgentReceipt | undefined {
		const row = this.db
			.prepare("SELECT receipt_json FROM receipts WHERE id = ?")
			.get(id) as ReceiptRow | undefined;
		return row ? parseReceiptJson(row.receipt_json, `id=${id}`) : undefined;
	}

	/**
	 * Retrieve all receipts in a chain, ordered by sequence.
	 */
	getChain(chainId: string): AgentReceipt[] {
		const rows = this.db
			.prepare(
				"SELECT receipt_json FROM receipts WHERE chain_id = ? ORDER BY sequence ASC",
			)
			.all(chainId) as unknown as ReceiptRow[];
		return rows.map((r) =>
			parseReceiptJson(r.receipt_json, `chain=${chainId}`),
		);
	}

	/**
	 * Query receipts with optional filters.
	 */
	query(filters: ReceiptQuery): AgentReceipt[] {
		const conditions: string[] = [];
		// node:sqlite binds each value using its runtime JS type (string → TEXT,
		// number → INTEGER). SQLite's LIMIT requires INTEGER; binding it as
		// TEXT silently returns zero rows. Typed as SQLInputValue[] so string
		// filter values and the numeric limit each bind as their native type.
		const params: SQLInputValue[] = [];

		if (filters.chainId !== undefined) {
			conditions.push("chain_id = ?");
			params.push(filters.chainId);
		}
		if (filters.actionType !== undefined) {
			conditions.push("action_type = ?");
			params.push(filters.actionType);
		}
		if (filters.riskLevel !== undefined) {
			conditions.push("risk_level = ?");
			params.push(filters.riskLevel);
		}
		if (filters.status !== undefined) {
			conditions.push("status = ?");
			params.push(filters.status);
		}
		if (filters.after !== undefined) {
			conditions.push("timestamp >= ?");
			params.push(filters.after);
		}
		if (filters.before !== undefined) {
			conditions.push("timestamp <= ?");
			params.push(filters.before);
		}

		const where =
			conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

		const dir = filters.order === "desc" ? "DESC" : "ASC";
		const orderClause = `ORDER BY timestamp ${dir}, sequence ${dir}, rowid ${dir}`;

		let sql: string;
		if (filters.limit !== undefined) {
			params.push(filters.limit);
			sql = `SELECT receipt_json FROM receipts ${where} ${orderClause} LIMIT ?`;
		} else {
			sql = `SELECT receipt_json FROM receipts ${where} ${orderClause}`;
		}

		const rows = this.db.prepare(sql).all(...params) as unknown as ReceiptRow[];

		return rows.map((r) => parseReceiptJson(r.receipt_json, "query"));
	}

	/**
	 * Get summary statistics for the store.
	 */
	stats(): StoreStats {
		const total = (
			this.db.prepare("SELECT COUNT(*) as count FROM receipts").get() as {
				count: number;
			}
		).count;

		const chains = (
			this.db
				.prepare("SELECT COUNT(DISTINCT chain_id) as count FROM receipts")
				.get() as { count: number }
		).count;

		const byRisk = this.db
			.prepare(
				"SELECT risk_level, COUNT(*) as count FROM receipts GROUP BY risk_level ORDER BY count DESC",
			)
			.all() as unknown as { risk_level: string; count: number }[];

		const byStatus = this.db
			.prepare(
				"SELECT status, COUNT(*) as count FROM receipts GROUP BY status ORDER BY count DESC",
			)
			.all() as unknown as { status: string; count: number }[];

		const byAction = this.db
			.prepare(
				"SELECT action_type, COUNT(*) as count FROM receipts GROUP BY action_type ORDER BY count DESC",
			)
			.all() as unknown as { action_type: string; count: number }[];

		return { total, chains, byRisk, byStatus, byAction };
	}

	/**
	 * Close the database connection.
	 */
	close(): void {
		this.db.close();
	}
}

/**
 * Open (or create) a receipt store at the given path.
 *
 * Use ":memory:" for an in-memory database.
 *
 * File-backed stores are opened in WAL mode with a 5s busy timeout, so
 * readers (including `openStoreReadOnly`) can query while a writer holds
 * a transaction. In-memory stores keep SQLite's memory journal.
 */
export function openStore(dbPath: string): ReceiptStore {
	return new ReceiptStore(dbPath);
}

/**
 * Open an existing receipt store at the given path in read-only mode.
 *
 * The database is opened with the SQLite URI `file:<abs-path>?mode=ro`,
 * so no schema creation or migration writes are performed. This makes it
 * safe to use alongside a running daemon that holds the write lock.
 *
 * The returned {@link ReceiptStore} supports all read operations
 * (query, getById, getChain, stats). Calling insert() will throw a
 * SQLite "attempt to write a readonly database" error.
 *
 * ":memory:" is rejected — a fresh in-memory database has no rows to read.
 */
export function openStoreReadOnly(dbPath: string): ReceiptStore {
	if (dbPath === ":memory:") {
		throw new Error(
			'openStoreReadOnly: ":memory:" is not supported — there is nothing to read in a fresh in-memory database',
		);
	}
	const abs = dbPath.startsWith("/") ? dbPath : `${process.cwd()}/${dbPath}`;
	const encodedPath = abs
		.split("/")
		.map((segment) => encodeURIComponent(segment))
		.join("/");
	const uri = `file:${encodedPath}?mode=ro`;
	return new ReceiptStore(uri, { skipInit: true });
}
