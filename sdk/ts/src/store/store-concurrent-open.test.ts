import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Worker } from "node:worker_threads";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openStore } from "./store.js";

// Simultaneous first opens of a fresh db race on the WAL switch and schema
// writes, where SQLite can return SQLITE_BUSY without invoking the busy
// handler. The store retries within a deadline (ADR-0004).
const RACERS = 4;
const ROUNDS = 5;

// Each racer waits on a shared flag, then performs the same first-open
// sequence as the store against the same fresh file. Racer errors are
// ignored: only the store's open is under test.
const RACER_SOURCE = `
const { workerData, parentPort } = require("node:worker_threads");
const { DatabaseSync } = require("node:sqlite");
const go = new Int32Array(workerData.go);
parentPort.postMessage("ready");
Atomics.wait(go, 0, 0, 5000);
try {
	const db = new DatabaseSync(workerData.dbPath);
	db.exec("PRAGMA busy_timeout = 5000");
	db.exec("PRAGMA journal_mode = WAL");
	db.exec("CREATE TABLE IF NOT EXISTS race_probe (x INTEGER)");
	db.close();
} catch {}
`;

function journalMode(path: string): string {
	const db = new DatabaseSync(path);
	try {
		const mode = db.prepare("PRAGMA journal_mode").get()?.journal_mode;
		return typeof mode === "string" ? mode.toLowerCase() : String(mode);
	} finally {
		db.close();
	}
}

describe("simultaneous first opens", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "ar-store-race-test-"));
	});

	afterEach(() => {
		rmSync(tmpDir, { recursive: true, force: true });
	});

	it("openStore succeeds while other connections initialise the same db", async () => {
		for (let round = 0; round < ROUNDS; round++) {
			const dbPath = join(tmpDir, `receipts-${round}.db`);
			const goBuf = new SharedArrayBuffer(4);
			const workers = Array.from(
				{ length: RACERS },
				() =>
					new Worker(RACER_SOURCE, {
						eval: true,
						workerData: { dbPath, go: goBuf },
					}),
			);
			const exits = workers.map(
				(w) =>
					new Promise<number>((resolve) => {
						w.once("exit", resolve);
					}),
			);
			await Promise.all(
				workers.map(
					(w) =>
						new Promise<void>((resolve, reject) => {
							w.once("message", () => resolve());
							w.once("error", reject);
						}),
				),
			);

			const go = new Int32Array(goBuf);
			Atomics.store(go, 0, 1);
			Atomics.notify(go, 0);
			try {
				openStore(dbPath).close();
			} finally {
				await Promise.all(exits);
			}
			expect(journalMode(dbPath)).toBe("wal");
		}
	});
});
