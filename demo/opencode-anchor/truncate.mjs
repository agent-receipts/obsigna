// Tail-truncation tool for the demo's attack step: snapshot the live receipt
// store into a self-contained copy, then delete every receipt past --keep.
//
// Usage: node --experimental-sqlite truncate.mjs <srcDb> <dstDb> <chainId> <keep>
//
// VACUUM INTO folds the WAL into the snapshot, so the copy is complete whatever
// journal mode the daemon used. This stands in for an attacker with write access
// to the store (a compromised host) — note it never touches the anchor, which
// lives in a UID the attacker cannot write.

import { DatabaseSync } from "node:sqlite";

const [src, dst, chain, keepArg] = process.argv.slice(2);
const keep = Number(keepArg);
if (!src || !dst || !chain || Number.isNaN(keep)) {
	console.error("usage: truncate.mjs <srcDb> <dstDb> <chainId> <keep>");
	process.exit(2);
}

const source = new DatabaseSync(src);
source.exec(`VACUUM INTO '${dst.replace(/'/g, "''")}'`);
source.close();

const db = new DatabaseSync(dst);
const count = () => db.prepare("SELECT count(*) c FROM receipts WHERE chain_id=?").get(chain).c;
const before = count();
const res = db.prepare("DELETE FROM receipts WHERE chain_id=? AND sequence>?").run(chain, keep);
const after = count();
db.close();

if (res.changes === 0) {
	console.error(`  nothing deleted — chain ${chain} has <= ${keep} receipts`);
	process.exit(1);
}
console.log(`  receipts: ${before} -> ${after}  (attacker deleted ${res.changes})`);
