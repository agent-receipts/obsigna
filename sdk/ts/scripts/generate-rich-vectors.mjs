#!/usr/bin/env node
// Sign the rich receipt from cross-sdk-tests/py_vectors.json with the
// TypeScript SDK and write cross-sdk-tests/ts_rich_vectors.json.
//
// Ed25519 signs the canonical receipt, not the proof, so this output must
// carry the same proofValue as the Python SDK's signingRich entry. The
// cross-language tests check that equality.
//
// Usage (after a build, which provides dist/):
//   pnpm build && node scripts/generate-rich-vectors.mjs

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..");
const { signReceipt } = await import("../dist/receipt/signing.js");

const tsFixture = JSON.parse(
	readFileSync(
		join(repoRoot, "sdk/py/tests/fixtures/ts_vectors.json"),
		"utf-8",
	),
);
const py = JSON.parse(
	readFileSync(join(repoRoot, "cross-sdk-tests/py_vectors.json"), "utf-8"),
);

const { keys } = tsFixture;
const { verificationMethod } = tsFixture.signing;
const unsigned = py.signingRich.unsigned;
const signed = signReceipt(unsigned, keys.privateKey, verificationMethod);

const out = { keys, unsigned, signed, verificationMethod };

writeFileSync(
	join(repoRoot, "cross-sdk-tests/ts_rich_vectors.json"),
	`${JSON.stringify(out, null, 2)}\n`,
);
console.log("wrote cross-sdk-tests/ts_rich_vectors.json");
