import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { type Document, didFromPublicKey, resolveDid } from "./did.js";

// Cross-SDK did:key resolution vectors (ADR-0007, issue #956). Asserts that
// the TypeScript SDK reproduces the pinned `did` and `did_document` values
// byte-for-byte, matching the Go and Python SDKs.

const vectorsPath = join(
	import.meta.dirname,
	"../../../spec/test-vectors/did-key/vectors.json",
);

interface DIDKeyVector {
	name: string;
	source: string;
	public_key_hex: string;
	did: string;
	did_document: Document;
}

interface DIDKeyVectorFile {
	vectors: DIDKeyVector[];
}

const vectors: DIDKeyVectorFile = JSON.parse(
	readFileSync(vectorsPath, "utf-8"),
);

function fromHex(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return bytes;
}

describe("did:key vectors", () => {
	it("has vectors to test", () => {
		expect(vectors.vectors.length).toBeGreaterThan(0);
	});

	for (const vector of vectors.vectors) {
		it(vector.name, () => {
			const pub = fromHex(vector.public_key_hex);

			expect(didFromPublicKey(pub)).toBe(vector.did);
			expect(resolveDid(vector.did)).toEqual(vector.did_document);
		});
	}
});
