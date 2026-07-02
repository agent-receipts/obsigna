import { describe, expect, it } from "vitest";
import { didFromPublicKey, resolveDid } from "./did.js";

// RFC 8032 §7.1 TEST 1's public key — same key vector-1 in
// spec/test-vectors/did-key/vectors.json uses.
const PUBLIC_KEY_HEX =
	"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const EXPECTED_DID = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";

function fromHex(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return bytes;
}

describe("didFromPublicKey", () => {
	it("derives the did:key identifier from a public key", () => {
		expect(didFromPublicKey(fromHex(PUBLIC_KEY_HEX))).toBe(EXPECTED_DID);
	});

	it.each([0, 16, 31, 33, 64])("rejects a public key of length %d", (n) => {
		expect(() => didFromPublicKey(new Uint8Array(n))).toThrow(/32 bytes/);
	});
});

describe("resolveDid", () => {
	it("round trips to the expected DID Document shape", () => {
		const doc = resolveDid(EXPECTED_DID);
		const fragment = EXPECTED_DID.slice("did:key:".length);
		const vmId = `${EXPECTED_DID}#${fragment}`;

		expect(doc.id).toBe(EXPECTED_DID);
		expect(doc.verificationMethod).toHaveLength(1);
		expect(doc.verificationMethod[0]).toEqual({
			id: vmId,
			type: "Multikey",
			controller: EXPECTED_DID,
			publicKeyMultibase: fragment,
		});
		expect(doc.authentication).toEqual([vmId]);
		expect(doc.assertionMethod).toEqual([vmId]);
		expect(doc["@context"]).toEqual([
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/multikey/v1",
		]);
	});

	it.each([
		"",
		"did:key:",
		"did:web:example.com",
		`did:key:u${EXPECTED_DID.slice("did:key:z".length)}`,
		"key:z6Mktwup",
		EXPECTED_DID.slice(1),
	])("rejects %j for missing/wrong prefix", (did) => {
		expect(() => resolveDid(did)).toThrow(/prefix/);
	});

	it.each([
		"0",
		"O",
		"I",
		"l",
	])("rejects the excluded base58btc character %j", (ch) => {
		expect(() => resolveDid(`did:key:z${ch}6Mktwup`)).toThrow(/base58btc/);
	});

	it("rejects a payload that decodes to the wrong length", () => {
		const short = didKeyEncodeForTest(
			new Uint8Array([0xed, ...new Array(32).fill(0)]),
		);
		expect(() => resolveDid(`did:key:z${short}`)).toThrow(/34 bytes/);

		const long = didKeyEncodeForTest(
			new Uint8Array([0xed, 0x01, ...new Array(33).fill(0)]),
		);
		expect(() => resolveDid(`did:key:z${long}`)).toThrow(/34 bytes/);
	});

	it("rejects an unsupported multicodec", () => {
		const wrongEd = didKeyEncodeForTest(
			new Uint8Array([0xed, 0x02, ...new Array(32).fill(0)]),
		);
		expect(() => resolveDid(`did:key:z${wrongEd}`)).toThrow(/multicodec/);

		const secp256k1 = didKeyEncodeForTest(
			new Uint8Array([0x12, 0x05, ...new Array(32).fill(0)]),
		);
		expect(() => resolveDid(`did:key:z${secp256k1}`)).toThrow(/multicodec/);
	});
});

// didFromPublicKey enforces a 32-byte public key, so malformed-payload test
// fixtures (wrong length, wrong multicodec) need their own base58btc
// encoder to build a did:key string directly from an arbitrary payload.
function didKeyEncodeForTest(payload: Uint8Array): string {
	const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	let zeros = 0;
	while (zeros < payload.length && payload[zeros] === 0) zeros++;
	let n = 0n;
	for (const byte of payload) n = n * 256n + BigInt(byte);
	const digits: string[] = [];
	while (n > 0n) {
		digits.push(ALPHABET[Number(n % 58n)]);
		n /= 58n;
	}
	for (let i = 0; i < zeros; i++) digits.push(ALPHABET[0]);
	return digits.reverse().join("");
}
