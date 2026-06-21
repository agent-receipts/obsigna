import { describe, expect, it } from "vitest";
import {
	type DisclosureEnvelope,
	decryptDisclosure,
	decryptResponse,
	encryptDisclosure,
	encryptDisclosureWithSeed,
	encryptResponse,
	encryptResponseWithSeed,
	generateForensicKeyPair,
} from "./disclosure.js";
import { canonicalize } from "./hash.js";

// RFC 7748 §6.1 well-known X25519 test keys. Published IETF test vectors — not real secrets.
// Verified: X25519(alicePriv, basepoint) === alicePub.
const ALICE_PUB_HEX =
	"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"; // skipcq: SCM-001
const ALICE_PRIV_HEX =
	"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"; // skipcq: SCM-001
const BOB_PUB_HEX =
	"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const BOB_PRIV_HEX =
	"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"; // skipcq: SCM-001

// ikmE values from spec/test-vectors/disclosure-envelope/vectors.json
const VECTOR1_IKME_HEX =
	"7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234";
const VECTOR2_IKME_HEX =
	"909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b";

function fromHex(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
	}
	return bytes;
}

describe("generateForensicKeyPair", () => {
	it("produces 32-byte keys that differ from each other", async () => {
		const kp = await generateForensicKeyPair();
		expect(kp.publicKey).toHaveLength(32);
		expect(kp.privateKey).toHaveLength(32);
		expect(kp.publicKey).not.toEqual(kp.privateKey);
	});

	it("round-trips encrypt/decrypt with a fresh key pair", async () => {
		const kp = await generateForensicKeyPair();
		const params = { tool: "read_file", path: "/tmp/test.txt" };
		const env = await encryptDisclosure(params, kp.publicKey, "sha256:test");
		const got = await decryptDisclosure(env, kp.privateKey);
		expect(got.tool).toBe("read_file");
		expect(got.path).toBe("/tmp/test.txt");
	});
});

describe("encryptDisclosure", () => {
	it("produces a valid v1 envelope shape", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const env = await encryptDisclosure(
			{ command: 'echo "build complete"' },
			alicePub,
			"did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQUQUaHL9XJ7Z5W#enc-1",
		);

		expect(env.v).toBe("1");
		expect(env.alg).toBe("hpke-x25519-hkdf-sha256-aes-256-gcm");
		expect(env.recipients).toHaveLength(1);
		// enc: 43 chars = unpadded base64url of 32 bytes
		expect(env.recipients[0].enc).toHaveLength(43);
		expect(env.recipients[0].enc).not.toMatch(/[+/=]/);
		expect(env.ct).not.toMatch(/[+/=]/);
		expect(env.ct.length).toBeGreaterThanOrEqual(24);
		// No nonce field — v1 is single-shot
		expect(JSON.stringify(env)).not.toContain('"nonce"');
	});

	it("round-trips with Alice's RFC 7748 key pair", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const alicePriv = fromHex(ALICE_PRIV_HEX);
		const params = { command: 'echo "build complete"' };
		const env = await encryptDisclosure(params, alicePub, "test-kid");
		const got = await decryptDisclosure(env, alicePriv);
		expect(got.command).toBe('echo "build complete"');
	});

	it("JCS-canonicalizes plaintext before encryption", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const alicePriv = fromHex(ALICE_PRIV_HEX);
		const params = { z_last: "last", a_first: "first", m_mid: "middle" };
		const env = await encryptDisclosure(params, alicePub, "test-kid");
		const got = await decryptDisclosure(env, alicePriv);
		expect(canonicalize(got)).toBe(canonicalize(params));
	});

	it("rejects short recipient public key", async () => {
		await expect(
			encryptDisclosure(
				{} as Record<string, unknown>,
				new Uint8Array(16),
				"kid",
			),
		).rejects.toThrow("32 bytes");
	});

	it("rejects empty kid", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		await expect(
			encryptDisclosure({} as Record<string, unknown>, alicePub, ""),
		).rejects.toThrow("kid");
	});
});

describe("decryptDisclosure", () => {
	it("rejects null envelope", async () => {
		await expect(
			decryptDisclosure(
				null as unknown as DisclosureEnvelope,
				new Uint8Array(32),
			),
		).rejects.toThrow();
	});

	it("rejects wrong version", async () => {
		const env = {
			v: "2",
			alg: "hpke-x25519-hkdf-sha256-aes-256-gcm",
			recipients: [{ kid: "k", enc: "A".repeat(43) }],
			ct: "B".repeat(24),
		} as unknown as DisclosureEnvelope;
		await expect(decryptDisclosure(env, new Uint8Array(32))).rejects.toThrow(
			"unsupported envelope version",
		);
	});

	it("rejects wrong alg", async () => {
		const env = {
			v: "1",
			alg: "hpke-x25519-chacha20poly1305",
			recipients: [{ kid: "k", enc: "A".repeat(43) }],
			ct: "B".repeat(24),
		} as unknown as DisclosureEnvelope;
		await expect(decryptDisclosure(env, new Uint8Array(32))).rejects.toThrow(
			"unsupported algorithm",
		);
	});

	it("rejects zero recipients", async () => {
		const env = {
			v: "1",
			alg: "hpke-x25519-hkdf-sha256-aes-256-gcm",
			recipients: [],
			ct: "B".repeat(24),
		} as unknown as DisclosureEnvelope;
		await expect(decryptDisclosure(env, new Uint8Array(32))).rejects.toThrow(
			"exactly 1 recipient",
		);
	});

	it("rejects short private key", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const env = await encryptDisclosure({ k: "v" }, alicePub, "kid");
		await expect(decryptDisclosure(env, new Uint8Array(16))).rejects.toThrow(
			"32 bytes",
		);
	});

	it("rejects wrong private key (authentication failure)", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const bobPriv = fromHex(BOB_PRIV_HEX);
		const env = await encryptDisclosure({ x: 1 }, alicePub, "kid");
		await expect(decryptDisclosure(env, bobPriv)).rejects.toThrow();
	});

	it("rejects padded or standard-base64 characters in enc", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const alicePriv = fromHex(ALICE_PRIV_HEX);
		const env = await encryptDisclosure({ k: "v" }, alicePub, "kid");
		// Splice in a padded enc (= character)
		const badEnc = `${env.recipients[0].enc.slice(0, 42)}=`;
		const badEnvPadded = {
			...env,
			recipients: [{ kid: "kid", enc: badEnc }],
		} as unknown as DisclosureEnvelope;
		await expect(decryptDisclosure(badEnvPadded, alicePriv)).rejects.toThrow(
			"invalid base64url",
		);
		// Splice in a standard-base64 character (+)
		const badEnvPlus = {
			...env,
			recipients: [{ kid: "kid", enc: `${"A".repeat(42)}+` }],
		} as unknown as DisclosureEnvelope;
		await expect(decryptDisclosure(badEnvPlus, alicePriv)).rejects.toThrow(
			"invalid base64url",
		);
	});

	it("rejects enc with invalid base64url length (len % 4 === 1)", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const alicePriv = fromHex(ALICE_PRIV_HEX);
		const env = await encryptDisclosure({ k: "v" }, alicePub, "kid");
		// 41 chars: 41 % 4 === 1 — never valid in base64
		const badEnv = {
			...env,
			recipients: [{ kid: "kid", enc: "A".repeat(41) }],
		} as unknown as DisclosureEnvelope;
		await expect(decryptDisclosure(badEnv, alicePriv)).rejects.toThrow(
			"invalid base64url",
		);
	});

	it("rejects ct shorter than 24 characters", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const alicePriv = fromHex(ALICE_PRIV_HEX);
		const env = await encryptDisclosure({ k: "v" }, alicePub, "kid");
		const badEnv = {
			...env,
			ct: "A".repeat(23),
		} as unknown as DisclosureEnvelope;
		await expect(decryptDisclosure(badEnv, alicePriv)).rejects.toThrow(
			"ct is too short",
		);
	});

	it("JSON round-trips cleanly", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const alicePriv = fromHex(ALICE_PRIV_HEX);
		const env = await encryptDisclosure({ key: "value" }, alicePub, "test-kid");
		const parsed: DisclosureEnvelope = JSON.parse(JSON.stringify(env));
		const got = await decryptDisclosure(parsed, alicePriv);
		expect(got.key).toBe("value");
	});
});

describe("envelope JCS canonical shape", () => {
	it("sorts top-level keys as [alg, ct, recipients, v] and recipient keys as [enc, kid]", () => {
		const enc = "A".repeat(43);
		const ct = "B".repeat(24);
		const env: DisclosureEnvelope = {
			v: "1",
			alg: "hpke-x25519-hkdf-sha256-aes-256-gcm",
			recipients: [{ kid: "did:key:test#enc-1", enc }],
			ct,
		};
		const wantJCS = `{"alg":"hpke-x25519-hkdf-sha256-aes-256-gcm","ct":"${ct}","recipients":[{"enc":"${enc}","kid":"did:key:test#enc-1"}],"v":"1"}`;
		expect(canonicalize(env)).toBe(wantJCS);
	});
});

describe("encryptDisclosureWithSeed input validation", () => {
	it("rejects ikmE of wrong length", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const ikmE31 = new Uint8Array(31);
		const ikmE33 = new Uint8Array(33);
		const ikmE0 = new Uint8Array(0);
		await expect(
			encryptDisclosureWithSeed({}, alicePub, "kid", ikmE31),
		).rejects.toThrow("32 bytes");
		await expect(
			encryptDisclosureWithSeed({}, alicePub, "kid", ikmE33),
		).rejects.toThrow("32 bytes");
		await expect(
			encryptDisclosureWithSeed({}, alicePub, "kid", ikmE0),
		).rejects.toThrow("32 bytes");
	});
});

describe("encryptResponse / decryptResponse", () => {
	it("produces a valid v1 envelope shape (mirrors encryptDisclosure)", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const env = await encryptResponse(
			{ content: "file contents here", exit_code: 0 },
			alicePub,
			"did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQUQUaHL9XJ7Z5W#enc-1",
		);

		expect(env.v).toBe("1");
		expect(env.alg).toBe("hpke-x25519-hkdf-sha256-aes-256-gcm");
		expect(env.recipients).toHaveLength(1);
		expect(env.recipients[0].enc).toHaveLength(43);
		expect(env.recipients[0].enc).not.toMatch(/[+/=]/);
		expect(env.ct).not.toMatch(/[+/=]/);
		expect(env.ct.length).toBeGreaterThanOrEqual(24);
		expect(JSON.stringify(env)).not.toContain('"nonce"');
	});

	it("round-trips with Alice's RFC 7748 key pair", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const alicePriv = fromHex(ALICE_PRIV_HEX);
		const response = { content: "hello world", exit_code: 0 };
		const env = await encryptResponse(response, alicePub, "test-kid");
		const got = await decryptResponse(env, alicePriv);
		expect(got.content).toBe("hello world");
		expect(got.exit_code).toBe(0);
	});

	it("JCS-canonicalizes response before encryption", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const alicePriv = fromHex(ALICE_PRIV_HEX);
		const response = { z_last: "last", a_first: "first", m_mid: "middle" };
		const env = await encryptResponse(response, alicePub, "test-kid");
		const got = await decryptResponse(env, alicePriv);
		expect(canonicalize(got)).toBe(canonicalize(response));
	});

	it("rejects short recipient public key", async () => {
		const body: Record<string, unknown> = {};
		await expect(
			encryptResponse(body, new Uint8Array(16), "kid"),
		).rejects.toThrow("32 bytes");
	});

	it("rejects empty kid", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const body: Record<string, unknown> = {};
		await expect(encryptResponse(body, alicePub, "")).rejects.toThrow("kid");
	});

	it("rejects wrong private key (authentication failure)", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const bobPriv = fromHex(BOB_PRIV_HEX);
		const env = await encryptResponse({ x: 1 }, alicePub, "kid");
		await expect(decryptResponse(env, bobPriv)).rejects.toThrow();
	});

	it("JSON round-trips cleanly", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const alicePriv = fromHex(ALICE_PRIV_HEX);
		const env = await encryptResponse({ output: "ok" }, alicePub, "test-kid");
		const parsed: DisclosureEnvelope = JSON.parse(JSON.stringify(env));
		const got = await decryptResponse(parsed, alicePriv);
		expect(got.output).toBe("ok");
	});

	it("encryptResponseWithSeed rejects ikmE of wrong length", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const ikmE31 = new Uint8Array(31);
		await expect(
			encryptResponseWithSeed({}, alicePub, "kid", ikmE31),
		).rejects.toThrow("32 bytes");
	});

	it("uses the same HPKE primitive as encryptDisclosure (cross-field interop)", async () => {
		// encryptResponse and encryptDisclosure are the same primitive —
		// given identical inputs they MUST produce the same ciphertext.
		const alicePub = fromHex(ALICE_PUB_HEX);
		const alicePriv = fromHex(ALICE_PRIV_HEX);
		const ikmE = fromHex(VECTOR1_IKME_HEX);
		const payload = { command: 'echo "build complete"' };
		const kid =
			"did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQUQUaHL9XJ7Z5W#enc-1";

		const envParam = await encryptDisclosureWithSeed(
			payload,
			alicePub,
			kid,
			ikmE,
		);
		const envResp = await encryptResponseWithSeed(payload, alicePub, kid, ikmE);

		// Same primitive → same envelope bytes.
		expect(envResp.ct).toBe(envParam.ct);
		expect(envResp.recipients[0].enc).toBe(envParam.recipients[0].enc);

		// decryptResponse recovers the same plaintext that decryptDisclosure does.
		const got = await decryptResponse(envResp, alicePriv);
		expect(got.command).toBe('echo "build complete"');
	});
});

describe("deterministic spec vectors", () => {
	it("vector-1: enc matches RFC 9180 §A.1.1 pkEm and JCS matches Go SDK", async () => {
		const alicePub = fromHex(ALICE_PUB_HEX);
		const alicePriv = fromHex(ALICE_PRIV_HEX);
		const ikmE = fromHex(VECTOR1_IKME_HEX);
		const params = { command: 'echo "build complete"' };
		const kid =
			"did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQUQUaHL9XJ7Z5W#enc-1";

		const env = await encryptDisclosureWithSeed(params, alicePub, kid, ikmE);

		// enc must match RFC 9180 §A.1.1 pkEm = 37fda3...
		const wantEnc = "N_2jVnvb1ijohmjDyNfpfR0SU7bU6m1EwVD3QfG_RDE";
		expect(env.recipients[0].enc).toBe(wantEnc);

		const wantCT =
			"YGn3i4NpiZxHjeZVggTP8lTxb0ZVdLl-2HjW31qsvo28PjQ_Lt_UQgAMidEXjzwhJPHM7OM";
		expect(env.ct).toBe(wantCT);

		const wantJCS = `{"alg":"hpke-x25519-hkdf-sha256-aes-256-gcm","ct":"${wantCT}","recipients":[{"enc":"${wantEnc}","kid":"${kid}"}],"v":"1"}`;
		expect(canonicalize(env)).toBe(wantJCS);

		expect(canonicalize(params)).toBe(
			'{"command":"echo \\"build complete\\""}',
		);

		const got = await decryptDisclosure(env, alicePriv);
		expect(got.command).toBe('echo "build complete"');
	});

	it("vector-2: enc and JCS match pinned Go SDK values", async () => {
		const bobPub = fromHex(BOB_PUB_HEX);
		const bobPriv = fromHex(BOB_PRIV_HEX);
		const ikmE = fromHex(VECTOR2_IKME_HEX);
		const params = {
			method: "POST",
			headers: {
				"content-type": "application/json",
				"x-request-id": "abc-123",
			},
			body: { user: "otto", delta: 42 },
		};
		const kid =
			"sha256:8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";

		const env = await encryptDisclosureWithSeed(params, bobPub, kid, ikmE);

		const wantEnc = "GvoI097AR6ZDiFFj8RgEdvp921TGqAKeoz-VeWvyrEo";
		expect(env.recipients[0].enc).toBe(wantEnc);

		const wantCT =
			"vJG1bfcwNTnyL7gqfzkIg8oDl08Rd0z2kp-HVcRypJDrYdPBwvHWbIwdhCXuYB4mKANMmKejzrsDHvaOnFAAHxVzB-f57sljHW5aDsb4kp5mhtM2SIAQwUj6VlVonllEdQquRKOl3hjbXEOwjQeXQUxvI7avsiWuk5z41na_Xx6vVJd96lb-59YV";
		expect(env.ct).toBe(wantCT);

		expect(canonicalize(params)).toBe(
			'{"body":{"delta":42,"user":"otto"},"headers":{"content-type":"application/json","x-request-id":"abc-123"},"method":"POST"}',
		);

		const got = await decryptDisclosure(env, bobPriv);
		expect(got.method).toBe("POST");
	});
});
