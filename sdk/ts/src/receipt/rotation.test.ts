import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { verifyChain } from "./chain.js";
import { createReceipt } from "./create.js";
import { hashReceipt } from "./hash.js";
import {
	ed25519RawToPem,
	keyFingerprint,
	pemToEd25519Raw,
	verifyRotationEvent,
} from "./rotation.js";
import { generateKeyPair, signReceipt } from "./signing.js";
import type { AgentReceipt, KeyRotation } from "./types.js";

// RFC 8032 §7.1 well-known test public keys (raw 32-byte Ed25519), reused by
// the spec rotation-event vector. TEST 2 is the outgoing key (signs the
// rotation); TEST 3 is the incoming key.
const RFC8032_TEST2_PUB_HEX =
	"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const RFC8032_TEST3_PUB_HEX =
	"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";

const here = dirname(fileURLToPath(import.meta.url));
const vectorPath = join(
	here,
	"..",
	"..",
	"..",
	"..",
	"spec",
	"test-vectors",
	"rotation-event",
	"example.json",
);

function pemFromHex(hex: string): string {
	return ed25519RawToPem(Buffer.from(hex, "hex"));
}

function loadVector(): AgentReceipt {
	return JSON.parse(readFileSync(vectorPath, "utf-8")) as AgentReceipt;
}

describe("key rotation", () => {
	it("verifies the spec rotation-event vector under the outgoing key", () => {
		const vector = loadVector();
		expect(vector.credentialSubject.keyRotation?.event_type).toBe(
			"key_rotated",
		);
		const outgoingPem = pemFromHex(RFC8032_TEST2_PUB_HEX);
		const cv = verifyChain([vector], outgoingPem);
		expect(cv.valid).toBe(true);
	});

	it("matches the published canonical-body hash", () => {
		const got = hashReceipt(loadVector());
		expect(got).toBe(
			"sha256:6983c9bd6fb24e844b90f7616315a914fdedc5fef8126e11d46149ba2f320457",
		);
	});

	it("binds the incoming key from the rotation event", () => {
		const vector = loadVector();
		const outgoingPem = pemFromHex(RFC8032_TEST2_PUB_HEX);
		const kr = vector.credentialSubject.keyRotation as KeyRotation;
		const rot = verifyRotationEvent(outgoingPem, kr);
		expect(rot.ok).toBe(true);
		if (rot.ok) {
			expect(rot.newKeyPem).toBe(pemFromHex(RFC8032_TEST3_PUB_HEX));
		}
	});

	it("rejects malformed rotation events", () => {
		const outgoingPem = pemFromHex(RFC8032_TEST2_PUB_HEX);
		const base = () =>
			structuredClone(
				loadVector().credentialSubject.keyRotation,
			) as KeyRotation;
		const zeroFp = `sha256:${"0".repeat(64)}`;
		const cases: Array<[string, (k: KeyRotation) => void, string]> = [
			[
				"bad event_type",
				(k) => ((k as { event_type: string }).event_type = "rotated"),
				"event_type",
			],
			[
				"bad signed_with",
				(k) => ((k as { signed_with: string }).signed_with = "new"),
				"signed_with",
			],
			[
				"unsupported old_algorithm",
				(k) => (k.old_algorithm = "ml-dsa"),
				"old_algorithm",
			],
			[
				"unsupported new_algorithm",
				(k) => (k.new_algorithm = "ml-dsa"),
				"new_algorithm",
			],
			[
				"old fingerprint mismatch",
				(k) => (k.old_key_fingerprint = zeroFp),
				"old_key_fingerprint",
			],
			[
				"new fingerprint mismatch",
				(k) => (k.new_key_fingerprint = zeroFp),
				"new_key_fingerprint",
			],
			[
				"new_public_key not multibase",
				(k) => (k.new_public_key = `z${k.new_public_key.slice(1)}`),
				"new_public_key",
			],
			[
				"new_public_key wrong length",
				(k) => (k.new_public_key = "uAAAA"),
				"new_public_key",
			],
		];
		for (const [, mutate, want] of cases) {
			const kr = base();
			mutate(kr);
			const rot = verifyRotationEvent(outgoingPem, kr);
			expect(rot.ok).toBe(false);
			if (!rot.ok) expect(rot.error).toContain(want);
		}
	});

	it("adopts the incoming key for receipts after a rotation", () => {
		const outKP = generateKeyPair();
		const inKP = generateKeyPair();
		const inRaw = pemToEd25519Raw(inKP.publicKey);

		const rot = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:test" },
			action: { type: "agent.key.rotate", risk_level: "high" },
			outcome: { status: "success" },
			chain: {
				sequence: 1,
				previous_receipt_hash: null,
				chain_id: "chain_rot",
			},
		});
		rot.credentialSubject.keyRotation = {
			event_type: "key_rotated",
			new_public_key: `u${inRaw.toString("base64url")}`,
			old_key_fingerprint: keyFingerprint(pemToEd25519Raw(outKP.publicKey)),
			new_key_fingerprint: keyFingerprint(inRaw),
			old_algorithm: "ed25519",
			new_algorithm: "ed25519",
			signed_with: "old",
		};
		const signed0 = signReceipt(rot, outKP.privateKey, "did:agent:test#key-1");
		const h0 = hashReceipt(signed0);

		const r1 = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:test" },
			action: { type: "filesystem.file.read", risk_level: "low" },
			outcome: { status: "success" },
			chain: { sequence: 2, previous_receipt_hash: h0, chain_id: "chain_rot" },
		});
		const signed1 = signReceipt(r1, inKP.privateKey, "did:agent:test#key-1");

		// Verified under only the outgoing genesis key — succeeds because the
		// rotation hands the key over.
		expect(verifyChain([signed0, signed1], outKP.publicKey).valid).toBe(true);

		// Without the rotation object, the successor signed by the incoming key
		// fails under the outgoing key alone. Omit keyRotation entirely (an
		// explicit undefined property would trip the canonicaliser).
		const { keyRotation: _omit, ...csNoRot } = rot.credentialSubject;
		const noRot = signReceipt(
			{ ...rot, credentialSubject: csNoRot },
			outKP.privateKey,
			"did:agent:test#key-1",
		);
		const h0b = hashReceipt(noRot);
		const r1b = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:test" },
			action: { type: "filesystem.file.read", risk_level: "low" },
			outcome: { status: "success" },
			chain: { sequence: 2, previous_receipt_hash: h0b, chain_id: "chain_rot" },
		});
		const noRot1 = signReceipt(r1b, inKP.privateKey, "did:agent:test#key-1");
		expect(verifyChain([noRot, noRot1], outKP.publicKey).valid).toBe(false);
	});
});
