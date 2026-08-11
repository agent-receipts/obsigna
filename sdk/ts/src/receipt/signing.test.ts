import { describe, expect, it } from "vitest";
import { hashReceipt } from "./hash.js";
import { generateKeyPair, signReceipt, verifyReceipt } from "./signing.js";
import type { AgentReceipt, UnsignedAgentReceipt } from "./types.js";
import { CONTEXT, CREDENTIAL_TYPE, VERSION } from "./types.js";

function makeUnsignedReceipt(): UnsignedAgentReceipt {
	return {
		"@context": CONTEXT,
		id: "urn:receipt:550e8400-e29b-41d4-a716-446655440000",
		type: CREDENTIAL_TYPE,
		version: VERSION,
		issuer: { id: "did:agent:test-agent" },
		issuanceDate: "2026-03-29T14:31:00Z",
		credentialSubject: {
			principal: { id: "did:user:test-user" },
			action: {
				id: "act_001",
				type: "filesystem.file.read",
				risk_level: "low",
				timestamp: "2026-03-29T14:31:00Z",
			},
			outcome: { status: "success" },
			chain: {
				sequence: 1,
				previous_receipt_hash: null,
				chain_id: "chain_test",
			},
		},
	};
}

describe("generateKeyPair", () => {
	it("returns PEM-encoded Ed25519 keys", () => {
		const { publicKey, privateKey } = generateKeyPair();

		expect(publicKey).toContain("BEGIN PUBLIC KEY");
		expect(publicKey).toContain("END PUBLIC KEY");
		expect(privateKey).toContain("BEGIN PRIVATE KEY");
		expect(privateKey).toContain("END PRIVATE KEY");
	});

	it("generates unique key pairs on each call", () => {
		const a = generateKeyPair();
		const b = generateKeyPair();

		expect(a.publicKey).not.toBe(b.publicKey);
		expect(a.privateKey).not.toBe(b.privateKey);
	});
});

describe("signReceipt", () => {
	it("returns a receipt with a valid proof", () => {
		const { privateKey } = generateKeyPair();
		const unsigned = makeUnsignedReceipt();
		const verificationMethod = "did:agent:test-agent#key-1";

		const signed = signReceipt(unsigned, privateKey, verificationMethod);

		expect(signed.proof.type).toBe("Ed25519Signature2020");
		expect(signed.proof.proofPurpose).toBe("assertionMethod");
		expect(signed.proof.verificationMethod).toBe(verificationMethod);
		expect(signed.proof.proofValue).toMatch(/^u[A-Za-z0-9_-]+$/);
		expect(signed.proof.created).toBeDefined();
	});

	it("preserves all unsigned fields", () => {
		const { privateKey } = generateKeyPair();
		const unsigned = makeUnsignedReceipt();

		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");

		expect(signed.id).toBe(unsigned.id);
		expect(signed.issuer).toEqual(unsigned.issuer);
		expect(signed.credentialSubject).toEqual(unsigned.credentialSubject);
	});
});

describe("verifyReceipt", () => {
	it("returns true for a validly signed receipt", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const unsigned = makeUnsignedReceipt();

		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");
		const valid = verifyReceipt(signed, publicKey);

		expect(valid).toBe(true);
	});

	it("returns false when the receipt has been tampered with", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const unsigned = makeUnsignedReceipt();

		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");
		signed.credentialSubject.action.risk_level = "critical";

		expect(verifyReceipt(signed, publicKey)).toBe(false);
	});

	it("returns false for malformed proofValue", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const unsigned = makeUnsignedReceipt();

		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");
		signed.proof.proofValue = "invalid";

		expect(verifyReceipt(signed, publicKey)).toBe(false);
	});

	it("returns false when proof.type is not Ed25519Signature2020", () => {
		// proof.type lives outside the signed bytes, so the Ed25519 signature
		// is still mathematically valid. verifyReceipt MUST still reject the
		// receipt — otherwise an attacker could swap the type to claim a
		// different scheme.
		const { publicKey, privateKey } = generateKeyPair();
		const unsigned = makeUnsignedReceipt();
		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");
		signed.proof.type = "RsaSignature2018";

		expect(verifyReceipt(signed, publicKey)).toBe(false);
	});

	it("returns false when verified with a different key", () => {
		const signer = generateKeyPair();
		const other = generateKeyPair();
		const unsigned = makeUnsignedReceipt();

		const signed = signReceipt(
			unsigned,
			signer.privateKey,
			"did:agent:test#key-1",
		);

		expect(verifyReceipt(signed, other.publicKey)).toBe(false);
	});

	it("throws when chain.terminal is explicitly false (spec §4.3.2 guard)", () => {
		const { privateKey } = generateKeyPair();
		const unsigned = makeUnsignedReceipt();
		// Bypass the type system the way an untyped JSON consumer would.
		(unsigned.credentialSubject.chain as { terminal: unknown }).terminal =
			false;

		expect(() =>
			signReceipt(unsigned, privateKey, "did:agent:test#key-1"),
		).toThrow(/terminal/);
	});
});

describe("ADR-0009 optional-null normalisation (issue #1005)", () => {
	// Ed25519 signing is deterministic (RFC 8032): the same key and message
	// always produce the same signature. That makes proofValue equality a
	// precise probe for "these two calls signed identical canonical bytes".
	it("signs identical bytes whether an optional field is null or absent", () => {
		const { privateKey } = generateKeyPair();

		const withNull = makeUnsignedReceipt();
		// Bypass the type system the way an `as UnsignedAgentReceipt` cast or
		// untyped JSON consumer would.
		(withNull.credentialSubject.outcome as { error: unknown }).error = null;
		const withAbsent = makeUnsignedReceipt();

		const signedWithNull = signReceipt(
			withNull,
			privateKey,
			"did:agent:test#key-1",
		);
		const signedWithAbsent = signReceipt(
			withAbsent,
			privateKey,
			"did:agent:test#key-1",
		);

		expect(signedWithNull.proof.proofValue).toBe(
			signedWithAbsent.proof.proofValue,
		);
	});

	it("verifies a receipt carrying an explicit null on an optional field", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const unsigned = makeUnsignedReceipt();
		(unsigned.credentialSubject.outcome as { error: unknown }).error = null;

		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");

		expect(verifyReceipt(signed, publicKey)).toBe(true);
	});

	it("signs over the same canonical bytes hashReceipt commits to", () => {
		const { privateKey } = generateKeyPair();
		const unsigned = makeUnsignedReceipt();
		(unsigned.credentialSubject.outcome as { error: unknown }).error = null;

		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");
		const signedWithoutNull: AgentReceipt = {
			...signed,
			credentialSubject: {
				...signed.credentialSubject,
				outcome: { status: "success" },
			},
		};

		// The proof differs (created timestamp), but the hash — which also
		// excludes proof — must be identical, since both signReceipt and
		// hashReceipt normalise `error: null` to absent before committing.
		expect(hashReceipt(signed)).toBe(hashReceipt(signedWithoutNull));
	});
});
