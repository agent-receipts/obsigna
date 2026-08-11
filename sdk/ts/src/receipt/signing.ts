import { generateKeyPairSync, sign, verify } from "node:crypto";
import { canonicalize, normalizeForCanonicalization } from "./hash.js";
import type { AgentReceipt, Proof, UnsignedAgentReceipt } from "./types.js";

export interface KeyPair {
	publicKey: string;
	privateKey: string;
}

/** Multibase prefix for base64url (no padding) encoding. */
const MULTIBASE_BASE64URL = "u";

/**
 * The only proof.type the spec accepts. Verifiers MUST reject any other
 * value so that consumers cannot be tricked into believing a receipt was
 * signed under a different scheme.
 */
const PROOF_TYPE_ED25519_SIGNATURE_2020 = "Ed25519Signature2020";

/**
 * Generate an Ed25519 key pair (PEM-encoded).
 *
 * Note: uses synchronous generation which blocks the event loop.
 * For long-running services, consider wrapping in a worker thread.
 */
export function generateKeyPair(): KeyPair {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
		publicKeyEncoding: { type: "spki", format: "pem" },
		privateKeyEncoding: { type: "pkcs8", format: "pem" },
	});
	return { publicKey, privateKey };
}

/**
 * Serialize an unsigned receipt to bytes using RFC 8785 canonicalization.
 *
 * Applies ADR-0009 Rule 2 (optional-null normalisation) via the same
 * normalizeForCanonicalization() helper hashReceipt() uses, so a receipt's
 * signature and its chain hash always commit to identical canonical bytes.
 */
function canonicalizeReceipt(receipt: UnsignedAgentReceipt): Buffer {
	return Buffer.from(
		canonicalize(normalizeForCanonicalization(receipt)),
		"utf-8",
	);
}

/**
 * Sign an unsigned receipt, returning a complete AgentReceipt with proof.
 *
 * Throws if the receipt carries `chain.terminal: false`. Per spec §4.3.2,
 * `terminal` is restricted to the constant `true` or absent — explicit
 * `false` is schema-invalid. This runtime guard mirrors Python's Pydantic
 * `Literal[True] | None` validation and Go's `Chain.MarshalJSON`
 * structural drop. TypeScript's `terminal?: true` type prevents this at
 * compile time, but untyped JSON or `as AgentReceipt` casts can bypass
 * the type system.
 */
export function signReceipt(
	unsigned: UnsignedAgentReceipt,
	privateKey: string,
	verificationMethod: string,
): AgentReceipt {
	const terminal = unsigned.credentialSubject?.chain?.terminal;
	if (terminal !== undefined && terminal !== true) {
		throw new Error(
			"signReceipt: chain.terminal must be true or absent (got false); spec §4.3.2 forbids terminal: false on the wire",
		);
	}

	const data = canonicalizeReceipt(unsigned);
	const signature = sign(null, data, privateKey);

	const proof: Proof = {
		type: PROOF_TYPE_ED25519_SIGNATURE_2020,
		created: new Date().toISOString(),
		verificationMethod,
		proofPurpose: "assertionMethod",
		proofValue: `${MULTIBASE_BASE64URL}${signature.toString("base64url")}`,
	};

	return { ...unsigned, proof };
}

/**
 * Verify the Ed25519 signature on a signed receipt.
 */
export function verifyReceipt(
	receipt: AgentReceipt,
	publicKey: string,
): boolean {
	const { proof, ...unsigned } = receipt;

	if (proof?.type !== PROOF_TYPE_ED25519_SIGNATURE_2020) {
		return false;
	}

	const proofValue = proof.proofValue;
	if (
		typeof proofValue !== "string" ||
		proofValue.length < 2 ||
		!proofValue.startsWith(MULTIBASE_BASE64URL)
	) {
		return false;
	}

	const data = canonicalizeReceipt(unsigned as UnsignedAgentReceipt);
	const signature = Buffer.from(proofValue.slice(1), "base64url");

	return verify(null, data, publicKey, signature);
}
