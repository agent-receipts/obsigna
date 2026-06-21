/**
 * HPKE disclosure envelope for parameters_disclosure (ADR-0012, amendment 2026-05-18).
 *
 * Ciphersuite: hpke-x25519-hkdf-sha256-aes-256-gcm
 * (RFC 9180, KEM=DHKEM(X25519,HKDF-SHA256) 0x0020, KDF=HKDF-SHA256 0x0001, AEAD=AES-256-GCM 0x0002)
 *
 * The HPKE primitives are implemented in ./hpke.ts on top of node:crypto, so
 * disclosure has no third-party crypto dependency.
 */

import { canonicalize, isPlainObject } from "./hash.js";
import { generateKeyPair, open, seal } from "./hpke.js";

const V1_ALG = "hpke-x25519-hkdf-sha256-aes-256-gcm" as const;

/** One entry in the recipients array. Field names match RFC 9180 §4.1 ("enc", not "encap"). */
export interface DisclosureRecipient {
	kid: string;
	enc: string; // HPKE encapsulated key; unpadded base64url, exactly 43 chars for X25519
}

/**
 * v1 asymmetric encryption envelope for parameters_disclosure (ADR-0012).
 * The signed receipt commits to the ciphertext; only the forensic private key
 * holder can recover the plaintext.
 */
export interface DisclosureEnvelope {
	v: "1";
	alg: typeof V1_ALG;
	recipients: [DisclosureRecipient]; // length-1 tuple enforces v1 single-recipient constraint
	ct: string; // AEAD ciphertext; unpadded base64url
}

/**
 * Raw X25519 key bytes (32 bytes each) for forensic disclosure.
 * Separate from the Ed25519 signing key pair per ADR-0001 / ADR-0012.
 */
export interface ForensicKeyPair {
	/** 32-byte X25519 public key. Share with emitters so they can encrypt disclosures. */
	publicKey: Uint8Array;
	/** 32-byte X25519 private key. Keep offline; required to decrypt disclosures. */
	privateKey: Uint8Array;
}

function toBase64Url(buf: ArrayBuffer | Uint8Array): string {
	return Buffer.from(
		buf instanceof Uint8Array ? buf : new Uint8Array(buf),
	).toString("base64url");
}

// Strict unpadded base64url decoder. Rejects:
//   - empty strings
//   - any character outside [A-Za-z0-9_-]
//   - strings where len % 4 === 1 (never valid in base64, even unpadded)
function fromBase64Url(s: string): Uint8Array {
	if (s.length === 0 || s.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(s)) {
		throw new Error(
			"invalid base64url: must be non-empty unpadded base64url [A-Za-z0-9_-] with valid length",
		);
	}
	return Buffer.from(s, "base64url");
}

/**
 * Generates an X25519 key pair for forensic disclosure.
 * The public key is shared with emitters; the private key must be kept offline.
 */
export async function generateForensicKeyPair(): Promise<ForensicKeyPair> {
	const { publicKey, privateKey } = generateKeyPair();
	return { publicKey, privateKey };
}

/**
 * Encrypts params as a v1 HPKE disclosure envelope.
 *
 * params is RFC 8785 JCS-canonicalized before encryption so all SDKs encrypt
 * the same bytes for the same parameters object.
 *
 * @param params - The parameters to encrypt (must be a plain object, not null/array).
 * @param recipientPublicKey - 32-byte X25519 forensic public key.
 * @param kid - Recipient key identifier (did:key DID URL or sha256:<hex> fingerprint).
 */
export async function encryptDisclosure(
	params: Record<string, unknown>,
	recipientPublicKey: Uint8Array,
	kid: string,
): Promise<DisclosureEnvelope> {
	if (!isPlainObject(params)) {
		throw new Error("params must be a plain object");
	}
	if (recipientPublicKey.byteLength !== 32) {
		throw new Error(
			`recipientPublicKey must be 32 bytes, got ${recipientPublicKey.byteLength}`,
		);
	}
	if (!kid) {
		throw new Error("kid must not be empty");
	}
	return encryptWithOptions(params, recipientPublicKey, kid, undefined);
}

/**
 * Deterministic variant of encryptDisclosure for cross-SDK test vectors.
 * ikmE (32 bytes) is the ephemeral key material; the HPKE layer applies
 * DHKEM(X25519) DeriveKeyPair (RFC 9180 §7.1.3 HKDF derivation) to produce the
 * ephemeral scalar — it does NOT use ikmE directly as the scalar. This is
 * confirmed by vector-1: ikmE = RFC 9180 §A.1.1 ikmE → enc = RFC 9180 §A.1.1 pkEm.
 *
 * @internal FOR TESTING ONLY. Reusing ikmE across real encryptions breaks confidentiality.
 */
export async function encryptDisclosureWithSeed(
	params: Record<string, unknown>,
	recipientPublicKey: Uint8Array,
	kid: string,
	ikmE: Uint8Array,
): Promise<DisclosureEnvelope> {
	if (!isPlainObject(params)) {
		throw new Error("params must be a plain object");
	}
	if (recipientPublicKey.byteLength !== 32) {
		throw new Error(
			`recipientPublicKey must be 32 bytes, got ${recipientPublicKey.byteLength}`,
		);
	}
	if (!kid) {
		throw new Error("kid must not be empty");
	}
	if (ikmE.byteLength !== 32) {
		throw new Error(`ikmE must be 32 bytes, got ${ikmE.byteLength}`);
	}
	return encryptWithOptions(params, recipientPublicKey, kid, ikmE);
}

async function encryptWithOptions(
	params: Record<string, unknown>,
	recipientPublicKey: Uint8Array,
	kid: string,
	ikmE: Uint8Array | undefined,
): Promise<DisclosureEnvelope> {
	// RFC 8785 JCS before encryption — cross-SDK interop depends on this.
	const canonical = canonicalize(params);

	// info="" and AAD="" per ADR-0012 amendment §8 — both baked into seal().
	const { enc, ct } = seal(
		recipientPublicKey,
		new TextEncoder().encode(canonical),
		ikmE,
	);

	return {
		v: "1",
		alg: V1_ALG,
		recipients: [{ kid, enc: toBase64Url(enc) }],
		ct: toBase64Url(ct),
	};
}

/**
 * Encrypts a tool response as a v1 HPKE disclosure envelope for `outcome.response_disclosure`.
 *
 * Identical to {@link encryptDisclosure} in primitive and encoding — uses the
 * same forensic key pair, same HPKE ciphersuite, and same JCS canonicalization.
 * The separation exists so operators can enable response disclosure independently
 * of parameter disclosure via separate `--response-disclosure` / `--parameter-disclosure`
 * policy flags.
 *
 * @param response - The response object to encrypt (must be a plain object, not null/array).
 * @param recipientPublicKey - 32-byte X25519 forensic public key.
 * @param kid - Recipient key identifier (did:key DID URL or sha256:<hex> fingerprint).
 */
export async function encryptResponse(
	response: Record<string, unknown>,
	recipientPublicKey: Uint8Array,
	kid: string,
): Promise<DisclosureEnvelope> {
	if (!isPlainObject(response)) {
		throw new Error("response must be a plain object");
	}
	if (recipientPublicKey.byteLength !== 32) {
		throw new Error(
			`recipientPublicKey must be 32 bytes, got ${recipientPublicKey.byteLength}`,
		);
	}
	if (!kid) {
		throw new Error("kid must not be empty");
	}
	return encryptWithOptions(response, recipientPublicKey, kid, undefined);
}

/**
 * Deterministic variant of {@link encryptResponse} for cross-SDK test vectors.
 *
 * @internal FOR TESTING ONLY. Reusing ikmE across real encryptions breaks confidentiality.
 */
export async function encryptResponseWithSeed(
	response: Record<string, unknown>,
	recipientPublicKey: Uint8Array,
	kid: string,
	ikmE: Uint8Array,
): Promise<DisclosureEnvelope> {
	if (!isPlainObject(response)) {
		throw new Error("response must be a plain object");
	}
	if (recipientPublicKey.byteLength !== 32) {
		throw new Error(
			`recipientPublicKey must be 32 bytes, got ${recipientPublicKey.byteLength}`,
		);
	}
	if (!kid) {
		throw new Error("kid must not be empty");
	}
	if (ikmE.byteLength !== 32) {
		throw new Error(`ikmE must be 32 bytes, got ${ikmE.byteLength}`);
	}
	return encryptWithOptions(response, recipientPublicKey, kid, ikmE);
}

/**
 * Recovers the plaintext response from a v1 HPKE disclosure envelope
 * stored in `outcome.response_disclosure`.
 *
 * Identical to {@link decryptDisclosure} — the same envelope format is used
 * for both parameters and response disclosures.
 *
 * @param env - The disclosure envelope to decrypt.
 * @param recipientPrivateKey - 32-byte X25519 forensic private key.
 */
export async function decryptResponse(
	env: DisclosureEnvelope,
	recipientPrivateKey: Uint8Array,
): Promise<Record<string, unknown>> {
	return decryptDisclosure(env, recipientPrivateKey);
}

/**
 * Recovers the plaintext parameters from a v1 HPKE disclosure envelope.
 * @param env - The disclosure envelope to decrypt.
 * @param recipientPrivateKey - 32-byte X25519 forensic private key.
 */
export async function decryptDisclosure(
	env: DisclosureEnvelope,
	recipientPrivateKey: Uint8Array,
): Promise<Record<string, unknown>> {
	if (env == null) {
		throw new Error("disclosure envelope must not be null or undefined");
	}
	if (env.v !== "1") {
		throw new Error(`unsupported envelope version "${env.v}"`);
	}
	if (env.alg !== V1_ALG) {
		throw new Error(`unsupported algorithm "${env.alg}"`);
	}
	if (!Array.isArray(env.recipients) || env.recipients.length !== 1) {
		throw new Error(
			`v1 envelope must have exactly 1 recipient, got ${env.recipients?.length ?? 0}`,
		);
	}
	if (recipientPrivateKey.byteLength !== 32) {
		throw new Error(
			`recipientPrivateKey must be 32 bytes, got ${recipientPrivateKey.byteLength}`,
		);
	}
	// 24 chars = 18 bytes minimum: AES-256-GCM 16-byte tag + 2-byte minimum plaintext ("{}").
	if (typeof env.ct !== "string" || env.ct.length < 24) {
		throw new Error(
			`ct is too short: expected at least 24 unpadded base64url characters, got ${env.ct?.length ?? 0}`,
		);
	}

	const recipient = env.recipients[0];
	if (typeof recipient?.enc !== "string") {
		throw new Error("recipient enc must be a string");
	}
	if (typeof recipient.kid !== "string" || recipient.kid.length === 0) {
		throw new Error("recipient kid must be a non-empty string");
	}

	const enc = fromBase64Url(recipient.enc);
	if (enc.byteLength !== 32) {
		throw new Error(
			`invalid enc: expected 32 bytes (X25519 encapsulated key), got ${enc.byteLength}`,
		);
	}
	const ct = fromBase64Url(env.ct);

	const plaintext = open(recipientPrivateKey, enc, ct);

	const result: unknown = JSON.parse(new TextDecoder().decode(plaintext));
	if (!isPlainObject(result)) {
		throw new Error("decrypted plaintext is not a JSON object");
	}
	return result;
}
