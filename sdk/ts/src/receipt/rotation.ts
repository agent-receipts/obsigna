import { createHash, createPublicKey } from "node:crypto";
import type { KeyRotation } from "./types.js";

/** The only signature algorithm the protocol supports (ADR-0001). Cross-algorithm
 *  rotation is deferred to the algorithm-agility work and rejected until then. */
const ALGORITHM_ED25519 = "ed25519";

/** Raw Ed25519 public keys are 32 bytes (RFC 8032 §5.1.5). */
const ED25519_PUBLIC_KEY_SIZE = 32;

/** ADR-0015 fingerprint of a raw public key: SHA-256 of the raw key bytes,
 *  rendered as sha256:<lowercase hex>. The bytes are the algorithm's canonical
 *  encoding — never an SPKI/PEM wrapper or a backend handle. */
export function keyFingerprint(raw: Buffer): string {
	return `sha256:${createHash("sha256").update(raw).digest("hex")}`;
}

/** Decode a multibase-"u" base64url string (the encoding ADR-0001 uses for
 *  proof.proofValue, applied here to raw public-key bytes) into a 32-byte
 *  Ed25519 public key. */
export function decodeMultibaseEd25519Key(s: string): Buffer {
	if (s.length === 0 || s[0] !== "u") {
		throw new Error('expected multibase "u" prefix');
	}
	if (!/^u[A-Za-z0-9_-]+$/.test(s)) {
		throw new Error("new_public_key is not multibase base64url");
	}
	const raw = Buffer.from(s.slice(1), "base64url");
	if (raw.length !== ED25519_PUBLIC_KEY_SIZE) {
		throw new Error(
			`expected ${ED25519_PUBLIC_KEY_SIZE} key bytes, got ${raw.length}`,
		);
	}
	return raw;
}

/** Wrap a raw 32-byte Ed25519 public key in PEM-encoded SPKI, the form the
 *  signature verifier consumes. */
export function ed25519RawToPem(raw: Buffer): string {
	const key = createPublicKey({
		key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
		format: "jwk",
	});
	return key.export({ type: "spki", format: "pem" }).toString();
}

/** Extract the raw 32-byte Ed25519 public key from a PEM-encoded SPKI key. */
export function pemToEd25519Raw(pem: string): Buffer {
	const jwk = createPublicKey(pem).export({ format: "jwk" });
	if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
		throw new Error("public key is not Ed25519");
	}
	return Buffer.from(jwk.x, "base64url");
}

export type RotationResult =
	| { ok: true; newKeyPem: string }
	| { ok: false; error: string };

/**
 * Validate the rotation-event fields of a key_rotated receipt against the
 * outgoing (currently active) public key and return the PEM-encoded incoming
 * key that subsequent receipts must verify against.
 *
 * Implements the field-level checks of the ADR-0015 verifier traversal: the
 * constant fields, the supported-algorithm guard, the old-key fingerprint
 * consistency check against the outgoing key, and the new-key fingerprint check
 * against the inline new_public_key. The rotation receipt's own signature is
 * verified separately by the caller (it is signed with the outgoing key).
 */
export function verifyRotationEvent(
	activeKeyPem: string,
	kr: KeyRotation,
): RotationResult {
	if (kr.event_type !== "key_rotated") {
		return {
			ok: false,
			error: `event_type must be "key_rotated", got "${kr.event_type}"`,
		};
	}
	if (kr.signed_with !== "old") {
		return {
			ok: false,
			error: `signed_with must be "old", got "${kr.signed_with}"`,
		};
	}
	if (kr.old_algorithm !== ALGORITHM_ED25519) {
		return {
			ok: false,
			error: `unsupported old_algorithm "${kr.old_algorithm}": only "${ALGORITHM_ED25519}" is supported`,
		};
	}
	if (kr.new_algorithm !== ALGORITHM_ED25519) {
		return {
			ok: false,
			error: `unsupported new_algorithm "${kr.new_algorithm}": only "${ALGORITHM_ED25519}" is supported`,
		};
	}

	let outRaw: Buffer;
	try {
		outRaw = pemToEd25519Raw(activeKeyPem);
	} catch (e) {
		return {
			ok: false,
			error: `parse outgoing key: ${e instanceof Error ? e.message : String(e)}`,
		};
	}
	const outFp = keyFingerprint(outRaw);
	if (outFp !== kr.old_key_fingerprint) {
		return {
			ok: false,
			error: `old_key_fingerprint mismatch: outgoing key is ${outFp}, field says ${kr.old_key_fingerprint}`,
		};
	}

	let newRaw: Buffer;
	try {
		newRaw = decodeMultibaseEd25519Key(kr.new_public_key);
	} catch (e) {
		return {
			ok: false,
			error: `decode new_public_key: ${e instanceof Error ? e.message : String(e)}`,
		};
	}
	const newFp = keyFingerprint(newRaw);
	if (newFp !== kr.new_key_fingerprint) {
		return {
			ok: false,
			error: `new_key_fingerprint mismatch: new_public_key hashes to ${newFp}, field says ${kr.new_key_fingerprint}`,
		};
	}

	try {
		return { ok: true, newKeyPem: ed25519RawToPem(newRaw) };
	} catch (e) {
		return {
			ok: false,
			error: `encode incoming key: ${e instanceof Error ? e.message : String(e)}`,
		};
	}
}
