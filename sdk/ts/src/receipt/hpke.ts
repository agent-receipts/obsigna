/**
 * RFC 9180 HPKE base mode, hand-rolled from node:crypto built-ins.
 *
 * Pinned ciphersuite (ADR-0012): hpke-x25519-hkdf-sha256-aes-256-gcm
 *   KEM  = DHKEM(X25519, HKDF-SHA256)  (0x0020)
 *   KDF  = HKDF-SHA256                 (0x0001)
 *   AEAD = AES-256-GCM                 (0x0002)
 *
 * Only the slice of RFC 9180 the disclosure envelope needs is implemented:
 * base mode (no PSK, no sender auth), single-shot seal/open, `info` and `aad`
 * both empty. Anything outside that profile is intentionally absent.
 *
 * This replaces the @hpke/core dependency — a small library is a real supply
 * chain surface for a cryptographic protocol, and the X25519 path is short
 * enough to own outright. The deterministic vectors in disclosure.test.ts pin
 * the output byte-for-byte against the Go SDK reference and RFC 9180 §A.1.1.
 */

import {
	createCipheriv,
	createDecipheriv,
	createHmac,
	createPrivateKey,
	createPublicKey,
	diffieHellman,
	generateKeyPairSync,
	type KeyObject,
} from "node:crypto";

// suite_id values per RFC 9180 §4.1 / §5.1.
//   KEM : "KEM"  || I2OSP(kem_id, 2)
//   HPKE: "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
const KEM_SUITE_ID = concatBytes(asBytes("KEM"), i2osp2(0x0020));
const HPKE_SUITE_ID = concatBytes(
	asBytes("HPKE"),
	i2osp2(0x0020),
	i2osp2(0x0001),
	i2osp2(0x0002),
);

const HASH_LEN = 32; // SHA-256 output (Nh)
const NSECRET = 32; // DHKEM(X25519) shared secret length
const NSK = 32; // X25519 private scalar length (Nsk)
const NK = 32; // AES-256-GCM key length (Nk)
const NN = 12; // AES-256-GCM nonce length (Nn)
const NT = 16; // AES-256-GCM authentication tag length
const MODE_BASE = 0x00;

/** Raw 32-byte X25519 key pair. */
export interface HpkeKeyPair {
	publicKey: Uint8Array;
	privateKey: Uint8Array;
}

// --- HKDF (RFC 5869) ---------------------------------------------------------

// HKDF-Extract. An empty salt is HMAC with an empty key, which Node treats
// identically to a HashLen-zero key — the behaviour RFC 5869 specifies and
// the disclosure vectors confirm byte-for-byte.
function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Buffer {
	return createHmac("sha256", salt).update(ikm).digest();
}

// HKDF-Expand. Every call in this suite requests <= HASH_LEN bytes
// (sk/shared_secret/key=32, base_nonce=12), so the loop runs once; it is kept
// general so the primitive stays correct for any length up to RFC 5869's
// 255*HashLen ceiling, beyond which the single-byte counter would wrap.
function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Buffer {
	if (length > 255 * HASH_LEN) {
		throw new Error(`HKDF-Expand length ${length} exceeds 255*HashLen`);
	}
	const blocks: Buffer[] = [];
	let prev = Buffer.alloc(0);
	for (let counter = 1; blockLen(blocks) < length; counter++) {
		prev = createHmac("sha256", prk)
			.update(prev)
			.update(info)
			.update(Uint8Array.of(counter))
			.digest();
		blocks.push(prev);
	}
	return Buffer.concat(blocks).subarray(0, length);
}

// --- Labeled HKDF (RFC 9180 §4) ---------------------------------------------

function labeledExtract(
	suiteId: Uint8Array,
	salt: Uint8Array,
	label: string,
	ikm: Uint8Array,
): Buffer {
	const labeledIkm = concatBytes(
		asBytes("HPKE-v1"),
		suiteId,
		asBytes(label),
		ikm,
	);
	return hkdfExtract(salt, labeledIkm);
}

function labeledExpand(
	suiteId: Uint8Array,
	prk: Uint8Array,
	label: string,
	info: Uint8Array,
	length: number,
): Buffer {
	const labeledInfo = concatBytes(
		i2osp2(length),
		asBytes("HPKE-v1"),
		suiteId,
		asBytes(label),
		info,
	);
	return hkdfExpand(prk, labeledInfo, length);
}

// --- DHKEM(X25519, HKDF-SHA256) (RFC 9180 §7.1) -----------------------------

/**
 * DeriveKeyPair for X25519 (RFC 9180 §7.1.3): HKDF over `ikm`, then the scalar
 * is used directly. This is the simple path — unlike NIST curves, X25519 does
 * NOT run the "candidate" rejection-sampling loop, and the LabeledExpand label
 * is "sk" with empty info.
 */
function kemDeriveKeyPair(ikm: Uint8Array): HpkeKeyPair {
	const dkpPrk = labeledExtract(KEM_SUITE_ID, EMPTY, "dkp_prk", ikm);
	const sk = labeledExpand(KEM_SUITE_ID, dkpPrk, "sk", EMPTY, NSK);
	const privateKeyObj = privFromRaw(sk);
	return {
		privateKey: sk,
		publicKey: rawPublicKey(
			createPublicKey(
				privateKeyObj as unknown as Parameters<typeof createPublicKey>[0],
			),
		),
	};
}

// ExtractAndExpand (RFC 9180 §4.1) over the DH output and KEM context.
function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Buffer {
	const eaePrk = labeledExtract(KEM_SUITE_ID, EMPTY, "eae_prk", dh);
	return labeledExpand(
		KEM_SUITE_ID,
		eaePrk,
		"shared_secret",
		kemContext,
		NSECRET,
	);
}

/**
 * Encap (RFC 9180 §7.1.1): generate (or, in the deterministic test path,
 * derive from `ikmE`) an ephemeral key pair, DH against the recipient, and
 * derive the shared secret. Returns the encapsulated public key and the
 * shared secret.
 */
function kemEncap(
	recipientPublicKey: Uint8Array,
	ikmE?: Uint8Array,
): { enc: Uint8Array; sharedSecret: Uint8Array } {
	const ephemeral =
		ikmE !== undefined ? kemDeriveKeyPair(ikmE) : generateKeyPair();
	const dh = x25519(
		privFromRaw(ephemeral.privateKey),
		pubFromRaw(recipientPublicKey),
		"recipient public key",
	);
	const kemContext = concatBytes(ephemeral.publicKey, recipientPublicKey);
	return {
		enc: ephemeral.publicKey,
		sharedSecret: extractAndExpand(dh, kemContext),
	};
}

/**
 * Decap (RFC 9180 §7.1.1): DH the recipient private key against the
 * encapsulated public key and re-derive the shared secret.
 */
function kemDecap(enc: Uint8Array, recipientPrivateKey: Uint8Array): Buffer {
	const recipientPriv = privFromRaw(recipientPrivateKey);
	const dh = x25519(recipientPriv, pubFromRaw(enc), "encapsulated key");
	const recipientPub = rawPublicKey(
		createPublicKey(
			recipientPriv as unknown as Parameters<typeof createPublicKey>[0],
		),
	);
	const kemContext = concatBytes(enc, recipientPub);
	return extractAndExpand(dh, kemContext);
}

// X25519 key agreement that maps OpenSSL's opaque derivation failure to an
// actionable error. A low-order public key (the all-zero shared secret RFC 7748
// §6.1 warns about) is rejected here rather than producing that secret;
// `keyName` identifies whose key was rejected for the caller.
function x25519(
	privateKey: KeyObject,
	publicKey: KeyObject,
	keyName: string,
): Buffer {
	try {
		return diffieHellman({ privateKey, publicKey });
	} catch (err) {
		throw new Error(`invalid ${keyName}: X25519 key agreement failed`, {
			cause: err,
		});
	}
}

// --- Key schedule (RFC 9180 §5.1) -------------------------------------------

// Base mode, info="", psk="", psk_id="". Derives the AEAD key and base nonce;
// the exporter secret is not needed by the disclosure envelope, so it is not
// computed.
function keySchedule(sharedSecret: Uint8Array): {
	key: Buffer;
	baseNonce: Buffer;
} {
	const pskIdHash = labeledExtract(HPKE_SUITE_ID, EMPTY, "psk_id_hash", EMPTY);
	const infoHash = labeledExtract(HPKE_SUITE_ID, EMPTY, "info_hash", EMPTY);
	const ksContext = concatBytes(Uint8Array.of(MODE_BASE), pskIdHash, infoHash);

	const secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, "secret", EMPTY);
	return {
		key: labeledExpand(HPKE_SUITE_ID, secret, "key", ksContext, NK),
		baseNonce: labeledExpand(
			HPKE_SUITE_ID,
			secret,
			"base_nonce",
			ksContext,
			NN,
		),
	};
}

// --- AEAD (AES-256-GCM) ------------------------------------------------------

// Single-shot seal: sequence number 0, so the nonce is the base nonce directly
// (RFC 9180 §5.2 ComputeNonce with seq=0). GCM tag is appended to the
// ciphertext, matching the @hpke/core and circl wire layout.
function aeadSeal(
	key: Uint8Array,
	nonce: Uint8Array,
	aad: Uint8Array,
	plaintext: Uint8Array,
): Buffer {
	const cipher = createCipheriv("aes-256-gcm", key, nonce);
	cipher.setAAD(aad);
	const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	return Buffer.concat([body, cipher.getAuthTag()]);
}

function aeadOpen(
	key: Uint8Array,
	nonce: Uint8Array,
	aad: Uint8Array,
	ciphertext: Uint8Array,
): Buffer {
	if (ciphertext.length < NT) {
		throw new Error(`ciphertext too short to contain a ${NT}-byte GCM tag`);
	}
	const tag = ciphertext.subarray(ciphertext.length - NT);
	const body = ciphertext.subarray(0, ciphertext.length - NT);
	const decipher = createDecipheriv("aes-256-gcm", key, nonce);
	decipher.setAAD(aad);
	decipher.setAuthTag(tag);
	// final() throws on tag mismatch — wrong key or tampered ciphertext.
	return Buffer.concat([decipher.update(body), decipher.final()]);
}

// --- Public API (info="" and aad="" baked in per ADR-0012) ------------------

/** Generates a fresh random X25519 key pair as raw 32-byte values. */
export function generateKeyPair(): HpkeKeyPair {
	const { privateKey, publicKey } = generateKeyPairSync("x25519");
	return {
		privateKey: rawPrivateKey(privateKey),
		publicKey: rawPublicKey(publicKey),
	};
}

/**
 * HPKE single-shot seal in base mode against `recipientPublicKey`.
 *
 * @param ikmE - Deterministic ephemeral key material (RFC 9180 §7.1.3
 *   DeriveKeyPair). FOR TESTING ONLY — production callers omit it so a fresh
 *   random ephemeral key is generated per call.
 */
export function seal(
	recipientPublicKey: Uint8Array,
	plaintext: Uint8Array,
	ikmE?: Uint8Array,
): { enc: Uint8Array; ct: Uint8Array } {
	if (recipientPublicKey.length !== 32) {
		throw new Error(
			`recipientPublicKey must be 32 bytes, got ${recipientPublicKey.length}`,
		);
	}
	if (ikmE !== undefined && ikmE.length !== NSK) {
		throw new Error(`ikmE must be ${NSK} bytes, got ${ikmE.length}`);
	}
	const { enc, sharedSecret } = kemEncap(recipientPublicKey, ikmE);
	const { key, baseNonce } = keySchedule(sharedSecret);
	return { enc, ct: aeadSeal(key, baseNonce, EMPTY, plaintext) };
}

/** HPKE single-shot open in base mode with `recipientPrivateKey`. */
export function open(
	recipientPrivateKey: Uint8Array,
	enc: Uint8Array,
	ciphertext: Uint8Array,
): Uint8Array {
	if (recipientPrivateKey.length !== 32) {
		throw new Error(
			`recipientPrivateKey must be 32 bytes, got ${recipientPrivateKey.length}`,
		);
	}
	if (enc.length !== 32) {
		throw new Error(
			`enc must be 32 bytes (X25519 public key), got ${enc.length}`,
		);
	}
	const sharedSecret = kemDecap(enc, recipientPrivateKey);
	const { key, baseNonce } = keySchedule(sharedSecret);
	return aeadOpen(key, baseNonce, EMPTY, ciphertext);
}

// --- X25519 raw <-> KeyObject helpers ---------------------------------------

// Node has no direct "raw bytes" import for X25519, so wrap the 32-byte scalar
// / public key in the fixed PKCS#8 / SPKI DER prefixes for the id-X25519 OID
// (1.3.101.110). The prefixes are constant; only the trailing 32 bytes vary.
const PKCS8_X25519_PREFIX = Buffer.from(
	"302e020100300506032b656e04220420",
	"hex",
);
const SPKI_X25519_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function privFromRaw(scalar: Uint8Array): KeyObject {
	if (scalar.length !== 32) {
		throw new Error(
			`X25519 private key must be 32 bytes, got ${scalar.length}`,
		);
	}
	return createPrivateKey({
		key: Buffer.concat([PKCS8_X25519_PREFIX, scalar]),
		format: "der",
		type: "pkcs8",
	});
}

function pubFromRaw(pub: Uint8Array): KeyObject {
	if (pub.length !== 32) {
		throw new Error(`X25519 public key must be 32 bytes, got ${pub.length}`);
	}
	return createPublicKey({
		key: Buffer.concat([SPKI_X25519_PREFIX, pub]),
		format: "der",
		type: "spki",
	});
}

function rawPublicKey(key: KeyObject): Uint8Array {
	const jwk = key.export({ format: "jwk" });
	if (typeof jwk.x !== "string") {
		throw new Error("X25519 public key JWK is missing the x coordinate");
	}
	return new Uint8Array(Buffer.from(jwk.x, "base64url"));
}

function rawPrivateKey(key: KeyObject): Uint8Array {
	const jwk = key.export({ format: "jwk" });
	if (typeof jwk.d !== "string") {
		throw new Error("X25519 private key JWK is missing the d scalar");
	}
	return new Uint8Array(Buffer.from(jwk.d, "base64url"));
}

// --- byte helpers ------------------------------------------------------------

const EMPTY = new Uint8Array(0);

function asBytes(s: string): Uint8Array {
	return new TextEncoder().encode(s);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
	return Buffer.concat(parts);
}

// I2OSP(n, 2): big-endian 2-byte encoding. All HPKE lengths here fit in 16 bits.
function i2osp2(n: number): Uint8Array {
	return Uint8Array.of((n >>> 8) & 0xff, n & 0xff);
}

function blockLen(blocks: Buffer[]): number {
	let total = 0;
	for (const b of blocks) total += b.length;
	return total;
}
