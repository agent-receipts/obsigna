/**
 * did:key v0.7 generation and resolution (ADR-0007).
 *
 * Implements the normative wire shape from
 * `docs/adr/0007-did-method-strategy.md` ("Implementation spec — did:key
 * v0.7 wire format"), which all SDKs and the hub re-verifier conform to. Do
 * not diverge from the ADR without updating it and
 * `spec/test-vectors/did-key/vectors.json` first.
 */

const PREFIX = "did:key:z";
const MULTICODEC_ED25519 = new Uint8Array([0xed, 0x01]);
const PAYLOAD_LEN = 34; // 2-byte multicodec prefix + 32-byte Ed25519 public key
const PUBLIC_KEY_LEN = 32;

// Bitcoin base58 alphabet: 0, O, I, and l are excluded to avoid visual
// ambiguity, per ADR-0007's resolution algorithm.
const BASE58BTC_ALPHABET =
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58BTC_INDEX = new Map<string, number>(
	Array.from(BASE58BTC_ALPHABET, (ch, i) => [ch, i]),
);

export interface VerificationMethod {
	id: string;
	type: string;
	controller: string;
	publicKeyMultibase: string;
}

export interface Document {
	"@context": string[];
	id: string;
	verificationMethod: VerificationMethod[];
	authentication: string[];
	assertionMethod: string[];
}

function base58btcEncode(data: Uint8Array): string {
	let zeros = 0;
	while (zeros < data.length && data[zeros] === 0) zeros++;

	let n = 0n;
	for (const byte of data) {
		n = n * 256n + BigInt(byte);
	}

	const digits: string[] = [];
	const base = 58n;
	while (n > 0n) {
		const rem = n % base;
		n /= base;
		digits.push(BASE58BTC_ALPHABET.charAt(Number(rem)));
	}
	for (let i = 0; i < zeros; i++) digits.push(BASE58BTC_ALPHABET.charAt(0));
	return digits.reverse().join("");
}

function base58btcDecode(s: string): Uint8Array {
	let zeros = 0;
	while (zeros < s.length && s.charAt(zeros) === BASE58BTC_ALPHABET.charAt(0))
		zeros++;

	let n = 0n;
	const base = 58n;
	for (let i = 0; i < s.length; i++) {
		const idx = BASE58BTC_INDEX.get(s.charAt(i));
		if (idx === undefined) {
			throw new Error(
				`invalid base58btc character ${JSON.stringify(s.charAt(i))} at position ${i}`,
			);
		}
		n = n * base + BigInt(idx);
	}

	const body: number[] = [];
	while (n > 0n) {
		body.push(Number(n % 256n));
		n /= 256n;
	}
	body.reverse();

	return new Uint8Array([...new Array(zeros).fill(0), ...body]);
}

/**
 * Derive the did:key identifier for a raw Ed25519 public key:
 * `did:key:z<base58btc(0xed01 || pubkey)>`.
 *
 * Throws if `publicKey` is not exactly 32 bytes (RFC 8032 §5.1.5).
 */
export function didFromPublicKey(publicKey: Uint8Array): string {
	if (publicKey.length !== PUBLIC_KEY_LEN) {
		throw new Error(
			`did: public key must be ${PUBLIC_KEY_LEN} bytes, got ${publicKey.length}`,
		);
	}
	const payload = new Uint8Array(PAYLOAD_LEN);
	payload.set(MULTICODEC_ED25519, 0);
	payload.set(publicKey, 2);
	return PREFIX + base58btcEncode(payload);
}

/**
 * Resolve a did:key identifier to its DID Document.
 *
 * Implements the ADR-0007 resolution algorithm: resolution is purely a
 * function of the input string — no network access or out-of-band state is
 * consulted. Throws if `did` does not begin with the literal prefix
 * `did:key:z`, contains a base58btc-invalid character, decodes to a payload
 * whose length is not exactly 34 bytes, or carries a multicodec other than
 * `0xed01`.
 */
export function resolveDid(did: string): Document {
	if (!did.startsWith(PREFIX)) {
		throw new Error(
			`did: ${JSON.stringify(did)} does not have the required ${JSON.stringify(PREFIX)} prefix`,
		);
	}

	// zAndPayload is the "z<X>" substring: the multibase prefix character
	// plus the base58btc-encoded payload. It doubles as the verification
	// method fragment and publicKeyMultibase value per the ADR's DID
	// Document shape.
	const zAndPayload = did.slice("did:key:".length);

	let payload: Uint8Array;
	try {
		payload = base58btcDecode(zAndPayload.slice(1));
	} catch (err) {
		throw new Error(
			`did: invalid base58btc encoding: ${err instanceof Error ? err.message : String(err)}`,
		);
	}

	if (payload.length !== PAYLOAD_LEN) {
		throw new Error(
			`did: decoded payload must be ${PAYLOAD_LEN} bytes, got ${payload.length}`,
		);
	}
	if (
		payload[0] !== MULTICODEC_ED25519[0] ||
		payload[1] !== MULTICODEC_ED25519[1]
	) {
		const got = Array.from(payload.slice(0, 2))
			.map((b) => b.toString(16).padStart(2, "0"))
			.join("");
		throw new Error(
			`did: unsupported multicodec ${got}, only ed01 (Ed25519) is accepted`,
		);
	}

	const vmId = `${did}#${zAndPayload}`;
	return {
		"@context": [
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/multikey/v1",
		],
		id: did,
		verificationMethod: [
			{
				id: vmId,
				type: "Multikey",
				controller: did,
				publicKeyMultibase: zAndPayload,
			},
		],
		authentication: [vmId],
		assertionMethod: [vmId],
	};
}
