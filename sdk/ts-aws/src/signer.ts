import { createPublicKey } from "node:crypto";
import {
	KMSClient as AwsKMSClient,
	GetPublicKeyCommand,
	SignCommand,
} from "@aws-sdk/client-kms";

/**
 * The Agent Receipts signing abstraction from ADR-0018, expressed in
 * TypeScript. Implementations sign canonical receipt bytes without ever
 * exposing the private key. `getPublicKey` returns the raw 32-byte Ed25519
 * public key (RFC 8032 §5.1.5) used by verifiers.
 *
 * The core `@obsigna/sdk-ts` package does not yet define this interface; it
 * is declared here so adapters in this package satisfy a single, documented
 * contract (mirrors the Go SDK's `aws` module).
 */
export interface Signer {
	sign(message: Uint8Array): Promise<Uint8Array>;
	getPublicKey(): Promise<Uint8Array>;
}

/** Per-request options threaded through to the underlying KMS call. */
export interface KMSRequestOptions {
	abortSignal?: AbortSignal;
}

export interface KMSSignInput {
	KeyId: string;
	Message: Uint8Array;
	SigningAlgorithm: "ED25519_SHA_512";
	MessageType: "RAW";
}

export interface KMSSignOutput {
	Signature?: Uint8Array;
}

export interface KMSGetPublicKeyInput {
	KeyId: string;
}

export interface KMSGetPublicKeyOutput {
	PublicKey?: Uint8Array;
}

/**
 * The subset of the AWS KMS API that {@link KMSSigner} depends on. The concrete
 * `@aws-sdk/client-kms` client satisfies it via a thin adapter; tests inject a
 * mock. It is deliberately narrow so the dependency surface — and the mock —
 * stay small.
 */
export interface KMSClient {
	sign(
		input: KMSSignInput,
		options?: KMSRequestOptions,
	): Promise<KMSSignOutput>;
	getPublicKey(
		input: KMSGetPublicKeyInput,
		options?: KMSRequestOptions,
	): Promise<KMSGetPublicKeyOutput>;
}

export interface KMSSignerOptions {
	/**
	 * Inject a custom KMS client. The primary use is testing with a mock;
	 * production code omits it and lets {@link KMSSigner} build a client from the
	 * ambient AWS credential chain.
	 */
	client?: KMSClient;
	/** AWS region for the default client. Ignored when `client` is provided. */
	region?: string;
	/**
	 * Per-request deadline (milliseconds) applied to each `kms:Sign` and
	 * `kms:GetPublicKey` call via an `AbortSignal`. Zero/omitted relies on the
	 * AWS SDK's built-in timeouts and retries; do not add a second retry layer.
	 */
	timeoutMs?: number;
}

function defaultClient(region?: string): KMSClient {
	const aws = new AwsKMSClient(region ? { region } : {});
	return {
		sign: (input, options) =>
			aws.send(new SignCommand(input), { abortSignal: options?.abortSignal }),
		getPublicKey: (input, options) =>
			aws.send(new GetPublicKeyCommand(input), {
				abortSignal: options?.abortSignal,
			}),
	};
}

/**
 * Decode the DER-encoded SPKI that `kms:GetPublicKey` returns into the raw
 * 32-byte Ed25519 public key (RFC 8032 §5.1.5). Rejects keys that are not
 * Ed25519 — i.e. a KMS key that is not `ECC_NIST_EDWARDS25519`.
 */
function rawEd25519FromSpki(der: Uint8Array): Uint8Array {
	let key: ReturnType<typeof createPublicKey>;
	try {
		key = createPublicKey({
			key: Buffer.from(der),
			format: "der",
			type: "spki",
		});
	} catch (cause) {
		throw new Error("kms signer: parse SPKI public key", { cause });
	}
	if (key.asymmetricKeyType !== "ed25519") {
		throw new Error(
			`kms signer: key is not Ed25519 (got ${key.asymmetricKeyType}); use an ECC_NIST_EDWARDS25519 KMS key`,
		);
	}
	const jwk = key.export({ format: "jwk" }) as { x?: string };
	if (!jwk.x) {
		throw new Error(
			"kms signer: KMS public key JWK is missing the x coordinate",
		);
	}
	const raw = Buffer.from(jwk.x, "base64url");
	if (raw.length !== 32) {
		throw new Error(`kms signer: public key is ${raw.length} bytes, want 32`);
	}
	return new Uint8Array(raw);
}

/**
 * Signs Agent Receipts with an Ed25519 KMS key. The private key never leaves
 * KMS; this holds only the key identifier, a KMS client, and a cached copy of
 * the public key. Safe for concurrent use — concurrent first-time
 * {@link getPublicKey} calls share a single in-flight fetch.
 */
export class KMSSigner implements Signer {
	readonly #keyId: string;
	readonly #client: KMSClient;
	readonly #timeoutMs: number;

	/** Raw 32-byte Ed25519 public key; undefined until the first fetch. */
	#pubKey: Uint8Array | undefined;
	/** Dedupes concurrent first-time fetches; cleared on settle. */
	#inflight: Promise<Uint8Array> | undefined;

	/**
	 * @param keyId A key ID, key ARN, alias name, or alias ARN — passed to AWS
	 * unchanged. The key must be an `ECC_NIST_EDWARDS25519` (Ed25519) key with
	 * `SIGN_VERIFY` usage. Credentials come from the AWS SDK default credential
	 * provider chain (instance role, IRSA, environment, shared profile).
	 */
	constructor(keyId: string, options: KMSSignerOptions = {}) {
		if (!keyId) {
			throw new Error("kms signer: keyId must not be empty");
		}
		const timeoutMs = options.timeoutMs ?? 0;
		if (timeoutMs < 0) {
			throw new Error(
				`kms signer: timeoutMs must not be negative, got ${timeoutMs}`,
			);
		}
		this.#keyId = keyId;
		this.#timeoutMs = timeoutMs;
		this.#client = options.client ?? defaultClient(options.region);
	}

	/**
	 * Returns the raw Ed25519 signature over `message`, computed inside KMS.
	 *
	 * Calls `kms:Sign` with `SigningAlgorithm=ED25519_SHA_512` and
	 * `MessageType=RAW`, which is standard (pure) Ed25519 per RFC 8032: KMS
	 * performs the SHA-512 hash internally, so the signature verifies against the
	 * public key from {@link getPublicKey}. AWS SDK errors propagate unchanged so
	 * callers can distinguish throttling, access-denied, and key-not-found.
	 */
	async sign(message: Uint8Array): Promise<Uint8Array> {
		const out = await this.#client.sign(
			{
				KeyId: this.#keyId,
				Message: message,
				SigningAlgorithm: "ED25519_SHA_512",
				MessageType: "RAW",
			},
			this.#requestOptions(),
		);
		if (!out.Signature) {
			throw new Error("kms signer: sign: KMS returned no signature");
		}
		return out.Signature;
	}

	/**
	 * Returns the raw 32-byte Ed25519 public key (RFC 8032 §5.1.5).
	 *
	 * The first call fetches via `kms:GetPublicKey`, decodes the DER-encoded SPKI
	 * KMS returns, and caches the raw bytes. Subsequent calls return a fresh copy
	 * of the cached value without contacting AWS. A failed fetch is not cached, so
	 * a later call retries. AWS SDK errors propagate unchanged.
	 */
	async getPublicKey(): Promise<Uint8Array> {
		if (this.#pubKey) {
			return this.#pubKey.slice();
		}
		if (!this.#inflight) {
			this.#inflight = this.#fetchPublicKey().then(
				(key) => {
					this.#pubKey = key;
					this.#inflight = undefined;
					return key;
				},
				(err: unknown) => {
					this.#inflight = undefined;
					throw err;
				},
			);
		}
		const key = await this.#inflight;
		return key.slice();
	}

	async #fetchPublicKey(): Promise<Uint8Array> {
		const out = await this.#client.getPublicKey(
			{ KeyId: this.#keyId },
			this.#requestOptions(),
		);
		if (!out.PublicKey) {
			throw new Error("kms signer: get public key: KMS returned no public key");
		}
		return rawEd25519FromSpki(out.PublicKey);
	}

	#requestOptions(): KMSRequestOptions | undefined {
		return this.#timeoutMs > 0
			? { abortSignal: AbortSignal.timeout(this.#timeoutMs) }
			: undefined;
	}
}
