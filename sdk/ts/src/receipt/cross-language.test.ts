import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { verifyChain } from "./chain.js";
import { canonicalize, hashReceipt, sha256 } from "./hash.js";
import { generateKeyPair, signReceipt, verifyReceipt } from "./signing.js";
import type { AgentReceipt, UnsignedAgentReceipt } from "./types.js";

interface TestVectors {
	keys: { publicKey: string; privateKey: string };
	canonicalization: {
		simpleInput: unknown;
		simpleExpected: string;
		receiptInput: unknown;
		receiptExpected: string;
	};
	hashing: {
		simpleInput: string;
		simpleExpected: string;
		receiptExpected: string;
	};
	signing: {
		unsigned: unknown;
		signed: AgentReceipt;
		verificationMethod: string;
	};
}

interface V020Vectors {
	version: string;
	keys: { publicKey: string; privateKey: string };
	responseHash: {
		rawResponse: Record<string, unknown>;
		redactedResponse: Record<string, unknown>;
		expectedHash: string;
	};
	terminalChain: {
		receipts: AgentReceipt[];
		expectedValid: boolean;
		expectedValidWithRequireTerminal: boolean;
	};
	parametersDisclosureReceipt: {
		description: string;
		receipt: AgentReceipt;
		expectedReceiptHash: string;
		expectedValid: boolean;
	};
}

const currentDir = dirname(fileURLToPath(import.meta.url));

function loadGoVectors(): TestVectors {
	const path = resolve(
		currentDir,
		"../../../../cross-sdk-tests/go_vectors.json",
	);
	return JSON.parse(readFileSync(path, "utf-8"));
}

function loadPyVectors(): TestVectors {
	const path = resolve(
		currentDir,
		"../../../../cross-sdk-tests/py_vectors.json",
	);
	return JSON.parse(readFileSync(path, "utf-8"));
}

interface MalformedVectors {
	description: string;
	keys: { publicKey: string; privateKey: string };
	receipts: Array<{ name: string; description: string; receipt: AgentReceipt }>;
	chains: Array<{
		name: string;
		description: string;
		receipts: AgentReceipt[];
	}>;
}

function loadMalformedVectors(): MalformedVectors {
	const path = resolve(
		currentDir,
		"../../../../cross-sdk-tests/malformed_vectors.json",
	);
	return JSON.parse(readFileSync(path, "utf-8"));
}

function safeVerify(receipt: AgentReceipt, publicKey: string): boolean {
	try {
		return verifyReceipt(receipt, publicKey);
	} catch {
		return false;
	}
}

function safeVerifyChain(receipts: AgentReceipt[], publicKey: string): boolean {
	try {
		return verifyChain(receipts, publicKey).valid === true;
	} catch {
		return false;
	}
}

function loadV020Vectors(): V020Vectors {
	const path = resolve(
		currentDir,
		"../../../../cross-sdk-tests/v020_vectors.json",
	);
	return JSON.parse(readFileSync(path, "utf-8"));
}

interface V030VectorEntry {
	description: string;
	receipt: AgentReceipt;
	expectedReceiptHash: string;
	expectedValid: boolean;
}

interface V030Vectors {
	version: string;
	keys: { publicKey: string; privateKey: string };
	parametersDisclosureEnvelopeReceipt: V030VectorEntry;
	peerCredentialEmitterMetadataReceipt: V030VectorEntry;
	peerCredentialRootReceipt: V030VectorEntry;
}

function loadV030Vectors(): V030Vectors {
	const path = resolve(
		currentDir,
		"../../../../cross-sdk-tests/v030_vectors.json",
	);
	return JSON.parse(readFileSync(path, "utf-8"));
}

describe("cross-language: Go SDK", () => {
	describe("canonicalization matches Go", () => {
		it("simple object", () => {
			const vectors = loadGoVectors();
			expect(canonicalize(vectors.canonicalization.simpleInput)).toBe(
				vectors.canonicalization.simpleExpected,
			);
		});

		it("unsigned receipt", () => {
			const vectors = loadGoVectors();
			expect(canonicalize(vectors.canonicalization.receiptInput)).toBe(
				vectors.canonicalization.receiptExpected,
			);
		});
	});

	describe("SHA-256 hashing matches Go", () => {
		it("simple string", () => {
			const vectors = loadGoVectors();
			expect(sha256(vectors.hashing.simpleInput)).toBe(
				vectors.hashing.simpleExpected,
			);
		});

		it("receipt hash", () => {
			const vectors = loadGoVectors();
			expect(hashReceipt(vectors.signing.signed)).toBe(
				vectors.hashing.receiptExpected,
			);
		});
	});

	describe("Go-signed receipt verification", () => {
		it("verifies in TypeScript", () => {
			const vectors = loadGoVectors();
			expect(
				verifyReceipt(vectors.signing.signed, vectors.keys.publicKey),
			).toBe(true);
		});

		it("fails with wrong key", () => {
			const vectors = loadGoVectors();
			const other = generateKeyPair();
			expect(verifyReceipt(vectors.signing.signed, other.publicKey)).toBe(
				false,
			);
		});

		it("fails when tampered", () => {
			const vectors = loadGoVectors();
			const tampered: AgentReceipt = {
				...vectors.signing.signed,
				credentialSubject: {
					...vectors.signing.signed.credentialSubject,
					action: {
						...vectors.signing.signed.credentialSubject.action,
						type: "filesystem.file.delete",
					},
				},
			};
			expect(verifyReceipt(tampered, vectors.keys.publicKey)).toBe(false);
		});
	});
});

describe("cross-language: Python SDK", () => {
	describe("canonicalization matches Python", () => {
		it("simple object", () => {
			const vectors = loadPyVectors();
			expect(canonicalize(vectors.canonicalization.simpleInput)).toBe(
				vectors.canonicalization.simpleExpected,
			);
		});

		it("unsigned receipt", () => {
			const vectors = loadPyVectors();
			expect(canonicalize(vectors.canonicalization.receiptInput)).toBe(
				vectors.canonicalization.receiptExpected,
			);
		});
	});

	describe("SHA-256 hashing matches Python", () => {
		it("simple string", () => {
			const vectors = loadPyVectors();
			expect(sha256(vectors.hashing.simpleInput)).toBe(
				vectors.hashing.simpleExpected,
			);
		});

		it("receipt hash", () => {
			const vectors = loadPyVectors();
			expect(hashReceipt(vectors.signing.signed)).toBe(
				vectors.hashing.receiptExpected,
			);
		});
	});

	describe("Python-signed receipt verification", () => {
		it("verifies in TypeScript", () => {
			const vectors = loadPyVectors();
			expect(
				verifyReceipt(vectors.signing.signed, vectors.keys.publicKey),
			).toBe(true);
		});

		it("fails with wrong key", () => {
			const vectors = loadPyVectors();
			const other = generateKeyPair();
			expect(verifyReceipt(vectors.signing.signed, other.publicKey)).toBe(
				false,
			);
		});

		it("fails when tampered", () => {
			const vectors = loadPyVectors();
			const tampered: AgentReceipt = {
				...vectors.signing.signed,
				credentialSubject: {
					...vectors.signing.signed.credentialSubject,
					action: {
						...vectors.signing.signed.credentialSubject.action,
						type: "filesystem.file.delete",
					},
				},
			};
			expect(verifyReceipt(tampered, vectors.keys.publicKey)).toBe(false);
		});
	});
});

describe("cross-language: v0.2.0 vectors", () => {
	it("response_hash canonicalization matches Go", () => {
		const v = loadV020Vectors();
		expect(sha256(canonicalize(v.responseHash.redactedResponse))).toBe(
			v.responseHash.expectedHash,
		);
	});

	it("Go-signed terminal chain verifies in TypeScript", () => {
		const v = loadV020Vectors();
		const result = verifyChain(v.terminalChain.receipts, v.keys.publicKey);
		expect(result.valid).toBe(true);
	});

	it("Go-signed terminal chain passes requireTerminal in TypeScript", () => {
		const v = loadV020Vectors();
		const result = verifyChain(v.terminalChain.receipts, v.keys.publicKey, {
			requireTerminal: true,
		});
		expect(result.valid).toBe(true);
	});

	it("last receipt in Go chain has terminal: true", () => {
		const v = loadV020Vectors();
		const last = v.terminalChain.receipts.at(-1);
		expect(last?.credentialSubject.chain.terminal).toBe(true);
	});

	it("Go-signed parameters_disclosure receipt verifies in TypeScript", () => {
		const v = loadV020Vectors();
		expect(
			verifyReceipt(v.parametersDisclosureReceipt.receipt, v.keys.publicKey),
		).toBe(true);
	});

	it("parameters_disclosure receipt hash matches Go", () => {
		const v = loadV020Vectors();
		expect(hashReceipt(v.parametersDisclosureReceipt.receipt)).toBe(
			v.parametersDisclosureReceipt.expectedReceiptHash,
		);
	});
});

describe("cross-language: malformed corpus", () => {
	it("the corpus contains receipt cases", () => {
		const v = loadMalformedVectors();
		expect(v.receipts.length).toBeGreaterThan(0);
	});

	it("rejects every malformed receipt case", () => {
		const v = loadMalformedVectors();
		const accepted = v.receipts
			.filter(({ receipt }) => safeVerify(receipt, v.keys.publicKey))
			.map(({ name }) => name);
		expect(accepted).toEqual([]);
	});

	it("rejects every malformed chain case", () => {
		const v = loadMalformedVectors();
		const accepted = v.chains
			.filter(({ receipts }) => safeVerifyChain(receipts, v.keys.publicKey))
			.map(({ name }) => name);
		expect(accepted).toEqual([]);
	});
});

// Cross-SDK byte-identical reproduction of the v0.3.0 vectors pinned in
// cross-sdk-tests/v030_vectors.json (PR #499). The TS SDK MUST hash these
// receipts to the same SHA-256 digests as the Go and Python SDKs; divergence
// indicates a wire-format bug (most likely JCS canonicalisation or
// ADR-0009 Rule 2 absent-vs-null normalisation on the new optional fields).
describe("cross-language: v0.3.0 vectors", () => {
	it("parameters_disclosure envelope receipt hash matches pin", () => {
		const v = loadV030Vectors();
		expect(hashReceipt(v.parametersDisclosureEnvelopeReceipt.receipt)).toBe(
			v.parametersDisclosureEnvelopeReceipt.expectedReceiptHash,
		);
	});

	it("parameters_disclosure envelope receipt verifies with shared key", () => {
		const v = loadV030Vectors();
		expect(
			verifyReceipt(
				v.parametersDisclosureEnvelopeReceipt.receipt,
				v.keys.publicKey,
			),
		).toBe(true);
	});

	it("peer_credential + emitter_metadata receipt hash matches pin", () => {
		const v = loadV030Vectors();
		expect(hashReceipt(v.peerCredentialEmitterMetadataReceipt.receipt)).toBe(
			v.peerCredentialEmitterMetadataReceipt.expectedReceiptHash,
		);
	});

	it("peer_credential + emitter_metadata receipt verifies with shared key", () => {
		const v = loadV030Vectors();
		expect(
			verifyReceipt(
				v.peerCredentialEmitterMetadataReceipt.receipt,
				v.keys.publicKey,
			),
		).toBe(true);
	});

	it("peer_credential root receipt (uid=0) hash matches pin", () => {
		const v = loadV030Vectors();
		expect(hashReceipt(v.peerCredentialRootReceipt.receipt)).toBe(
			v.peerCredentialRootReceipt.expectedReceiptHash,
		);
	});

	it("peer_credential root receipt (uid=0) verifies with shared key", () => {
		const v = loadV030Vectors();
		expect(
			verifyReceipt(v.peerCredentialRootReceipt.receipt, v.keys.publicKey),
		).toBe(true);
	});
});

interface V040Vectors {
	version: string;
	keys: { publicKey: string; privateKey: string };
	idempotencyKeyReceipt: {
		idempotencyKey: string;
		receipt: AgentReceipt;
		expectedReceiptHash: string;
		expectedValid: boolean;
	};
	duplicateIdempotencyChain: {
		duplicateKey: string;
		receipts: AgentReceipt[];
		expectedValid: boolean;
		expectedWarningCount: number;
	};
}

function loadV040Vectors(): V040Vectors {
	const path = resolve(
		currentDir,
		"../../../../cross-sdk-tests/v040_vectors.json",
	);
	return JSON.parse(readFileSync(path, "utf-8"));
}

// Cross-SDK reproduction of the v0.4.0 vectors pinned in
// cross-sdk-tests/v040_vectors.json (#480). The TS SDK MUST hash the
// idempotency_key receipt to the same digest as Go and Python, and its chain
// verifier MUST flag the shared-key chain as valid with exactly one warning.
describe("cross-language: v0.4.0 vectors", () => {
	it("idempotency_key receipt hash matches pin", () => {
		const v = loadV040Vectors();
		expect(hashReceipt(v.idempotencyKeyReceipt.receipt)).toBe(
			v.idempotencyKeyReceipt.expectedReceiptHash,
		);
	});

	it("idempotency_key receipt verifies with shared key", () => {
		const v = loadV040Vectors();
		expect(
			verifyReceipt(v.idempotencyKeyReceipt.receipt, v.keys.publicKey),
		).toBe(true);
	});

	it("duplicate-idempotency_key chain is valid with one warning", () => {
		const v = loadV040Vectors();
		const result = verifyChain(
			v.duplicateIdempotencyChain.receipts,
			v.keys.publicKey,
		);
		expect(result.valid).toBe(v.duplicateIdempotencyChain.expectedValid);
		expect(result.warnings ?? []).toHaveLength(
			v.duplicateIdempotencyChain.expectedWarningCount,
		);
		expect(result.warnings?.[0]).toContain(
			v.duplicateIdempotencyChain.duplicateKey,
		);
	});
});

interface V050ReceiptSection {
	receipt: AgentReceipt;
	expectedReceiptHash: string;
	expectedValid: boolean;
}

interface V050Vectors {
	version: string;
	keys: { publicKey: string; privateKey: string };
	runtimeReceipt: V050ReceiptSection;
	extendedRuntimeReceipt: V050ReceiptSection;
	rootAgentReceipt: V050ReceiptSection;
}

function loadV050Vectors(): V050Vectors {
	const path = resolve(
		currentDir,
		"../../../../cross-sdk-tests/v050_vectors.json",
	);
	return JSON.parse(readFileSync(path, "utf-8"));
}

// Cross-SDK reproduction of the v0.5.0 vectors pinned in
// cross-sdk-tests/v050_vectors.json (issuer.runtime open sub-object, ADR-0026).
// The TS SDK MUST hash both the runtime-bearing and root-agent receipts to the
// same digests as Go and Python, proving the nested runtime object canonicalises
// identically.
describe("cross-language: v0.5.0 vectors", () => {
	it("runtime receipt hash matches pin", () => {
		const v = loadV050Vectors();
		expect(hashReceipt(v.runtimeReceipt.receipt)).toBe(
			v.runtimeReceipt.expectedReceiptHash,
		);
	});

	it("runtime receipt verifies with shared key", () => {
		const v = loadV050Vectors();
		expect(verifyReceipt(v.runtimeReceipt.receipt, v.keys.publicKey)).toBe(
			true,
		);
	});

	it("runtime members round-trip", () => {
		const v = loadV050Vectors();
		expect(v.runtimeReceipt.receipt.issuer.runtime?.agent_id).toBe(
			"a3e49db54342a92d4",
		);
		expect(v.runtimeReceipt.receipt.issuer.runtime?.agent_type).toBe(
			"general-purpose",
		);
	});

	it("extended runtime preserves unknown key and hash matches", () => {
		// Open-container gate: a runtime key the SDK does not model (trace_id)
		// must survive and hash to the pinned digest (ADR-0026). The Runtime
		// index signature keeps it; canonicalize re-emits it.
		const v = loadV050Vectors();
		expect(v.extendedRuntimeReceipt.receipt.issuer.runtime?.trace_id).toBe(
			"4bf92f3577b34da6a3ce929d0e0e4736",
		);
		expect(hashReceipt(v.extendedRuntimeReceipt.receipt)).toBe(
			v.extendedRuntimeReceipt.expectedReceiptHash,
		);
	});

	it("root-agent receipt hash matches pin and omits runtime", () => {
		const v = loadV050Vectors();
		expect(hashReceipt(v.rootAgentReceipt.receipt)).toBe(
			v.rootAgentReceipt.expectedReceiptHash,
		);
		expect(v.rootAgentReceipt.receipt.issuer.runtime).toBeUndefined();
	});
});

interface TsRichVectors {
	keys: { publicKey: string; privateKey: string };
	unsigned: UnsignedAgentReceipt;
	signed: AgentReceipt;
	verificationMethod: string;
}

function loadTsRichVectors(): TsRichVectors {
	const path = resolve(
		currentDir,
		"../../../../cross-sdk-tests/ts_rich_vectors.json",
	);
	return JSON.parse(readFileSync(path, "utf-8"));
}

// A receipt with action.target and parameters_hash, signed by the TypeScript
// SDK. Python signs the same unsigned receipt in py_vectors.json (signingRich),
// so the two proofValues must match.
describe("rich receipt signed by TypeScript", () => {
	it("verifies in TypeScript", () => {
		const v = loadTsRichVectors();
		expect(verifyReceipt(v.signed, v.keys.publicKey)).toBe(true);
	});

	it("re-signing the unsigned receipt reproduces the committed proofValue", () => {
		const v = loadTsRichVectors();
		const resigned = signReceipt(
			v.unsigned,
			v.keys.privateKey,
			v.verificationMethod,
		);
		expect(resigned.proof.proofValue).toBe(v.signed.proof.proofValue);
	});

	it("has the same proofValue as the Python SDK's signature", () => {
		const v = loadTsRichVectors();
		const py = JSON.parse(
			readFileSync(
				resolve(currentDir, "../../../../cross-sdk-tests/py_vectors.json"),
				"utf-8",
			),
		) as { signingRich: { signed: AgentReceipt } };
		expect(v.signed.proof.proofValue).toBe(
			py.signingRich.signed.proof.proofValue,
		);
	});
});
