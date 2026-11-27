import { describe, expect, it, vi } from "vitest";
import { InMemoryEmitter } from "./emitters/in-memory.js";
import type { Emitter } from "./emitters/types.js";
import { verifyChain } from "./receipt/chain.js";
import { hashReceipt } from "./receipt/hash.js";
import { generateKeyPair } from "./receipt/signing.js";
import { type AgentReceipt, ISSUER_TYPE_AI_AGENT } from "./receipt/types.js";
import {
	ReceiptChain,
	type ReceiptChainEmitInput,
	type ReceiptChainOptions,
} from "./receipt-chain.js";

const keys = generateKeyPair();
const VERIFICATION_METHOD = "did:agent:test#key-1";

function makeInput(resource: string): ReceiptChainEmitInput {
	return {
		issuer: { id: "did:agent:test" },
		principal: { id: "did:user:alice" },
		action: {
			type: "filesystem.file.read",
			risk_level: "low",
			target: { system: "local", resource },
		},
		outcome: { status: "success" },
	};
}

function makeChain(overrides: Partial<ReceiptChainOptions> = {}): ReceiptChain {
	return new ReceiptChain({
		chainId: "chain_test",
		privateKey: keys.privateKey,
		verificationMethod: VERIFICATION_METHOD,
		emitter: new InMemoryEmitter(),
		...overrides,
	});
}

/** Emitter whose emit() blocks until `release()` is called. */
class GateEmitter implements Emitter {
	readonly inner = new InMemoryEmitter();
	#gate: Promise<void>;
	#open!: () => void;

	constructor() {
		this.#gate = new Promise((resolve) => {
			this.#open = resolve;
		});
	}

	release(): void {
		this.#open();
	}

	async emit(receipt: AgentReceipt): Promise<void> {
		await this.#gate;
		await this.inner.emit(receipt);
	}
}

describe("ReceiptChain", () => {
	it("requires the core options", () => {
		const base = {
			chainId: "c",
			privateKey: keys.privateKey,
			verificationMethod: VERIFICATION_METHOD,
			emitter: new InMemoryEmitter(),
		};
		expect(() => new ReceiptChain({ ...base, chainId: "" })).toThrow(/chainId/);
		expect(() => new ReceiptChain({ ...base, privateKey: "" })).toThrow(
			/privateKey/,
		);
		expect(() => new ReceiptChain({ ...base, verificationMethod: "" })).toThrow(
			/verificationMethod/,
		);
		expect(
			() =>
				// @ts-expect-error emitter is required: this also asserts the
				// public type rejects a missing emitter, not just the runtime guard.
				new ReceiptChain({ ...base, emitter: undefined }),
		).toThrow(/emitter/);
		for (const startSequence of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
			expect(() => new ReceiptChain({ ...base, startSequence })).toThrow(
				/startSequence/,
			);
		}
	});

	it("builds, signs, links, and delivers sequential receipts", async () => {
		const emitter = new InMemoryEmitter();
		const chain = makeChain({ emitter });

		expect(chain.nextSequence).toBe(1);
		expect(chain.previousReceiptHash).toBeNull();

		const r1 = await chain.emit(makeInput("/a"));
		const r2 = await chain.emit(makeInput("/b"));
		const r3 = await chain.emit(makeInput("/c"));

		// Sequence increments, hash links thread through the signed receipts.
		expect(r1.credentialSubject.chain.sequence).toBe(1);
		expect(r1.credentialSubject.chain.previous_receipt_hash).toBeNull();
		expect(r2.credentialSubject.chain.sequence).toBe(2);
		expect(r2.credentialSubject.chain.previous_receipt_hash).toBe(
			hashReceipt(r1),
		);
		expect(r3.credentialSubject.chain.previous_receipt_hash).toBe(
			hashReceipt(r2),
		);

		// Head accessors reflect the next receipt to come.
		expect(chain.nextSequence).toBe(4);
		expect(chain.previousReceiptHash).toBe(hashReceipt(r3));

		const result = verifyChain([...emitter.received], keys.publicKey);
		expect(result.valid).toBe(true);
		expect(result.length).toBe(3);
	});

	it("does not warn when calls are awaited sequentially", async () => {
		const onConcurrentEmit = vi.fn();
		const chain = makeChain({ onConcurrentEmit });

		await chain.emit(makeInput("/a"));
		await chain.emit(makeInput("/b"));

		expect(onConcurrentEmit).not.toHaveBeenCalled();
	});

	it("serialises concurrent emit() calls and warns once", async () => {
		const onConcurrentEmit = vi.fn();
		const gate = new GateEmitter();
		const chain = makeChain({ emitter: gate, onConcurrentEmit });

		// Fire five emits without awaiting — they overlap from the chain's view.
		const pending = [
			chain.emit(makeInput("/0")),
			chain.emit(makeInput("/1")),
			chain.emit(makeInput("/2")),
			chain.emit(makeInput("/3")),
			chain.emit(makeInput("/4")),
		];

		// Overlap is detected synchronously, before any work runs.
		expect(onConcurrentEmit).toHaveBeenCalledTimes(1);
		expect(onConcurrentEmit.mock.calls[0]?.[0]).toMatch(/concurrent emit/i);

		gate.release();
		await Promise.all(pending);

		// Delivered in arrival order, with a contiguous, valid chain.
		const received = [...gate.inner.received];
		expect(received.map((r) => r.credentialSubject.chain.sequence)).toEqual([
			1, 2, 3, 4, 5,
		]);
		expect(verifyChain(received, keys.publicKey).valid).toBe(true);
	});

	it("advances the head before delivery so a failed emit does not fork the chain", async () => {
		let failNext = true;
		const inner = new InMemoryEmitter();
		const emitter: Emitter = {
			async emit(receipt) {
				if (failNext) {
					failNext = false;
					throw new Error("collector unreachable");
				}
				await inner.emit(receipt);
			},
		};
		const chain = makeChain({ emitter });

		await expect(chain.emit(makeInput("/a"))).rejects.toThrow(
			/collector unreachable/,
		);
		// Head advanced even though delivery failed.
		expect(chain.nextSequence).toBe(2);

		const r2 = await chain.emit(makeInput("/b"));
		expect(r2.credentialSubject.chain.sequence).toBe(2);
		// r2 links to the signed-but-undelivered r1, not back to null.
		expect(r2.credentialSubject.chain.previous_receipt_hash).not.toBeNull();
	});

	it("rejects emit after a terminal receipt", async () => {
		const chain = makeChain();
		await chain.emit({ ...makeInput("/done"), terminal: true });
		await expect(chain.emit(makeInput("/after"))).rejects.toThrow(/closed/i);
	});

	it("resumes an existing chain from a supplied head", async () => {
		const emitter = new InMemoryEmitter();
		const chain = makeChain({
			emitter,
			startSequence: 7,
			previousReceiptHash: "sha256:deadbeef",
		});

		const r = await chain.emit(makeInput("/a"));
		expect(r.credentialSubject.chain.sequence).toBe(7);
		expect(r.credentialSubject.chain.previous_receipt_hash).toBe(
			"sha256:deadbeef",
		);
		expect(chain.nextSequence).toBe(8);
	});

	it("defaults issuer.type to AIAgent and keeps an explicit value", async () => {
		const chain = makeChain();
		const input = makeInput("/a");

		const r = await chain.emit(input);
		expect(ISSUER_TYPE_AI_AGENT).toBe("AIAgent");
		expect(r.issuer.type).toBe(ISSUER_TYPE_AI_AGENT);
		expect(input.issuer.type).toBeUndefined();

		const custom = makeInput("/b");
		custom.issuer.type = "CustomAgent";
		const r2 = await chain.emit(custom);
		expect(r2.issuer.type).toBe("CustomAgent");

		const empty = makeInput("/c");
		empty.issuer.type = "";
		expect((await chain.emit(empty)).issuer.type).toBe(ISSUER_TYPE_AI_AGENT);
	});
});
