/**
 * ReceiptChain — serialised, stateful receipt construction (ADR-0020, #488).
 *
 * Client-side chaining requires that receipt N is fully signed and its hash
 * computed before receipt N+1 is constructed. A sequential agent satisfies
 * this automatically, but an agent that fires parallel tool calls would race
 * on the shared chain head (`sequence` + `previous_receipt_hash`), producing
 * colliding sequence numbers or a forked hash link.
 *
 * `ReceiptChain` owns that mutable head. It builds → signs → hashes → links →
 * delivers each receipt through a single internal queue, so concurrent
 * {@link ReceiptChain.emit} calls are sequenced at the receipt layer even when
 * the tool calls that triggered them ran in parallel. Concurrent calls are not
 * an error — they are queued in arrival order — but the first time overlap is
 * detected a warning is emitted (see {@link ReceiptChainOptions.onConcurrentEmit}),
 * since concurrent emission usually means the caller assumed parallel chains
 * are supported. They are not in v1; a future ADR may add forked sub-chains.
 *
 * The head advances (sequence + previous hash) as soon as a receipt is signed
 * and hashed — *before* delivery — so a delivery failure leaves the chain
 * intact and linkable. Pair with a WAL-backed emitter for at-least-once
 * delivery (see ADR-0020 § "At-least-once delivery and the WAL").
 */

import type { Emitter } from "./emitters/types.js";
import { type CreateReceiptInput, createReceipt } from "./receipt/create.js";
import { hashReceipt } from "./receipt/hash.js";
import { signReceipt } from "./receipt/signing.js";
import {
	type AgentReceipt,
	type Chain,
	ISSUER_TYPE_AI_AGENT,
} from "./receipt/types.js";

/**
 * Per-receipt inputs accepted by {@link ReceiptChain.emit}. Identical to
 * {@link CreateReceiptInput} minus `chain`: the chain head (sequence,
 * previous_receipt_hash, chain_id) is owned by the {@link ReceiptChain} and
 * must not be supplied per call. `ReceiptChain` signs in the agent's own
 * process, so an unset `issuer.type` defaults to {@link ISSUER_TYPE_AI_AGENT}.
 * Do not declare `ISSUER_TYPE_AGENT_RECEIPTS_DAEMON` here (spec §4.3.1).
 */
export type ReceiptChainEmitInput = Omit<CreateReceiptInput, "chain">;

/** Configuration for a {@link ReceiptChain}. */
export interface ReceiptChainOptions {
	/** Stable identifier stamped on every receipt's `chain.chain_id`. */
	chainId: string;
	/** Ed25519 private key (PKCS#8 PEM) used to sign each receipt. */
	privateKey: string;
	/** `proof.verificationMethod` recorded on each receipt. */
	verificationMethod: string;
	/** Delivery transport for signed receipts (HTTP, WAL, in-memory, …). */
	emitter: Emitter;
	/**
	 * Sequence number for the first receipt. Defaults to 1; must be a positive
	 * safe integer (>= 1) per the spec. Set when resuming an existing chain
	 * (e.g. a warm serverless instance continuing its chain).
	 */
	startSequence?: number;
	/**
	 * `previous_receipt_hash` to link the first emitted receipt to. Defaults to
	 * `null` (a fresh chain). Set when resuming an existing chain.
	 */
	previousReceiptHash?: string | null;
	/**
	 * Invoked once, the first time overlapping `emit()` calls are detected.
	 * Defaults to `console.warn`. The calls are still serialised — this is a
	 * diagnostic, not an error. Pass a no-op to silence it.
	 */
	onConcurrentEmit?: (message: string) => void;
}

const CONCURRENT_EMIT_MESSAGE =
	"agent-receipts: concurrent emit() detected on a ReceiptChain. Receipt " +
	"construction is serialised at the receipt layer (ADR-0020); parallel tool " +
	"calls cannot build receipts concurrently in v1. The calls are queued in " +
	"arrival order, which may not match the order the tool calls completed.";

/**
 * Stateful, serialised builder for a single hash-linked receipt chain.
 *
 * Construct one per chain (typically one per agent session, or one per
 * serverless invocation — see the ephemeral-compute deployment guide), then
 * call {@link emit} for each action. See the module documentation for the
 * concurrency contract.
 */
export class ReceiptChain {
	readonly #chainId: string;
	readonly #privateKey: string;
	readonly #verificationMethod: string;
	readonly #emitter: Emitter;
	readonly #onConcurrentEmit: (message: string) => void;

	#sequence: number;
	#previousReceiptHash: string | null;

	/** Tail of the serial queue; every emit() chains its work onto this. */
	#tail: Promise<void> = Promise.resolve();
	/** Number of emit() calls currently queued or in flight. */
	#active = 0;
	/** Whether the concurrency warning has already fired (warn at most once). */
	#warned = false;
	/** Set once a terminal receipt is signed; rejects further emit() calls. */
	#closed = false;

	constructor(options: ReceiptChainOptions) {
		if (!options.chainId) {
			throw new Error("ReceiptChain: chainId is required");
		}
		if (!options.privateKey) {
			throw new Error("ReceiptChain: privateKey is required");
		}
		if (!options.verificationMethod) {
			throw new Error("ReceiptChain: verificationMethod is required");
		}
		if (!options.emitter) {
			throw new Error("ReceiptChain: emitter is required");
		}
		// `?? 1` (not `|| 1`) so an explicit 0 is rejected below rather than
		// silently defaulting; the spec requires sequence >= 1.
		const startSequence = options.startSequence ?? 1;
		if (!Number.isSafeInteger(startSequence) || startSequence < 1) {
			throw new Error(
				"ReceiptChain: startSequence must be a positive safe integer (>= 1)",
			);
		}
		this.#chainId = options.chainId;
		this.#privateKey = options.privateKey;
		this.#verificationMethod = options.verificationMethod;
		this.#emitter = options.emitter;
		this.#onConcurrentEmit =
			options.onConcurrentEmit ?? ((message) => console.warn(message));
		this.#sequence = startSequence;
		this.#previousReceiptHash = options.previousReceiptHash ?? null;
	}

	/** The `chain_id` stamped on every receipt this chain emits. */
	get chainId(): string {
		return this.#chainId;
	}

	/** Sequence number the next emitted receipt will carry. */
	get nextSequence(): number {
		return this.#sequence;
	}

	/** Hash the next receipt will link to (`null` before the first emit). */
	get previousReceiptHash(): string | null {
		return this.#previousReceiptHash;
	}

	/**
	 * Build, sign, hash-link, and deliver one receipt, resolving with the
	 * signed {@link AgentReceipt}. Calls are serialised: receipt N is fully
	 * constructed and its head committed before receipt N+1 begins, even when
	 * `emit()` is invoked concurrently.
	 *
	 * Rejects (after the head has advanced) if the underlying emitter rejects:
	 * the receipt was signed and the chain head moved on, so use a WAL-backed
	 * emitter when delivery durability matters.
	 *
	 * Emitting a receipt with `terminal: true` closes the chain: any later
	 * `emit()` rejects rather than linking a receipt after the terminal one
	 * (which {@link verifyChain} would reject as a protocol violation).
	 */
	emit(input: ReceiptChainEmitInput): Promise<AgentReceipt> {
		if (this.#active > 0 && !this.#warned) {
			this.#warned = true;
			this.#onConcurrentEmit(CONCURRENT_EMIT_MESSAGE);
		}
		this.#active += 1;
		const run = this.#tail.then(() => this.#build(input));
		// Keep the queue draining regardless of this run's outcome so one
		// failed delivery cannot wedge every later emit().
		this.#tail = run.then(
			() => undefined,
			() => undefined,
		);
		return run.finally(() => {
			this.#active -= 1;
		});
	}

	async #build(input: ReceiptChainEmitInput): Promise<AgentReceipt> {
		if (this.#closed) {
			throw new Error(
				"ReceiptChain: terminal receipt already emitted; chain is closed",
			);
		}
		const chain: Chain = {
			sequence: this.#sequence,
			previous_receipt_hash: this.#previousReceiptHash,
			chain_id: this.#chainId,
		};
		const issuer = input.issuer.type
			? input.issuer
			: { ...input.issuer, type: ISSUER_TYPE_AI_AGENT };
		const unsigned = createReceipt({ ...input, issuer, chain });
		const signed = signReceipt(
			unsigned,
			this.#privateKey,
			this.#verificationMethod,
		);
		// Advance the head from the just-signed receipt *before* delivery so a
		// delivery failure cannot fork or stall the chain (ADR-0020 WAL model).
		this.#previousReceiptHash = hashReceipt(signed);
		this.#sequence += 1;
		// A terminal receipt closes the chain: nothing may link after it.
		if (input.terminal) {
			this.#closed = true;
		}
		await this.#emitter.emit(signed);
		return signed;
	}
}
