import { canonicalize, hashReceipt, sha256 } from "./hash.js";
import { verifyRotationEvent } from "./rotation.js";
import { verifyReceipt } from "./signing.js";
import type { AgentReceipt } from "./types.js";

/**
 * Scan the chain for non-empty `action.idempotency_key` values that appear on
 * more than one receipt and return a human-readable advisory for each such key
 * (spec §7.3.6). Retries are legitimate, so these are warnings, not failures.
 * Order is deterministic: warnings follow the first-seen order of each
 * duplicated key, and the indices within each warning are in chain order.
 * Receipts that omit the key never contribute. Returns undefined when there
 * are no duplicates so the optional `warnings` field stays absent.
 */
function duplicateIdempotencyWarnings(
	receipts: AgentReceipt[],
): string[] | undefined {
	const indices = new Map<string, number[]>();
	const order: string[] = [];
	receipts.forEach((r, i) => {
		const key = r.credentialSubject.action.idempotency_key;
		if (!key) return;
		const existing = indices.get(key);
		if (existing === undefined) {
			order.push(key);
			indices.set(key, [i]);
		} else {
			existing.push(i);
		}
	});
	const warnings: string[] = [];
	for (const key of order) {
		const idx = indices.get(key);
		if (idx === undefined || idx.length < 2) continue;
		warnings.push(
			`duplicate idempotency_key ${JSON.stringify(key)} on receipts at indices ${idx.join(", ")} (retries are legitimate; review for double-counting)`,
		);
	}
	return warnings.length > 0 ? warnings : undefined;
}

/**
 * Classify chain termination based purely on what the receipts claim on the
 * wire (independent of verification result). See spec §7.3.3.
 */
function classifyTerminationStatus(
	receipts: AgentReceipt[],
): ChainTerminationStatus {
	const last = receipts[receipts.length - 1];
	if (!last || last.credentialSubject.chain.terminal !== true) {
		return "unknown";
	}
	return last.credentialSubject.chain.status === "interrupted"
		? "interrupted"
		: "complete";
}

/**
 * Detect an incomplete tool roundtrip: a chain whose final, non-terminal
 * receipt records `outcome.status: "pending"` — a tool call that was logged
 * but whose result receipt never arrived (e.g. the emitter crashed between
 * the call and the result, or the WAL never drained).
 *
 * Reported as a distinct advisory signal (ADR-0019 §O3, retained by
 * ADR-0020) rather than folded into the generic chain-break path: the chain
 * may still verify cryptographically. A terminal receipt closes the chain
 * deliberately, so a `pending` terminal receipt is not flagged here.
 */
function isIncompleteToolRoundtrip(receipts: AgentReceipt[]): boolean {
	const last = receipts[receipts.length - 1];
	if (!last || last.credentialSubject.chain.terminal === true) {
		return false;
	}
	return last.credentialSubject.outcome.status === "pending";
}

/**
 * Result of verifying a single receipt in a chain.
 */
export interface ReceiptVerification {
	/** Index of the receipt in the chain. */
	index: number;
	/** Receipt id. */
	receiptId: string;
	/** Whether the Ed25519 signature is valid. */
	signatureValid: boolean;
	/** Whether the previous_receipt_hash matches the prior receipt's hash. */
	hashLinkValid: boolean;
	/** Whether the sequence number is correct. */
	sequenceValid: boolean;
}

/**
 * Termination status of a chain (verifier-derived).
 *
 * - `"complete"` — final receipt has `chain.terminal: true` and either
 *   `chain.status: "complete"` or no `chain.status`.
 * - `"interrupted"` — final receipt has `chain.terminal: true` and
 *   `chain.status: "interrupted"`.
 * - `"unknown"` — chain has no terminal receipt. Cannot distinguish a
 *   crashed issuer from a truncated tail without external witness.
 *
 * See spec §7.3.3.
 */
export type ChainTerminationStatus = "complete" | "interrupted" | "unknown";

/**
 * Result of verifying an entire chain.
 */
export interface ChainVerification {
	/** Whether the entire chain is valid. */
	valid: boolean;
	/** Number of receipts verified. */
	length: number;
	/** Verifier-derived termination status. Reported regardless of validity —
	 *  describes what the chain claims about its own termination. */
	status: ChainTerminationStatus;
	/** Per-receipt verification results. */
	receipts: ReceiptVerification[];
	/** Index of the first broken receipt, or -1 if chain is valid. */
	brokenAt: number;
	/**
	 * True when the final non-terminal receipt has `outcome.status: "pending"`
	 * — a tool call whose result receipt never arrived (ADR-0019 §O3, retained
	 * by ADR-0020). Advisory: it does not by itself set `valid: false`, since
	 * the chain may verify cryptographically. Distinct from a generic chain
	 * break so callers can surface "incomplete tool roundtrip" specifically.
	 */
	incompleteToolRoundtrip: boolean;
	/** Non-empty when one or more receipts carry response_hash but no response body was supplied. */
	responseHashNote?: string;
	/** Non-empty when verification failed with a descriptive message. */
	error?: string;
	/**
	 * Non-fatal advisories about the verified chain, populated independently of
	 * `valid` — a warning never changes the verification result. Currently
	 * surfaces duplicate `action.idempotency_key` values (spec §7.3.6): retries
	 * are legitimate, so duplicates are flagged for auditor review rather than
	 * treated as failures. Omitted when there are no warnings.
	 */
	warnings?: string[];
}

/**
 * Optional parameters for verifyChain.
 * Omitting any parameter preserves v0.1 behaviour.
 */
export interface ChainVerifyOptions {
	/**
	 * When set, verification fails if the observed chain length does not equal
	 * this value. Provides out-of-band truncation detection.
	 */
	expectedLength?: number;
	/**
	 * When set, verification fails if the SHA-256 hash of the last observed
	 * receipt does not equal this value. Provides out-of-band truncation
	 * detection when the caller knows the expected final receipt hash.
	 */
	expectedFinalHash?: string;
	/**
	 * When true, verification fails if the last observed receipt does not have
	 * chain.terminal: true. Use for chains that must close cleanly.
	 */
	requireTerminal?: boolean;
	/**
	 * Maps receipt id → pre-redacted response body. When a receipt carries
	 * outcome.response_hash and its id appears here, verifyChain recomputes the
	 * hash and fails on mismatch. When the entry is absent an informational note
	 * is emitted instead. An absent body is not a verification failure.
	 */
	responseBodies?: Record<string, unknown>;
}

/**
 * Verify a chain of signed receipts.
 *
 * Checks for each receipt (in execution order):
 * 1. Ed25519 signature validity
 * 2. Hash linkage: previous_receipt_hash matches SHA-256 of prior receipt
 * 3. Sequence numbers are strictly incrementing
 * 4. Chain identifier binding: all receipts MUST share the same
 *    chain.chain_id as the first receipt (unconditional, spec §7.3.4)
 * 5. Receipt-after-terminal: if any receipt has chain.terminal: true, no
 *    subsequent receipt may reference it (unconditional, spec §7.3.2)
 *
 * Chain verification does NOT detect tail truncation by default — dropping the
 * last N receipts from a chain still produces valid: true. To detect truncation:
 * - Supply expectedLength and/or expectedFinalHash (out-of-band witness)
 * - Supply requireTerminal for chains that must close with chain.terminal: true
 *
 * Chains that are open-ended and have no external witness cannot be detected as
 * truncated. See spec §7.3.1 for the full treatment.
 */
export function verifyChain(
	receipts: AgentReceipt[],
	publicKey: string,
	options?: ChainVerifyOptions,
): ChainVerification {
	if (receipts.length === 0) {
		if (options?.expectedLength !== undefined && options.expectedLength !== 0) {
			return {
				valid: false,
				length: 0,
				status: "unknown",
				receipts: [],
				brokenAt: 0,
				incompleteToolRoundtrip: false,
				responseHashNote: undefined,
			};
		}
		return {
			valid: true,
			length: 0,
			status: "unknown",
			receipts: [],
			brokenAt: -1,
			incompleteToolRoundtrip: false,
		};
	}

	const status = classifyTerminationStatus(receipts);
	const incompleteToolRoundtrip = isIncompleteToolRoundtrip(receipts);

	// Idempotency-key duplicate detection is independent of validity (spec
	// §7.3.6) — compute it once up front so every return path can surface it.
	const warnings = duplicateIdempotencyWarnings(receipts);

	const results: ReceiptVerification[] = [];
	let brokenAt = -1;
	let previous: AgentReceipt | undefined;
	let signatureError: string | undefined;
	let signatureErrorAt = -1;
	let rotationError: string | undefined;
	let rotationErrorAt = -1;
	let hashComputeError: string | undefined;
	let hashComputeErrorAt = -1;

	// activeKey is the public key the current receipt must verify against. It
	// starts as the caller-supplied genesis key and is replaced by the incoming
	// key after each verified key_rotated receipt (spec §7.3.7).
	let activeKey = publicKey;

	for (let i = 0; i < receipts.length; i++) {
		const receipt = receipts[i];
		if (!receipt) continue;
		const chain = receipt.credentialSubject.chain;

		let signatureValid: boolean;
		try {
			signatureValid = verifyReceipt(receipt, activeKey);
		} catch (e) {
			signatureValid = false;
			if (signatureError === undefined) {
				const reason = e instanceof Error ? e.message : String(e);
				signatureError = `signature compute failed at index ${i}: ${reason}`;
				signatureErrorAt = i;
			}
		}

		let hashLinkValid: boolean;
		if (previous === undefined) {
			hashLinkValid = chain.previous_receipt_hash === null;
		} else {
			let previousHash: string | undefined;
			try {
				previousHash = hashReceipt(previous);
			} catch (e) {
				const reason = e instanceof Error ? e.message : String(e);
				if (hashComputeError === undefined) {
					hashComputeError = `hash compute failed at index ${i - 1}: ${reason}`;
					// Store the index of the receipt whose hash computation
					// failed, not the iteration index. Matches the error
					// message and keeps precedence comparisons consistent.
					hashComputeErrorAt = i - 1;
				}
			}
			hashLinkValid =
				previousHash !== undefined &&
				chain.previous_receipt_hash === previousHash;
		}

		let sequenceValid: boolean;
		const currentSequence = chain.sequence;
		if (!Number.isSafeInteger(currentSequence)) {
			sequenceValid = false;
		} else if (previous === undefined) {
			sequenceValid = currentSequence >= 1;
		} else {
			const prevSequence = previous.credentialSubject.chain.sequence;
			sequenceValid =
				Number.isSafeInteger(prevSequence) &&
				currentSequence === prevSequence + 1;
		}

		results.push({
			index: i,
			receiptId: receipt.id,
			signatureValid,
			hashLinkValid,
			sequenceValid,
		});

		if (
			brokenAt === -1 &&
			(!signatureValid || !hashLinkValid || !sequenceValid)
		) {
			brokenAt = i;
		}

		// Key-rotation traversal (ADR-0015 / spec §7.3.7). A key_rotated receipt
		// is signed with the OUTGOING (currently active) key; once that signature
		// and the rotation-event fields check out, the incoming key carried inline
		// takes over for every subsequent receipt until the next rotation.
		const kr = receipt.credentialSubject.keyRotation;
		if (kr !== undefined) {
			const rot = verifyRotationEvent(activeKey, kr);
			if (!rot.ok) {
				if (rotationError === undefined) {
					rotationError = `key rotation invalid at index ${i}: ${rot.error}`;
					rotationErrorAt = i;
				}
				if (brokenAt === -1) {
					brokenAt = i;
				}
			} else if (signatureValid) {
				// Only adopt the incoming key when the rotation receipt itself
				// verified under the outgoing key; otherwise the binding of
				// new_public_key to the prior chain segment is not trustworthy.
				activeKey = rot.newKeyPem;
			}
		}

		previous = receipt;
	}

	// Pick whichever compute error occurred first in the chain. When both
	// fire at the same index (e.g. a single receipt that fails both sig and
	// hash), sig wins the tie (it is the more direct cryptographic
	// statement). Mirrors the Go SDK's loopErr / loopErrAt selection so
	// cross-SDK error strings agree on which failure to surface.
	// Candidates checked in priority order — sig > rotation > hash — so when two
	// errors fire at the same index the higher-priority one wins. Mirrors the Go
	// SDK's loopErr / loopErrAt selection so cross-SDK error strings agree on
	// which failure to surface.
	let loopError: string | undefined;
	let loopErrorAt = -1;
	for (const [msg, at] of [
		[signatureError, signatureErrorAt],
		[rotationError, rotationErrorAt],
		[hashComputeError, hashComputeErrorAt],
	] as const) {
		if (msg === undefined) continue;
		if (loopErrorAt === -1 || at < loopErrorAt) {
			loopError = msg;
			loopErrorAt = at;
		}
	}

	// Chain identifier binding check (unconditional — spec §7.3.4).
	// All receipts in a verified chain MUST share chain.chain_id. Reject
	// cross-chain splices: an attacker with a valid hash linkage might
	// otherwise mix receipts from two distinct chains under one verification
	// call. Runs independently of hash linkage so that a forged link still
	// fails here.
	const expectedChainId = receipts[0]?.credentialSubject.chain.chain_id;
	for (let i = 1; i < receipts.length; i++) {
		const r = receipts[i];
		if (!r) continue;
		const observedChainId = r.credentialSubject.chain.chain_id;
		if (observedChainId !== expectedChainId) {
			// brokenAt aligns with the error message — set unconditionally to the
			// mismatch index so callers reading brokenAt and the error see the
			// same offending receipt. (Any earlier per-receipt failure already
			// surfaces in the per-receipt results array.)
			return {
				valid: false,
				length: receipts.length,
				status,
				receipts: results,
				brokenAt: i,
				incompleteToolRoundtrip,
				responseHashNote: undefined,
				warnings,
				error: `chain_id mismatch at index ${i}: expected "${expectedChainId}", got "${observedChainId}"`,
			};
		}
	}

	// Receipt-after-terminal integrity check (unconditional — spec §7.3.2).
	for (let i = 0; i < receipts.length - 1; i++) {
		const r = receipts[i];
		if (r && r.credentialSubject.chain.terminal === true) {
			// A receipt exists after a terminal one — protocol violation.
			const terminalViolationAt = i + 1;
			if (brokenAt === -1) brokenAt = terminalViolationAt;
			// Use the loop error only when it occurred at or before the
			// terminal violation; otherwise the terminal violation is the
			// earlier (and only relevant) failure and gets the dedicated
			// message. Mirrors the Go SDK's position-aware fallback in
			// VerifyChain (spec §7.3.2).
			const error =
				loopError !== undefined && loopErrorAt <= terminalViolationAt
					? loopError
					: `receipt after terminal: receipt at index ${terminalViolationAt} follows a terminal receipt at index ${i}`;
			return {
				valid: false,
				length: receipts.length,
				status,
				receipts: results,
				brokenAt,
				incompleteToolRoundtrip,
				responseHashNote: undefined,
				warnings,
				error,
			};
		}
	}

	const cv: ChainVerification = {
		valid: brokenAt === -1,
		length: receipts.length,
		status,
		receipts: results,
		brokenAt,
		incompleteToolRoundtrip,
	};
	if (warnings !== undefined) {
		cv.warnings = warnings;
	}
	if (loopError !== undefined) {
		cv.error = loopError;
	}

	// Response-hash verification (spec §4.3.2).
	// When a body is supplied: recompute and fail on mismatch.
	// When the body is absent: emit an informational note only.
	for (let i = 0; i < receipts.length; i++) {
		const r = receipts[i];
		if (!r) continue;
		const expectedHash = r.credentialSubject.outcome.response_hash;
		if (!expectedHash) continue;

		const body = options?.responseBodies?.[r.id];
		if (body === undefined) {
			cv.responseHashNote =
				"response_hash present in one or more receipts; response body not supplied — hash cannot be verified offline";
			continue;
		}
		if (!cv.valid) continue;

		const computed = sha256(canonicalize(body));
		if (computed !== expectedHash) {
			return {
				...cv,
				valid: false,
				brokenAt: i,
				error: `response_hash mismatch at index ${i}: receipt has ${expectedHash}, body hashes to ${computed}`,
			};
		}
	}

	if (!cv.valid) return cv;

	// Optional out-of-band checks (only when basic verification passes).
	if (
		options?.expectedLength !== undefined &&
		receipts.length !== options.expectedLength
	) {
		return {
			...cv,
			valid: false,
			brokenAt: receipts.length - 1,
		};
	}

	if (options?.expectedFinalHash !== undefined) {
		const lastReceipt = receipts[receipts.length - 1];
		if (!lastReceipt) {
			return {
				...cv,
				valid: false,
				brokenAt: receipts.length - 1,
			};
		}
		let lastHash: string;
		try {
			lastHash = hashReceipt(lastReceipt);
		} catch (err) {
			const reason = err instanceof Error ? err.message : String(err);
			return {
				...cv,
				valid: false,
				brokenAt: receipts.length - 1,
				error: `hash compute failed at index ${receipts.length - 1}: ${reason}`,
			};
		}
		if (lastHash !== options.expectedFinalHash) {
			return {
				...cv,
				valid: false,
				brokenAt: receipts.length - 1,
				error: `final receipt hash mismatch at index ${receipts.length - 1}: expected ${options.expectedFinalHash}, got ${lastHash}`,
			};
		}
	}

	if (options?.requireTerminal) {
		const lastReceipt = receipts[receipts.length - 1];
		if (!lastReceipt || lastReceipt.credentialSubject.chain.terminal !== true) {
			return {
				...cv,
				valid: false,
				brokenAt: receipts.length - 1,
			};
		}
	}

	return cv;
}
