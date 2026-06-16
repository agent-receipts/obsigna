/**
 * Framework-agnostic core that turns OpenCode native tool calls into Agent
 * Receipts. The OpenCode adapter in `plugin.ts` is a thin wrapper around this;
 * keeping the logic here lets the round-trip tests exercise it against a real
 * daemon socket without an OpenCode runtime.
 *
 * Trust boundary (load-bearing): this code runs INSIDE the OpenCode process and
 * is an EMITTER ONLY. It forwards unsigned tool-call frames to the
 * out-of-process daemon via {@link DaemonEmitter}, which captures peer
 * credentials, canonicalises (RFC 8785), signs (Ed25519), and chains the
 * receipt. It never instantiates a signer, signs, or holds a key (ADR-0010
 * daemon-sole-writer). This is the execd-side, honest-operator placement: it
 * maximises coverage of native tool calls but is NOT adversary-resistant — a
 * compromised OpenCode can omit or misreport calls. The MCP channel via
 * mcp-proxy is the adversary-resistant placement.
 *
 * Chain mapping: each OpenCode `sessionID` gets its own {@link DaemonEmitter}
 * so receipts carry that session id (ADR-0010 OQ4). In the daemon's current
 * single-root-chain model, every session's calls — including subagent child
 * sessions — land on the one daemon chain, grouped by `session_id`. Per-agent
 * sub-chains with `delegation` backlinks (issue #753) are a follow-up: the
 * `tool.execute` hook context exposes only `{ tool, sessionID, callID }`, not a
 * named-agent identity, so the sub-chain keying cannot be derived here without
 * guessing.
 */

import { DaemonEmitter, type EmitEvent } from "@obsigna/sdk-ts";
import { resolveActionType } from "./actions.js";
import { type ResolvedConfig, shouldEmit } from "./config.js";

/**
 * The slice of {@link DaemonEmitter} the recorder depends on. Declaring it as
 * an interface lets tests inject a capturing fake without a socket, and keeps
 * the recorder honest about the emitter-only surface it uses (no signing).
 */
export interface ReceiptEmitter {
	emit(ev: EmitEvent): Promise<Error | null>;
	close(): void;
}

/** Creates a per-session emitter. The default wires a real {@link DaemonEmitter}. */
export type EmitterFactory = (sessionID: string) => ReceiptEmitter;

/** A tool call about to run — captured from `tool.execute.before` for intent/params. */
export interface ToolIntent {
	tool: string;
	sessionID: string;
	callID: string;
	args: unknown;
}

/** A completed tool call — captured from `tool.execute.after`. */
export interface ToolResult {
	tool: string;
	sessionID: string;
	callID: string;
	/** Final args from the after-hook; falls back to the intent args when absent. */
	args?: unknown;
	title?: string;
	output?: string;
	metadata?: unknown;
	/** Human-readable error when the tool call failed. */
	error?: string;
}

/**
 * Records native OpenCode tool calls as daemon-signed receipts. One instance
 * per plugin load; safe to drive concurrently from the async hook callbacks.
 */
export class ReceiptRecorder {
	private readonly config: ResolvedConfig;
	private readonly emitterFactory: EmitterFactory;
	private readonly emitters = new Map<string, ReceiptEmitter>();
	/**
	 * Pending intent args keyed by callID, bridging before → after. The
	 * sessionID is stored alongside so {@link closeSession} can reclaim intents
	 * whose tool call never completed (an aborted/cancelled call fires
	 * `before` with no matching `after`), rather than leaking them for the life
	 * of the process.
	 */
	private readonly pendingArgs = new Map<
		string,
		{ sessionID: string; args: unknown }
	>();
	private closed = false;

	constructor(config: ResolvedConfig, emitterFactory?: EmitterFactory) {
		this.config = config;
		this.emitterFactory =
			emitterFactory ??
			((sessionID) =>
				new DaemonEmitter({
					socketPath: config.socketPath,
					sessionId: sessionID,
					// Surface transport failures (ADR-0025) so strict mode can
					// re-throw and default mode can log them. Never bestEffort.
					bestEffort: false,
					debugLog: config.debugLog,
				}));
	}

	/** Record a tool call's intent/params (from `tool.execute.before`). */
	recordIntent(intent: ToolIntent): void {
		if (this.closed || !shouldEmit(this.config, intent.tool)) {
			return;
		}
		this.pendingArgs.set(intent.callID, {
			sessionID: intent.sessionID,
			args: intent.args,
		});
	}

	/**
	 * Emit one receipt for a completed tool call (from `tool.execute.after`).
	 * In default mode an emit failure is logged and swallowed — the tool call
	 * is never aborted. In strict mode the failure is re-thrown (ADR-0025).
	 */
	async recordResult(result: ToolResult): Promise<void> {
		const pending = this.pendingArgs.get(result.callID);
		this.pendingArgs.delete(result.callID);
		const args = result.args !== undefined ? result.args : pending?.args;

		if (this.closed || !shouldEmit(this.config, result.tool)) {
			return;
		}

		const emitter = this.emitterFor(result.sessionID);
		if (emitter === null) {
			return; // construction failed; already logged/thrown per posture
		}

		const err = await emitter.emit(this.buildEvent(result, args));
		if (err !== null) {
			this.handleFailure(result, err);
		}
	}

	/**
	 * Close and forget the emitter for a deleted session, and reclaim any
	 * pending intents captured for it whose tool call never completed. Called
	 * on `session.deleted` (and indirectly on {@link close}/`dispose`).
	 */
	closeSession(sessionID: string): void {
		const emitter = this.emitters.get(sessionID);
		if (emitter) {
			emitter.close();
			this.emitters.delete(sessionID);
		}
		for (const [callID, pending] of this.pendingArgs) {
			if (pending.sessionID === sessionID) {
				this.pendingArgs.delete(callID);
			}
		}
	}

	/** Close every emitter and stop accepting calls (`dispose`). */
	close(): void {
		this.closed = true;
		for (const emitter of this.emitters.values()) {
			emitter.close();
		}
		this.emitters.clear();
		this.pendingArgs.clear();
	}

	private buildEvent(result: ToolResult, args: unknown): EmitEvent {
		const ev: EmitEvent = {
			channel: this.config.channel,
			tool: { name: result.tool },
			decision: "allowed",
		};
		const actionType = resolveActionType(result.tool, this.config.actionMap);
		if (actionType) {
			ev.actionType = actionType;
		}
		const input = safeStringify(args);
		if (input !== undefined) {
			ev.input = input;
		}
		const output = safeStringify(buildOutput(result));
		if (output !== undefined) {
			ev.output = output;
		}
		if (result.error) {
			ev.error = result.error;
		}
		return ev;
	}

	/**
	 * Lazily build (and cache) the emitter for a session. Returns null when
	 * construction fails (e.g. no socket path on an unsupported platform):
	 * in strict mode this re-throws; in default mode it logs and the caller
	 * skips the emission rather than aborting the tool call.
	 */
	private emitterFor(sessionID: string): ReceiptEmitter | null {
		const existing = this.emitters.get(sessionID);
		if (existing) {
			return existing;
		}
		try {
			const emitter = this.emitterFactory(sessionID);
			this.emitters.set(sessionID, emitter);
			return emitter;
		} catch (err) {
			const e = err instanceof Error ? err : new Error(String(err));
			if (this.config.strict) {
				throw e;
			}
			this.config.debugLog("agent-receipts: emitter construction failed", {
				session: sessionID,
				err: e.message,
			});
			return null;
		}
	}

	private handleFailure(result: ToolResult, err: Error): void {
		if (this.config.strict) {
			throw err;
		}
		this.config.debugLog(
			"agent-receipts: receipt emit failed (call recorded with a gap)",
			{
				tool: result.tool,
				session: result.sessionID,
				err: err.message,
			},
		);
	}
}

/** Assemble the receipt output payload from the after-hook fields, dropping empties. */
function buildOutput(result: ToolResult): Record<string, unknown> | undefined {
	const out: Record<string, unknown> = {};
	if (result.title !== undefined) {
		out.title = result.title;
	}
	if (result.output !== undefined) {
		out.output = result.output;
	}
	if (result.metadata !== undefined) {
		out.metadata = result.metadata;
	}
	return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * JSON.stringify that never throws and never yields invalid JSON: returns
 * undefined for `undefined` input and for values that cannot be serialised
 * (circular references, BigInt). Non-finite numbers (NaN, Infinity) are
 * serialised as null per JSON semantics — the frame is valid JSON and the
 * daemon accepts it, so those values silently become null in the receipt.
 */
function safeStringify(value: unknown): string | undefined {
	if (value === undefined) {
		return undefined;
	}
	try {
		const json = JSON.stringify(value);
		// JSON.stringify returns undefined for values like a bare `undefined`
		// or a function; guard so we never set an invalid `input`/`output`.
		return json;
	} catch {
		return undefined;
	}
}
