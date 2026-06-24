/**
 * Thin fire-and-forget emitter for the agent-receipts daemon's local Unix
 * domain socket. Emit forwards a tool-call frame to the daemon, which
 * captures peer credentials, canonicalises (RFC 8785), signs (Ed25519), and
 * persists the receipt. The emitter does NO crypto, NO canonicalisation, and
 * holds NO chain state — those moved to the daemon per ADR-0010 (daemon
 * process separation, 2026-05-03).
 *
 * Concurrency: emit() is safe to call from multiple async contexts on a
 * single Emitter instance. The internal write is serialised so concurrent
 * calls cannot interleave bytes on the same socket connection.
 *
 * Failure model: emit() MUST NOT block the agent on the daemon, and it MUST
 * surface transport failure (ADR-0025). When the socket is unreachable (daemon
 * not started, socket file missing, broken connection) emit() logs a
 * debug-level drop and resolves with an `EmitTransportError` within
 * milliseconds — distinct from the plain `Error` returned for caller bugs
 * (missing channel, missing tool name, invalid decision, invalid JSON, emitter
 * already closed) so callers can retry only transport failures. Pass
 * `bestEffort: true` to opt back into loss-tolerant emission (emit() resolves
 * with null on transport failure).
 */

import { randomUUID } from "node:crypto";
import { createConnection, type Socket } from "node:net";
import { homedir, platform } from "node:os";
import { isAbsolute, join } from "node:path";

/** Maximum allowed frame size in bytes (1 MiB). Must match daemon's socket.MaxFrameSize. */
export const MAX_FRAME_SIZE = 1 << 20;

/** Wire format version. Must match daemon's pipeline.SupportedFrameVersion. */
export const SUPPORTED_FRAME_VERSION = "1";

/**
 * Maximum UTF-8 byte length of an identity-style field. Applies to
 * {@link EmitTarget.system}. The daemon enforces the same limit
 * (`maxIdentityFieldLen`); validating client-side surfaces violations before
 * the write rather than as a silent daemon-side rejection.
 */
export const MAX_IDENTITY_FIELD_LEN = 256;

/**
 * Maximum UTF-8 byte length of {@link EmitTarget.resource}. File paths can
 * reach 4096 bytes on Linux (PATH_MAX), so a wider cap than
 * {@link MAX_IDENTITY_FIELD_LEN} is used. The daemon enforces the same limit.
 */
export const MAX_TARGET_RESOURCE_LEN = 4096;

/**
 * Inclusive range of emitter-frame schema versions this SDK can speak to the
 * daemon — its declared daemon-protocol range in the ADR-0024 Gate #8 sense.
 * Today the SDK emits exactly one version ({@link SUPPORTED_FRAME_VERSION}), so
 * `min === max`. Gate #8 reads this range from the published SDK and asserts it
 * intersects the released daemon's spoken range, so a release cannot ship an
 * SDK/daemon pair that cannot talk to each other.
 */
export const DAEMON_PROTOCOL_RANGE = { min: 1, max: 1 } as const;

/** Dial timeout in milliseconds — caps how long emit() blocks reaching the daemon. */
const DIAL_TIMEOUT_MS = 25;

/** Write deadline in milliseconds — caps how long a single frame write can block. */
const WRITE_TIMEOUT_MS = 100;

/** Valid decision values (must be lowercase to match the wire format). */
const VALID_DECISIONS = new Set(["allowed", "denied", "pending"]);

/**
 * Returned by {@link DaemonEmitter.emit} when the daemon transport fails — a
 * dial failure (daemon not running, socket missing), write failure, or write
 * timeout (ADR-0025). Distinct from the plain `Error` returned for caller bugs
 * (invalid event, closed emitter), so callers can check
 * `err instanceof EmitTransportError` to retry only recoverable transport
 * failures. Returned as null only when the emitter is constructed with
 * `bestEffort: true`.
 */
export class EmitTransportError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "EmitTransportError";
	}
}

/** Tool identifies the tool the agent invoked. server is optional. */
export interface EmitTool {
	/** Optional server qualifier. When absent the action type is "channel.name". */
	server?: string;
	/** Tool name. Required and non-empty. */
	name: string;
}

/**
 * Identifies the system and resource an action operates on. `system` names a
 * resource domain (e.g. "filesystem"); `resource` is the path or identifier
 * within that domain (e.g. a file path). Both must be set together — a
 * half-populated target is rejected.
 */
export interface EmitTarget {
	/** Resource domain, e.g. "filesystem". */
	system: string;
	/** Path or identifier within the domain, e.g. a file path. */
	resource: string;
}

/** One tool invocation to forward to the daemon. */
export interface EmitEvent {
	/** Stable channel identifier (required, non-empty). */
	channel: string;
	tool: EmitTool;
	/**
	 * Optional taxonomic action type the emitter has already resolved (e.g.
	 * "filesystem.file.modify"). The daemon uses it verbatim as action.type and
	 * resolves risk_level from it via the taxonomy. When omitted, the daemon
	 * falls back to a synthetic "<channel>.<tool>" type that rarely matches the
	 * taxonomy, so risk defaults to medium. Emitters that know the real action
	 * type SHOULD set it — that is what makes risk-based controls (e.g.
	 * parameter-disclosure "high") effective. The daemon resolves risk itself
	 * rather than trusting an emitter-supplied risk, so an emitter cannot
	 * downgrade risk to evade disclosure by setting this field.
	 *
	 * Note: this field is currently TypeScript-only. The Go and Python emitters
	 * do not yet expose an equivalent option; adding cross-SDK parity is a
	 * follow-up.
	 */
	actionType?: string;
	/**
	 * Raw JSON string for the tool input. Forwarded verbatim — the exact
	 * bytes are embedded in the frame without re-parsing or reformatting,
	 * so the daemon's RFC 8785 canonicalisation sees the same bytes the
	 * caller produced. Must be valid JSON if provided.
	 */
	input?: string;
	/**
	 * Raw JSON string for the tool output. Forwarded verbatim — the exact
	 * bytes are embedded in the frame without re-parsing or reformatting,
	 * so the daemon's RFC 8785 canonicalisation sees the same bytes the
	 * caller produced. Must be valid JSON if provided.
	 */
	output?: string;
	/** Human-readable error message when the tool call failed. */
	error?: string;
	/**
	 * Optional target identifying the resource the action operates on (e.g. a
	 * file path for filesystem tools). When set, the daemon maps it to
	 * `action.target.{system,resource}` on the receipt — for example
	 * `{ system: "filesystem", resource: "<file path>" }`. Both `system` and
	 * `resource` must be set together; a half-populated target is rejected.
	 * `system` is capped at {@link MAX_IDENTITY_FIELD_LEN} UTF-8 bytes and
	 * `resource` at {@link MAX_TARGET_RESOURCE_LEN}. Omitted from the frame when
	 * unset.
	 */
	target?: EmitTarget;
	/** Policy decision for this call. */
	decision: "allowed" | "denied" | "pending";
}

/** Options for constructing a DaemonEmitter. */
export interface DaemonEmitterOptions {
	/**
	 * Override the daemon socket path. When unset, resolved from the
	 * AGENTRECEIPTS_SOCKET env var then the per-OS default.
	 */
	socketPath?: string;
	/**
	 * Supply a host session identifier instead of generating a fresh UUID v4.
	 * Per ADR-0010 OQ4, use the host's session id when available so a single
	 * agent loop produces one logical session. An empty string is ignored and
	 * a UUID is generated instead.
	 */
	sessionId?: string;
	/**
	 * Logger function for debug-level drop diagnostics. Defaults to no-op.
	 * Pass `console.debug` or a structured logger to surface drops.
	 */
	debugLog?: (message: string, attrs: Record<string, string>) => void;
	/**
	 * Opt out of the emit failure contract (ADR-0025). When true, emit()
	 * resolves with null on transport failure instead of an
	 * `EmitTransportError`. Use only when the caller knowingly accepts
	 * silently dropped events; the default surfaces failures so audit-critical
	 * callers get the safe behaviour without opting in.
	 */
	bestEffort?: boolean;
}

/**
 * Wire frame sent to the daemon (field names must match exactly).
 *
 * input/output are sentinel placeholder strings during JSON.stringify; the
 * encoded sentinels are then replaced with the caller's raw JSON bytes so
 * the daemon hashes the verbatim input/output the caller produced.
 */
interface WireFrame {
	v: string;
	ts_emit: string;
	session_id: string;
	channel: string;
	tool: {
		server?: string;
		name: string;
	};
	action_type?: string;
	input?: string;
	output?: string;
	error?: string;
	target_system?: string;
	target_resource?: string;
	decision: string;
}

/**
 * Sentinel placeholders for verbatim input/output pass-through. These strings
 * are placed into the frame in the input/output slots, then JSON.stringify
 * encodes them as JSON string literals (with surrounding quotes). After
 * stringification we splice the encoded sentinel out and splice the caller's
 * raw JSON bytes in, so the daemon's RFC 8785 canonicalisation sees the
 * exact bytes the caller produced (no whitespace normalisation, no key
 * reordering, no number reformatting).
 *
 * Sentinels include random hex so they cannot collide with caller content
 * even if the caller deliberately tries to forge them.
 */
const RAW_INPUT_SENTINEL = `__AR_RAW_INPUT_${randomUUID()}__`;
const RAW_OUTPUT_SENTINEL = `__AR_RAW_OUTPUT_${randomUUID()}__`;

/**
 * Dependencies that vary by host environment. Threading them through
 * resolveSocketPath as a parameter (instead of reading process.env / node:os
 * directly) lets tests exercise the darwin / linux / unsupported branches on
 * any host without monkey-patching globals. The public defaultSocketPath
 * wires the real values once below.
 */
export interface SocketPathDeps {
	platform: () => NodeJS.Platform;
	env: NodeJS.ProcessEnv;
	homedir: () => string;
}

/**
 * resolveSocketPath is the pure resolver behind defaultSocketPath, exported
 * here (not from the package root) so the unit tests can pin the darwin
 * branch on Linux CI. Real callers should use defaultSocketPath; consumers
 * outside this file have no reason to override these deps.
 *
 * Resolution order matches defaultSocketPath:
 * 1. AGENTRECEIPTS_SOCKET (any platform — wins everywhere so an explicit
 *    override is honoured even on hosts where the platform default is "").
 * 2. macOS: $XDG_DATA_HOME/agent-receipts/events.sock (defaulting to
 *    ~/.local/share/agent-receipts/events.sock). Issue #545 moved this off
 *    $TMPDIR so the daemon and any GUI-spawned emitter agree on the path
 *    regardless of inherited environment.
 * 3. Linux: $XDG_RUNTIME_DIR/agentreceipts/events.sock if set, else
 *    /run/agentreceipts/events.sock.
 * 4. Other platforms: empty string — pass socketPath explicitly to the
 *    Emitter constructor.
 */
export function resolveSocketPath(deps: SocketPathDeps): string {
	const envPath = deps.env.AGENTRECEIPTS_SOCKET;
	if (envPath) {
		return envPath;
	}
	const os = deps.platform();
	if (os === "darwin") {
		const base = xdgDataHome(deps);
		if (!base) {
			return "";
		}
		return join(base, "agent-receipts", "events.sock");
	}
	if (os === "linux") {
		const xdgRuntime = deps.env.XDG_RUNTIME_DIR;
		if (xdgRuntime) {
			return join(xdgRuntime, "agentreceipts", "events.sock");
		}
		return "/run/agentreceipts/events.sock";
	}
	return "";
}

/**
 * Returns the per-OS default path for the daemon socket. See
 * resolveSocketPath for the full resolution order. The macOS resolution
 * mirrors the Go and Python SDKs so every emitter and the daemon agree on
 * a single path per user.
 */
export function defaultSocketPath(): string {
	return resolveSocketPath({
		platform,
		env: process.env,
		homedir,
	});
}

/**
 * Returns $XDG_DATA_HOME (absolute only) or $HOME/.local/share. Mirrors
 * the Go and Python xdgDataHome helpers so every SDK resolves the same
 * per-user directory the daemon writes to. A relative XDG_DATA_HOME is
 * ignored per the XDG spec — silently relocating sockets under the
 * working directory of whichever process happened to start the emitter
 * would be surprising. Returns an empty string when neither source
 * yields an absolute path.
 */
function xdgDataHome(deps: SocketPathDeps): string {
	const dataHome = deps.env.XDG_DATA_HOME;
	if (dataHome && isAbsolute(dataHome)) {
		return dataHome;
	}
	const home = deps.homedir();
	if (!home || !isAbsolute(home)) {
		return "";
	}
	return join(home, ".local", "share");
}

/**
 * RFC3339Nano timestamp: Node's toISOString() produces milliseconds only
 * ("2026-05-07T12:34:56.789Z"). Extend to nanosecond-resolution zeros to
 * match Go's time.RFC3339Nano format ("2026-05-07T12:34:56.789000000Z").
 */
function rfc3339Nano(): string {
	return new Date().toISOString().replace(/\.(\d{3})Z$/, ".$1000000Z");
}

/**
 * DaemonEmitter is the daemon-socket client. Construct with
 * `new DaemonEmitter(...)`, fire events with `emit()`, release the socket
 * with `close()`.
 *
 * The session_id is generated once at construction (UUID v4) and remains
 * stable for the lifetime of this instance — including across daemon
 * reconnects (ADR-0010 OQ4).
 *
 * Construction does NOT dial the daemon — dialing is lazy on the first
 * `emit()` so that constructing an emitter cannot fail because the daemon
 * happens to be down at the moment.
 *
 * Per ADR-0020 step 1, this class is the legacy daemon-socket client and
 * its `emit()` accepts the unsigned `EmitEvent` frame — not an
 * `AgentReceipt`. It therefore does NOT implement the new `Emitter`
 * interface defined in `./emitters/types.js`. Step 2 of the migration
 * (daemon learns to accept signed receipts) is tracked separately and is
 * out of scope for this rename.
 */
export class DaemonEmitter {
	readonly sessionId: string;

	private readonly socketPath: string;
	private readonly debugLog: (
		message: string,
		attrs: Record<string, string>,
	) => void;
	private readonly bestEffort: boolean;

	private conn: Socket | null = null;
	private closed = false;
	// Serialise writes so concurrent emit() calls cannot interleave bytes.
	private writeQueue: Promise<void> = Promise.resolve();

	constructor(options: DaemonEmitterOptions = {}) {
		// Validate caller-supplied options early. JS callers bypass the
		// compile-time types, so a non-string path or non-boolean flag would
		// otherwise surface as an opaque downstream failure; fail fast with a
		// clear caller-bug error instead. Mirrors the Go/Python SDKs, which
		// type-check their constructor inputs.
		if (
			options.socketPath !== undefined &&
			typeof options.socketPath !== "string"
		) {
			throw new TypeError(
				`emitter: socketPath must be a string, got ${typeof options.socketPath}`,
			);
		}
		if (
			options.bestEffort !== undefined &&
			typeof options.bestEffort !== "boolean"
		) {
			throw new TypeError(
				`emitter: bestEffort must be a boolean, got ${typeof options.bestEffort}`,
			);
		}
		const socketPath = options.socketPath ?? defaultSocketPath();
		if (!socketPath) {
			throw new Error(
				`emitter: no default socket path on ${platform()}; set AGENTRECEIPTS_SOCKET or pass socketPath`,
			);
		}
		this.socketPath = socketPath;
		const trimmedSessionId = options.sessionId?.trim();
		this.sessionId = trimmedSessionId ? trimmedSessionId : randomUUID();
		this.debugLog = options.debugLog ?? (() => {});
		this.bestEffort = options.bestEffort ?? false;
	}

	/**
	 * Build the return value for a transport failure: an `EmitTransportError`
	 * by default (ADR-0025), or null when constructed with `bestEffort: true`.
	 */
	private transportFailure(message: string): Error | null {
		return this.bestEffort ? null : new EmitTransportError(message);
	}

	/**
	 * Emit sends one event to the daemon. On success resolves with null. By
	 * default (ADR-0025) it resolves with an `EmitTransportError` when the
	 * daemon is unreachable: dial and write failures are logged at debug level
	 * and the conn is reset for re-dial on the next emit(). Construct with
	 * `bestEffort: true` to resolve with null on transport failure instead.
	 * Resolves with a plain Error for caller bugs (emitter closed, oversized
	 * frame, invalid event fields, malformed input/output JSON) — situations a
	 * retry could not fix — which stay distinct from `EmitTransportError`.
	 *
	 * Concurrent-close caveat: if close() is called concurrently with an
	 * in-flight emit() that has already passed the initial closed check, the
	 * emit resolves with an Error rather than completing normally — either
	 * `Error("emitter: closed")` once the close is observed, or an
	 * `EmitTransportError` if the connection is torn down mid-write (the daemon
	 * may or may not have received the frame, consistent with the
	 * fire-and-forget failure model). A silent drop (null) happens only under
	 * `bestEffort: true`, where that transport failure is swallowed.
	 */
	async emit(ev: EmitEvent): Promise<Error | null> {
		// Validate caller-supplied fields first (before acquiring the write lock).
		if (this.closed) {
			return new Error("emitter: closed");
		}
		if (!ev.channel) {
			return new Error("emitter: missing channel");
		}
		if (!ev.tool.name) {
			return new Error("emitter: missing tool.name");
		}
		if (!VALID_DECISIONS.has(ev.decision)) {
			return new Error(
				`emitter: invalid decision "${ev.decision}" (want allowed|denied|pending)`,
			);
		}
		if (ev.actionType !== undefined && typeof ev.actionType !== "string") {
			return new Error("emitter: actionType must be a string");
		}
		if (ev.target !== undefined) {
			const targetErr = validateTarget(ev.target);
			if (targetErr !== null) {
				return targetErr;
			}
		}
		if (ev.input !== undefined && !isValidJson(ev.input)) {
			return new Error("emitter: input is not valid JSON");
		}
		if (ev.output !== undefined && !isValidJson(ev.output)) {
			return new Error("emitter: output is not valid JSON");
		}

		// Build the frame with sentinel placeholder strings for input/output.
		// JSON.stringify will encode these as JSON string literals; we then
		// splice the raw caller-supplied JSON bytes in so the daemon hashes
		// the exact bytes the caller produced (verbatim pass-through).
		const wireFrame: WireFrame = {
			v: SUPPORTED_FRAME_VERSION,
			ts_emit: rfc3339Nano(),
			session_id: this.sessionId,
			channel: ev.channel,
			tool: {
				...(ev.tool.server ? { server: ev.tool.server } : {}),
				name: ev.tool.name,
			},
			...(ev.actionType ? { action_type: ev.actionType } : {}),
			...(ev.input !== undefined ? { input: RAW_INPUT_SENTINEL } : {}),
			...(ev.output !== undefined ? { output: RAW_OUTPUT_SENTINEL } : {}),
			...(ev.error ? { error: ev.error } : {}),
			// Both fields are non-empty here (validateTarget enforces both-or-
			// neither); guarding on `system` omits an all-empty target so the
			// frame matches the Go emitter's omitempty behaviour.
			...(ev.target?.system
				? {
						target_system: ev.target.system,
						target_resource: ev.target.resource,
					}
				: {}),
			decision: ev.decision,
		};

		let serialised = JSON.stringify(wireFrame);
		if (ev.input !== undefined) {
			// Match "input":"<sentinel>" so the replacement can never target
			// another field even if the sentinel appears elsewhere in the frame.
			// Use a function replacement so '$' sequences in ev.input are not
			// interpreted as String.prototype.replace special patterns.
			const input = ev.input;
			serialised = serialised.replace(
				`"input":${JSON.stringify(RAW_INPUT_SENTINEL)}`,
				() => `"input":${input}`,
			);
		}
		if (ev.output !== undefined) {
			const output = ev.output;
			serialised = serialised.replace(
				`"output":${JSON.stringify(RAW_OUTPUT_SENTINEL)}`,
				() => `"output":${output}`,
			);
		}
		const body = Buffer.from(serialised, "utf8");
		if (body.length > MAX_FRAME_SIZE) {
			return new Error(
				`emitter: frame too large: ${body.length} bytes (max ${MAX_FRAME_SIZE})`,
			);
		}

		// Serialise into the write queue so concurrent calls do not interleave.
		return this.enqueueWrite(body);
	}

	/**
	 * Close releases the underlying connection. After Close, subsequent emit()
	 * calls return an Error. Safe to call multiple times.
	 */
	close(): void {
		if (this.closed) {
			return;
		}
		this.closed = true;
		if (this.conn !== null) {
			this.conn.destroy();
			this.conn = null;
		}
	}

	/**
	 * Enqueue a serialised write onto the sequential write queue. All calls
	 * run in order; a failed write drops and resets the connection.
	 */
	private enqueueWrite(body: Buffer): Promise<Error | null> {
		const next = this.writeQueue.then(() => this.doWrite(body));
		// Keep the queue moving even if doWrite rejects (it shouldn't, but guard it).
		this.writeQueue = next.then(
			() => {},
			() => {},
		);
		// doWrite is designed to resolve with Error | null and never reject, but
		// a synchronous throw from a Node socket call (e.g. write() on a freshly
		// destroyed socket) would otherwise reject emit()'s Promise and break the
		// documented contract. Convert any unexpected rejection into a transport
		// failure so callers always get Error | null.
		return next.catch((err: unknown) => {
			const e = err instanceof Error ? err : new Error(String(err));
			this.logDrop("write", e);
			// A synchronous throw most likely came from a socket call on a bad
			// connection. Discard it so the next emit() re-dials instead of
			// reusing a dead socket and failing the same way.
			if (this.conn !== null) {
				this.discardConn(this.conn);
			}
			return this.transportFailure(
				`emitter: unexpected emit error: ${e.message}`,
			);
		});
	}

	/**
	 * doWrite dials if needed, then writes the framed body. Returns null on
	 * success; logs and returns an EmitTransportError on transport failure
	 * (null when bestEffort is set). The "emitter: closed" caller-bug error is
	 * propagated as a plain Error regardless.
	 *
	 * Write timeouts are treated as drops without retry: a timeout does not
	 * mean the frame was not received — the data may already be in-flight or
	 * fully delivered, so retrying risks a duplicate receipt.
	 *
	 * Connection errors (EPIPE, ECONNRESET, etc.) on a previously-established
	 * connection trigger one transparent re-dial + re-write. Node buffers
	 * writes optimistically: a write that "succeeded" earlier may turn out to
	 * have been on a stale socket the kernel only reports as dead on the next
	 * attempt, so the FIRST emit after a daemon restart would otherwise be
	 * lost without anyone seeing a transient failure.
	 */
	private async doWrite(body: Buffer): Promise<Error | null> {
		const dialErr = await this.dialIfNeeded();
		if (dialErr !== null) {
			// "emitter: closed" is a caller-bug error — propagate it so
			// emit() surfaces it even when close() raced past the entry check.
			if (dialErr.message === "emitter: closed") {
				return dialErr;
			}
			this.logDrop("dial", dialErr);
			return this.transportFailure(
				`emitter: dial ${this.socketPath} failed: ${dialErr.message}`,
			);
		}

		const conn = this.conn;
		if (conn === null) {
			// close() raced between dialIfNeeded and this read.
			return this.closed
				? new Error("emitter: closed")
				: this.transportFailure("emitter: connection lost before write");
		}

		const writeErr = await this.writeFrame(conn, body);
		if (writeErr === null) {
			return null;
		}

		// A write timeout means the frame may already have been received by
		// the daemon. Retrying risks a duplicate receipt — treat as a drop.
		if (writeErr.message.startsWith("write timeout")) {
			this.logDrop("write", writeErr);
			this.discardConn(conn);
			return this.transportFailure(
				`emitter: write to ${this.socketPath} failed: ${writeErr.message}`,
			);
		}

		// Connection error: the daemon definitively did not receive the frame.
		// Discard and attempt one transparent re-dial + re-write.
		this.discardConn(conn);

		const redialErr = await this.dialIfNeeded();
		if (redialErr !== null) {
			if (redialErr.message === "emitter: closed") {
				return redialErr;
			}
			this.logDrop("dial", redialErr);
			return this.transportFailure(
				`emitter: dial ${this.socketPath} failed: ${redialErr.message}`,
			);
		}
		const newConn = this.conn;
		if (newConn === null) {
			return this.closed
				? new Error("emitter: closed")
				: this.transportFailure("emitter: connection lost before write");
		}
		const retryErr = await this.writeFrame(newConn, body);
		if (retryErr !== null) {
			this.logDrop("write", retryErr);
			this.discardConn(newConn);
			return this.transportFailure(
				`emitter: write to ${this.socketPath} failed: ${retryErr.message}`,
			);
		}
		return null;
	}

	/** Dial the daemon socket if not already connected. */
	private dialIfNeeded(): Promise<Error | null> {
		if (this.conn !== null) {
			return Promise.resolve(null);
		}
		if (this.closed) {
			return Promise.resolve(new Error("emitter: closed"));
		}
		return new Promise((resolve) => {
			let settled = false;
			const settle = (err: Error | null) => {
				if (settled) {
					return;
				}
				settled = true;
				clearTimeout(timer);
				resolve(err);
			};

			const timer = setTimeout(() => {
				socket.destroy();
				settle(new Error(`dial timeout after ${DIAL_TIMEOUT_MS}ms`));
			}, DIAL_TIMEOUT_MS);

			const socket = createConnection({ path: this.socketPath }, () => {
				// Dial timeout already fired and destroyed this socket — the
				// promise is settled. Discard the late-arriving connection
				// without touching this.conn so the next emit() re-dials.
				if (settled) {
					socket.destroy();
					return;
				}
				// Attach a permanent error listener BEFORE settling. Without
				// it, any later 'error' event on this socket (peer reset,
				// daemon crash, EPIPE on a half-open conn) crashes the host
				// process via Node's unhandled-'error' rule. The listener
				// also discards the dead conn so the next emit() re-dials
				// transparently.
				socket.on("error", (err) => this.handleSocketError(socket, err));
				// If close() ran while we were dialing, drop this freshly
				// connected socket on the floor — the caller already asked
				// to release resources.
				if (this.closed) {
					socket.destroy();
					settle(new Error("emitter: closed"));
					return;
				}
				this.conn = socket;
				settle(null);
			});

			socket.once("error", (err) => {
				// Dial-time error: 'connect' never fired, so the permanent
				// listener was never installed and this once-listener is
				// the only one. settle() also clears the dial timer.
				settle(err);
			});
		});
	}

	/**
	 * Permanent socket error listener. Discards the dead conn so the next
	 * emit() re-dials, and logs the drop. This listener is what prevents
	 * a peer reset from crashing the host process via Node's unhandled-
	 * 'error' rule.
	 */
	private handleSocketError(socket: Socket, err: Error): void {
		this.logDrop("socket", err);
		// Only forget conn if it still points at this socket; a later dial
		// may have replaced it and we don't want to drop the live one.
		if (this.conn === socket) {
			this.conn = null;
		}
		socket.destroy();
	}

	/** Discard a connection: forget it if current, then destroy. */
	private discardConn(socket: Socket): void {
		if (this.conn === socket) {
			this.conn = null;
		}
		socket.destroy();
	}

	/** Write a 4-byte big-endian length prefix followed by the body. */
	private writeFrame(conn: Socket, body: Buffer): Promise<Error | null> {
		return new Promise((resolve) => {
			let settled = false;
			const settle = (err: Error | null) => {
				if (settled) {
					return;
				}
				settled = true;
				clearTimeout(timer);
				resolve(err);
			};

			const header = Buffer.allocUnsafe(4);
			header.writeUInt32BE(body.length, 0);

			const timer = setTimeout(() => {
				settle(new Error(`write timeout after ${WRITE_TIMEOUT_MS}ms`));
			}, WRITE_TIMEOUT_MS);

			// Write header and body as two sequential calls to avoid allocating
			// a concat buffer for every emit (avoids one copy of the full frame).
			conn.write(header);
			conn.write(body, (err) => {
				settle(err ?? null);
			});
		});
	}

	private logDrop(stage: string, err: Error): void {
		try {
			this.debugLog("agent-receipts emitter dropped event", {
				stage,
				socket: this.socketPath,
				err: err.message,
			});
		} catch {
			// A throwing debugLog must not take down the host process.
		}
	}
}

/**
 * Validates an {@link EmitTarget} against the daemon's rules, returning a
 * caller-bug Error on violation or null when valid. Caps are measured in UTF-8
 * bytes (via Buffer.byteLength), not JS string length, to match the daemon and
 * the Go emitter, which count bytes — a multi-byte string under the char limit
 * can still exceed the byte cap.
 */
function validateTarget(target: unknown): Error | null {
	// Guard null and non-objects: callers without TypeScript can pass anything,
	// and validateTarget must return a caller-bug Error rather than throw.
	if (typeof target !== "object" || target === null) {
		return new Error("emitter: target must be an object");
	}
	const { system, resource } = target as Partial<EmitTarget>;
	if (typeof system !== "string" || typeof resource !== "string") {
		return new Error(
			"emitter: target.system and target.resource must be strings",
		);
	}
	// Both set or both empty — a half-populated target would produce an
	// ActionTarget with an empty system or resource in the signed receipt.
	if ((system !== "") !== (resource !== "")) {
		return new Error(
			"emitter: target.system and target.resource must both be set or both empty",
		);
	}
	const systemBytes = Buffer.byteLength(system, "utf8");
	if (systemBytes > MAX_IDENTITY_FIELD_LEN) {
		return new Error(
			`emitter: target_system exceeds ${MAX_IDENTITY_FIELD_LEN} bytes (got ${systemBytes})`,
		);
	}
	const resourceBytes = Buffer.byteLength(resource, "utf8");
	if (resourceBytes > MAX_TARGET_RESOURCE_LEN) {
		return new Error(
			`emitter: target_resource exceeds ${MAX_TARGET_RESOURCE_LEN} bytes (got ${resourceBytes})`,
		);
	}
	return null;
}

/**
 * Returns true if the string is syntactically valid JSON and contains no
 * non-finite numbers. JSON.parse accepts overflow values like 1e400 as
 * Infinity, but the daemon's RFC 8785 canonicaliser rejects non-finite
 * numbers — so we reject them here rather than silently dropping the frame.
 */
function isValidJson(s: string): boolean {
	try {
		return !hasNonFiniteNumber(JSON.parse(s));
	} catch {
		return false;
	}
}

function hasNonFiniteNumber(val: unknown): boolean {
	if (typeof val === "number") {
		return !Number.isFinite(val);
	}
	if (Array.isArray(val)) {
		return val.some(hasNonFiniteNumber);
	}
	if (val !== null && typeof val === "object") {
		return Object.values(val).some(hasNonFiniteNumber);
	}
	return false;
}
