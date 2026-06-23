/**
 * Tests for the fire-and-forget Unix socket emitter (ADR-0010).
 *
 * Test categories:
 *   - Frame round-trip: events reach a local echo server
 *   - session_id stability: same value across emits and reconnects
 *   - Fire-and-forget: returns null quickly when daemon is down
 *   - Reconnect: re-dials transparently after server restart
 *   - Error after close: returns Error for closed emitter
 *   - Validation: caller-bug errors for bad inputs
 *   - Frame size: oversized frames return an Error
 *   - defaultSocketPath: env-var and OS-default resolution
 */

import { unlinkSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	DAEMON_PROTOCOL_RANGE,
	DaemonEmitter,
	defaultSocketPath,
	type EmitEvent,
	EmitTransportError,
	MAX_FRAME_SIZE,
	MAX_IDENTITY_FIELD_LEN,
	MAX_TARGET_RESOURCE_LEN,
	resolveSocketPath,
	type SocketPathDeps,
	SUPPORTED_FRAME_VERSION,
} from "./daemon-emitter.js";

describe("DAEMON_PROTOCOL_RANGE — declared daemon-protocol range (Gate #8)", () => {
	it("is well-formed (min <= max)", () => {
		expect(DAEMON_PROTOCOL_RANGE.min).toBeLessThanOrEqual(
			DAEMON_PROTOCOL_RANGE.max,
		);
	});

	it("covers the version the SDK actually emits", () => {
		// While the SDK emits a single version, min === max === that version.
		// A mismatch would advertise a range that does not match the frames the
		// SDK puts on the wire, defeating Gate #8.
		const emitted = Number(SUPPORTED_FRAME_VERSION);
		expect(Number.isInteger(emitted)).toBe(true);
		expect(DAEMON_PROTOCOL_RANGE.min).toBe(emitted);
		expect(DAEMON_PROTOCOL_RANGE.max).toBe(emitted);
	});
});

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Monotonic counter so every tempSockPath call returns a unique path. */
let _sockSeq = 0;

/**
 * A unique socket path for each call (pid + counter + suffix).
 *
 * On macOS, os.tmpdir() returns a long path under /var/folders/… that can
 * exceed the AF_UNIX 104-byte limit. Use /tmp directly on darwin to keep
 * paths well under the limit.
 */
function tempSockPath(suffix: string): string {
	const base = process.platform === "darwin" ? "/tmp" : tmpdir();
	return join(base, `ar-${process.pid}-${++_sockSeq}-${suffix}.sock`);
}

/**
 * Minimal echo server that reads length-prefixed frames and collects the JSON
 * body of each frame. Returns the socket path and a way to read received
 * frames.
 *
 * `ready` resolves once the server is actually listening. Tests that emit
 * immediately after construction should await it to avoid a race between the
 * first connect and the server's bind completing.
 */
function startEchoServer(sockPath: string): {
	frames: () => Promise<string[]>;
	stop: () => Promise<void>;
	ready: Promise<void>;
} {
	const received: string[] = [];
	// Track open client sockets so stop() can forcefully destroy them,
	// ensuring the emitter sees the connection die immediately.
	const openSockets = new Set<import("node:net").Socket>();

	const server = createServer((socket) => {
		openSockets.add(socket);
		socket.once("close", () => openSockets.delete(socket));

		let buf = Buffer.alloc(0);
		socket.on("data", (chunk: Buffer) => {
			buf = Buffer.concat([buf, chunk]);
			// Parse as many complete frames as possible.
			while (buf.length >= 4) {
				const len = buf.readUInt32BE(0);
				if (buf.length < 4 + len) {
					break;
				}
				received.push(buf.subarray(4, 4 + len).toString("utf8"));
				buf = buf.subarray(4 + len);
			}
		});
	});

	// Unlink any stale socket file from a previous (possibly crashed) test run
	// so server.listen() doesn't get EADDRINUSE.
	try {
		unlinkSync(sockPath);
	} catch {
		// Socket file didn't exist — fine.
	}

	const ready = new Promise<void>((resolve, reject) => {
		server.once("listening", resolve);
		server.once("error", reject);
	});
	server.listen(sockPath);

	return {
		frames: () =>
			new Promise<string[]>((resolve) => {
				// Give the OS a tick to deliver any in-flight data.
				setTimeout(() => resolve([...received]), 10);
			}),
		stop: () =>
			new Promise<void>((resolve, reject) => {
				// Destroy all open client sockets so the emitter sees the connection
				// die immediately rather than waiting for a graceful FIN.
				for (const s of openSockets) {
					s.destroy();
				}
				server.close((err) => {
					try {
						unlinkSync(sockPath);
					} catch {
						// Already gone — fine.
					}
					err ? reject(err) : resolve();
				});
			}),
		ready,
	};
}

/** Wait up to `ms` for `predicate()` to return true, polling every 5 ms. */
async function waitFor(
	predicate: () => boolean | Promise<boolean>,
	ms = 500,
): Promise<void> {
	const deadline = Date.now() + ms;
	while (Date.now() < deadline) {
		if (await predicate()) {
			return;
		}
		await new Promise((r) => setTimeout(r, 5));
	}
	throw new Error(`waitFor timed out after ${ms}ms`);
}

const GOOD_EVENT: EmitEvent = {
	channel: "test-channel",
	tool: { name: "my_tool" },
	decision: "allowed",
};

// ─── Tests ──────────────────────────────────────────────────────────────────

describe("DaemonEmitter — validation errors (caller bugs)", () => {
	it("returns an error for empty channel", async () => {
		const e = new DaemonEmitter({ socketPath: tempSockPath("noop") });
		const err = await e.emit({ ...GOOD_EVENT, channel: "" });
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/missing channel/);
		e.close();
	});

	it("returns an error for empty tool.name", async () => {
		const e = new DaemonEmitter({ socketPath: tempSockPath("noop") });
		const err = await e.emit({ ...GOOD_EVENT, tool: { name: "" } });
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/missing tool\.name/);
		e.close();
	});

	it("returns an error for invalid decision", async () => {
		const e = new DaemonEmitter({ socketPath: tempSockPath("noop") });
		const err = await e.emit({
			...GOOD_EVENT,
			// @ts-expect-error testing invalid decision value
			decision: "maybe",
		});
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/invalid decision/);
		e.close();
	});

	it("returns an error for malformed input JSON", async () => {
		const e = new DaemonEmitter({ socketPath: tempSockPath("noop") });
		const err = await e.emit({ ...GOOD_EVENT, input: "{bad json}" });
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/input is not valid JSON/);
		e.close();
	});

	it("returns an error for malformed output JSON", async () => {
		const e = new DaemonEmitter({ socketPath: tempSockPath("noop") });
		const err = await e.emit({ ...GOOD_EVENT, output: "[unclosed" });
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/output is not valid JSON/);
		e.close();
	});

	it("returns an error for input containing a non-finite number", async () => {
		// 1e400 overflows float64 to Infinity; JSON.parse accepts it but the
		// daemon's RFC 8785 canonicaliser rejects it — catch it here as a
		// caller-bug Error rather than letting it become a silent drop.
		const e = new DaemonEmitter({ socketPath: tempSockPath("noop") });
		const err = await e.emit({ ...GOOD_EVENT, input: '{"n":1e400}' });
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/input is not valid JSON/);
		e.close();
	});

	it("returns an error for output containing a non-finite number", async () => {
		const e = new DaemonEmitter({ socketPath: tempSockPath("noop") });
		const err = await e.emit({ ...GOOD_EVENT, output: "[1e400]" });
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/output is not valid JSON/);
		e.close();
	});

	it("rejects a target with only system set", async () => {
		const e = new DaemonEmitter({ socketPath: tempSockPath("noop") });
		const err = await e.emit({
			...GOOD_EVENT,
			target: { system: "filesystem", resource: "" },
		});
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/both be set or both empty/);
		e.close();
	});

	it("rejects a target with only resource set", async () => {
		const e = new DaemonEmitter({ socketPath: tempSockPath("noop") });
		const err = await e.emit({
			...GOOD_EVENT,
			target: { system: "", resource: "/etc/hosts" },
		});
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/both be set or both empty/);
		e.close();
	});

	it("rejects a target.system over the byte cap", async () => {
		const e = new DaemonEmitter({ socketPath: tempSockPath("noop") });
		const err = await e.emit({
			...GOOD_EVENT,
			target: {
				system: "a".repeat(MAX_IDENTITY_FIELD_LEN + 1),
				resource: "/etc/hosts",
			},
		});
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/target_system exceeds 256 bytes/);
		e.close();
	});

	it("rejects a target.resource over the byte cap", async () => {
		const e = new DaemonEmitter({ socketPath: tempSockPath("noop") });
		const err = await e.emit({
			...GOOD_EVENT,
			target: {
				system: "filesystem",
				resource: "a".repeat(MAX_TARGET_RESOURCE_LEN + 1),
			},
		});
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/target_resource exceeds 4096 bytes/);
		e.close();
	});

	it("measures the target.system cap in UTF-8 bytes, not characters", async () => {
		// "あ" is 3 UTF-8 bytes but 1 JS char (well within UTF-16 length).
		// 86 copies = 258 bytes (> 256) yet only 86 .length, so a char-length
		// check would wrongly accept this.
		const e = new DaemonEmitter({ socketPath: tempSockPath("noop") });
		const system = "あ".repeat(86);
		expect(system.length).toBeLessThanOrEqual(MAX_IDENTITY_FIELD_LEN);
		expect(Buffer.byteLength(system, "utf8")).toBeGreaterThan(
			MAX_IDENTITY_FIELD_LEN,
		);
		const err = await e.emit({
			...GOOD_EVENT,
			target: { system, resource: "/etc/hosts" },
		});
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/target_system exceeds 256 bytes/);
		e.close();
	});

	it("accepts a multi-byte target at the byte boundary", async () => {
		// A multi-byte resource whose byte length is exactly the cap must pass —
		// proves the check is inclusive and byte-accurate. Use an echo server so
		// the emit reaches the write path rather than failing transport.
		const sockPath = tempSockPath("target-boundary");
		const server = startEchoServer(sockPath);
		await server.ready;
		const e = new DaemonEmitter({ socketPath: sockPath });
		// "あ" is 3 bytes; 1365 * 3 = 4095, + one ASCII byte = 4096 = cap.
		const resource = `${"あ".repeat(1365)}a`;
		expect(Buffer.byteLength(resource, "utf8")).toBe(MAX_TARGET_RESOURCE_LEN);
		const err = await e.emit({
			...GOOD_EVENT,
			target: { system: "filesystem", resource },
		});
		expect(err).toBeNull();
		e.close();
		await server.stop();
	});

	it("returns an error after close", async () => {
		const sockPath = tempSockPath("closed");
		const server = startEchoServer(sockPath);
		await server.ready;
		const e = new DaemonEmitter({ socketPath: sockPath });
		e.close();
		const err = await e.emit(GOOD_EVENT);
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/closed/);
		await server.stop();
	});
});

describe("DaemonEmitter — frame round-trip", () => {
	let sockPath: string;
	let server: ReturnType<typeof startEchoServer>;
	let emitter: DaemonEmitter;

	beforeEach(async () => {
		sockPath = tempSockPath("roundtrip");
		server = startEchoServer(sockPath);
		await server.ready;
		emitter = new DaemonEmitter({ socketPath: sockPath });
	});

	afterEach(async () => {
		emitter.close();
		await server.stop();
	});

	it("delivers a frame to the server", async () => {
		const err = await emitter.emit(GOOD_EVENT);
		expect(err).toBeNull();

		await waitFor(async () => (await server.frames()).length > 0);

		const frames = await server.frames();
		expect(frames).toHaveLength(1);
		const f = JSON.parse(frames[0] ?? "{}");
		expect(f.v).toBe(SUPPORTED_FRAME_VERSION);
		expect(f.channel).toBe("test-channel");
		expect(f.tool.name).toBe("my_tool");
		expect(f.decision).toBe("allowed");
	});

	it("frame contains session_id matching emitter.sessionId", async () => {
		await emitter.emit(GOOD_EVENT);
		await waitFor(async () => (await server.frames()).length > 0);

		const frames = await server.frames();
		const f = JSON.parse(frames[0] ?? "{}");
		expect(f.session_id).toBe(emitter.sessionId);
	});

	it("ts_emit is RFC3339Nano UTC", async () => {
		await emitter.emit(GOOD_EVENT);
		await waitFor(async () => (await server.frames()).length > 0);

		const frames = await server.frames();
		const f = JSON.parse(frames[0] ?? "{}");
		// e.g. "2026-05-07T12:34:56.789000000Z"
		expect(f.ts_emit).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$/);
		expect(f.ts_emit.endsWith("Z")).toBe(true);
	});

	it("optional tool.server is included when provided", async () => {
		await emitter.emit({
			...GOOD_EVENT,
			tool: { server: "mcp-server", name: "read_file" },
		});
		await waitFor(async () => (await server.frames()).length > 0);

		const frames = await server.frames();
		const f = JSON.parse(frames[0] ?? "{}");
		expect(f.tool.server).toBe("mcp-server");
		expect(f.tool.name).toBe("read_file");
	});

	it("tool.server is absent when not provided", async () => {
		await emitter.emit(GOOD_EVENT);
		await waitFor(async () => (await server.frames()).length > 0);

		const frames = await server.frames();
		const f = JSON.parse(frames[0] ?? "{}");
		expect(f.tool).not.toHaveProperty("server");
	});

	it("action_type is included when provided", async () => {
		await emitter.emit({ ...GOOD_EVENT, actionType: "filesystem.file.modify" });
		await waitFor(async () => (await server.frames()).length > 0);

		const frames = await server.frames();
		const f = JSON.parse(frames[0] ?? "{}");
		expect(f.action_type).toBe("filesystem.file.modify");
	});

	it("action_type is absent when not provided", async () => {
		await emitter.emit(GOOD_EVENT);
		await waitFor(async () => (await server.frames()).length > 0);

		const frames = await server.frames();
		const f = JSON.parse(frames[0] ?? "{}");
		expect(f).not.toHaveProperty("action_type");
	});

	it("returns an error for non-string actionType", async () => {
		const e = new DaemonEmitter({ socketPath: tempSockPath("noop") });
		const err = await e.emit({
			...GOOD_EVENT,
			// @ts-expect-error testing runtime type-check for non-TS callers
			actionType: 42,
		});
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/actionType must be a string/);
		e.close();
	});

	it("target is forwarded as target_system / target_resource", async () => {
		await emitter.emit({
			...GOOD_EVENT,
			target: { system: "filesystem", resource: "/etc/hosts" },
		});
		await waitFor(async () => (await server.frames()).length > 0);

		const frames = await server.frames();
		const f = JSON.parse(frames[0] ?? "{}");
		expect(f.target_system).toBe("filesystem");
		expect(f.target_resource).toBe("/etc/hosts");
	});

	it("target_system and target_resource are absent when target is omitted", async () => {
		await emitter.emit(GOOD_EVENT);
		await waitFor(async () => (await server.frames()).length > 0);

		const frames = await server.frames();
		const f = JSON.parse(frames[0] ?? "{}");
		expect(f).not.toHaveProperty("target_system");
		expect(f).not.toHaveProperty("target_resource");
	});

	it("input and output are forwarded as raw JSON values (not double-encoded)", async () => {
		await emitter.emit({
			...GOOD_EVENT,
			input: '{"key":"value"}',
			output: "[1,2,3]",
		});
		await waitFor(async () => (await server.frames()).length > 0);

		const frames = await server.frames();
		const f = JSON.parse(frames[0] ?? "{}");
		expect(f.input).toEqual({ key: "value" });
		expect(f.output).toEqual([1, 2, 3]);
	});

	it("input and output are byte-exact verbatim (whitespace preserved)", async () => {
		// The daemon canonicalises (RFC 8785) and hashes the raw frame bytes,
		// so any whitespace, key-order, or number-formatting changes here would
		// silently change the receipt hash. Pin the verbatim guarantee.
		const rawInput = '{ "b": 2,\n  "a": 1 }';
		const rawOutput = "[\t1.0,\n2,\n3 ]";
		await emitter.emit({
			...GOOD_EVENT,
			input: rawInput,
			output: rawOutput,
		});
		await waitFor(async () => (await server.frames()).length > 0);

		const raw = (await server.frames())[0] ?? "";
		expect(raw).toContain(`"input":${rawInput}`);
		expect(raw).toContain(`"output":${rawOutput}`);
	});

	it("preserves '$' sequences in input/output (no String.replace pattern interpretation)", async () => {
		// String.prototype.replace treats '$&', '$1', etc. as backreferences when
		// the replacement is a string. We use the function form to avoid that —
		// pin it with a payload that would be mangled if we ever regressed.
		const rawInput = '{"price":"$100","ref":"$1$&$\'"}';
		await emitter.emit({ ...GOOD_EVENT, input: rawInput });
		await waitFor(async () => (await server.frames()).length > 0);

		const raw = (await server.frames())[0] ?? "";
		expect(raw).toContain(`"input":${rawInput}`);
	});

	it("omits input and output when not provided", async () => {
		await emitter.emit(GOOD_EVENT);
		await waitFor(async () => (await server.frames()).length > 0);

		const frames = await server.frames();
		const f = JSON.parse(frames[0] ?? "{}");
		expect(f).not.toHaveProperty("input");
		expect(f).not.toHaveProperty("output");
	});

	it("includes error field when provided", async () => {
		await emitter.emit({ ...GOOD_EVENT, error: "tool failed" });
		await waitFor(async () => (await server.frames()).length > 0);

		const frames = await server.frames();
		const f = JSON.parse(frames[0] ?? "{}");
		expect(f.error).toBe("tool failed");
	});

	it("sends multiple frames in order", async () => {
		for (const decision of ["allowed", "denied", "pending"] as const) {
			await emitter.emit({ ...GOOD_EVENT, decision });
		}
		await waitFor(async () => (await server.frames()).length >= 3);

		const frames = await server.frames();
		expect(frames).toHaveLength(3);
		const decisions = frames.map((raw) => JSON.parse(raw).decision);
		expect(decisions).toEqual(["allowed", "denied", "pending"]);
	});
});

describe("DaemonEmitter — session_id stability", () => {
	it("session_id is stable across multiple emits", async () => {
		const sockPath = tempSockPath("session");
		const server = startEchoServer(sockPath);
		await server.ready;
		const emitter = new DaemonEmitter({ socketPath: sockPath });

		await emitter.emit(GOOD_EVENT);
		await emitter.emit(GOOD_EVENT);
		await waitFor(async () => (await server.frames()).length >= 2);

		const frames = await server.frames();
		const ids = frames.map((raw) => JSON.parse(raw).session_id);
		expect(ids[0]).toBe(ids[1]);
		expect(ids[0]).toBe(emitter.sessionId);

		emitter.close();
		await server.stop();
	});

	it("host-supplied sessionId is used and stable", async () => {
		const sockPath = tempSockPath("supplied-session");
		const server = startEchoServer(sockPath);
		await server.ready;
		const emitter = new DaemonEmitter({
			socketPath: sockPath,
			sessionId: "my-session-42",
		});

		expect(emitter.sessionId).toBe("my-session-42");

		await emitter.emit(GOOD_EVENT);
		await waitFor(async () => (await server.frames()).length > 0);

		const frames = await server.frames();
		const f = JSON.parse(frames[0] ?? "{}");
		expect(f.session_id).toBe("my-session-42");

		emitter.close();
		await server.stop();
	});

	it("empty sessionId falls back to a generated UUID", () => {
		const emitter = new DaemonEmitter({
			socketPath: tempSockPath("empty-session"),
			sessionId: "",
		});
		expect(emitter.sessionId).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
		);
		emitter.close();
	});
});

describe("DaemonEmitter — surfaces transport failure when daemon is down", () => {
	it("resolves with EmitTransportError quickly when no daemon is listening", async () => {
		const sockPath = tempSockPath("down");
		const emitter = new DaemonEmitter({ socketPath: sockPath });

		const start = Date.now();
		const err = await emitter.emit(GOOD_EVENT);
		const elapsed = Date.now() - start;

		expect(err).toBeInstanceOf(EmitTransportError);
		// Non-blocking: a dial failure is detected well within the 150ms bound
		// (dial timeout is 25ms; the failure surfaces in roughly that time).
		expect(elapsed).toBeLessThan(150);

		emitter.close();
	});

	it("resolves with null under bestEffort when no daemon is listening", async () => {
		const sockPath = tempSockPath("down-best-effort");
		const emitter = new DaemonEmitter({
			socketPath: sockPath,
			bestEffort: true,
		});

		const start = Date.now();
		const err = await emitter.emit(GOOD_EVENT);
		const elapsed = Date.now() - start;

		expect(err).toBeNull();
		expect(elapsed).toBeLessThan(150);

		emitter.close();
	});

	it("transport failure is distinct from a caller-bug Error", async () => {
		const sockPath = tempSockPath("down-distinct");
		const emitter = new DaemonEmitter({ socketPath: sockPath });

		const callerBug = await emitter.emit({
			...GOOD_EVENT,
			// @ts-expect-error intentionally invalid decision to exercise caller-bug validation
			decision: "nope",
		});
		expect(callerBug).toBeInstanceOf(Error);
		expect(callerBug).not.toBeInstanceOf(EmitTransportError);

		const transport = await emitter.emit(GOOD_EVENT);
		expect(transport).toBeInstanceOf(EmitTransportError);

		emitter.close();
	});

	it("logs a drop when daemon is down (debugLog is called)", async () => {
		const sockPath = tempSockPath("drop-log");
		const drops: Array<{ message: string; attrs: Record<string, string> }> = [];
		const emitter = new DaemonEmitter({
			socketPath: sockPath,
			debugLog: (message, attrs) => drops.push({ message, attrs }),
		});

		await emitter.emit(GOOD_EVENT);

		expect(drops).toHaveLength(1);
		expect(drops[0]?.message).toMatch(/dropped event/);
		expect(drops[0]?.attrs.stage).toBe("dial");

		emitter.close();
	});
});

describe("DaemonEmitter — reconnect after daemon restart", () => {
	it("re-dials after the server stops and restarts", async () => {
		const sockPath = tempSockPath("reconnect");
		const server1 = startEchoServer(sockPath);
		await server1.ready;
		const emitter = new DaemonEmitter({ socketPath: sockPath });

		// First emit reaches server1.
		await emitter.emit(GOOD_EVENT);
		await waitFor(async () => (await server1.frames()).length > 0);
		expect(await server1.frames()).toHaveLength(1);

		// Stop server1 and emit — connection is broken, re-dial fails (no
		// server), so the transport failure surfaces (ADR-0025).
		await server1.stop();
		const errAfterStop = await emitter.emit(GOOD_EVENT);
		expect(errAfterStop).toBeInstanceOf(EmitTransportError);

		// Restart on the same socket path, then emit again — should re-dial.
		const server2 = startEchoServer(sockPath);
		await server2.ready;

		const errAfterRestart = await emitter.emit(GOOD_EVENT);
		expect(errAfterRestart).toBeNull();

		await waitFor(async () => (await server2.frames()).length > 0);
		expect(await server2.frames()).toHaveLength(1);

		emitter.close();
		await server2.stop();
	});
});

describe("DaemonEmitter — frame size limit", () => {
	it("returns an error for oversized frames", async () => {
		const sockPath = tempSockPath("oversize");
		const emitter = new DaemonEmitter({ socketPath: sockPath });
		// Construct a JSON string that, when marshalled into the full frame, exceeds 1 MiB.
		// A 1 MiB payload string alone is sufficient.
		const bigInput = JSON.stringify("x".repeat(MAX_FRAME_SIZE));
		const err = await emitter.emit({ ...GOOD_EVENT, input: bigInput });
		expect(err).toBeInstanceOf(Error);
		expect(err?.message).toMatch(/frame too large/);
		emitter.close();
	});
});

describe("resolveSocketPath", () => {
	// Helper: build a SocketPathDeps from an inline spec so each test reads as
	// a single object literal rather than three separate stubs.
	function deps(spec: {
		platform: NodeJS.Platform;
		env?: NodeJS.ProcessEnv;
		home?: string;
	}): SocketPathDeps {
		return {
			platform: () => spec.platform,
			env: spec.env ?? {},
			homedir: () => spec.home ?? "",
		};
	}

	it("respects AGENTRECEIPTS_SOCKET on every platform", () => {
		// Env override wins even on platforms with no default — explicit
		// configuration must never be silently swallowed by an unrelated
		// HOME/XDG resolution failure (Copilot finding on PR #547).
		for (const os of ["darwin", "linux", "win32"] as NodeJS.Platform[]) {
			expect(
				resolveSocketPath(
					deps({ platform: os, env: { AGENTRECEIPTS_SOCKET: "/x.sock" } }),
				),
			).toBe("/x.sock");
		}
	});

	// Issue #545: macOS must resolve against $HOME, not $TMPDIR, so a
	// process spawned without TMPDIR (Claude Desktop's MCP children, for
	// instance) still finds the same socket the daemon is listening on.
	// Injecting platform/env/homedir lets this regression run on Linux CI
	// where sdk-ts is actually built; the Go daemon CI matrix covers the
	// behaviour on a real macOS host.
	it("darwin: resolves to ~/.local/share/agent-receipts/events.sock by default", () => {
		expect(
			resolveSocketPath(deps({ platform: "darwin", home: "/Users/testuser" })),
		).toBe("/Users/testuser/.local/share/agent-receipts/events.sock");
	});

	it("darwin: ignores TMPDIR (#545 regression guard)", () => {
		const got = resolveSocketPath(
			deps({
				platform: "darwin",
				env: { TMPDIR: "/fake-tmpdir" },
				home: "/Users/testuser",
			}),
		);
		expect(got).not.toContain("/fake-tmpdir");
		expect(got).toMatch(/\/\.local\/share\/agent-receipts\/events\.sock$/);
	});

	it("darwin: honours an absolute XDG_DATA_HOME", () => {
		expect(
			resolveSocketPath(
				deps({
					platform: "darwin",
					env: { XDG_DATA_HOME: "/srv/data" },
					home: "/Users/testuser",
				}),
			),
		).toBe("/srv/data/agent-receipts/events.sock");
	});

	it("darwin: ignores a relative XDG_DATA_HOME per the XDG spec", () => {
		// A relative value must not silently relocate the socket under the
		// caller's CWD — the daemon's xdgDataHome makes the same guarantee.
		expect(
			resolveSocketPath(
				deps({
					platform: "darwin",
					env: { XDG_DATA_HOME: "relative/data" },
					home: "/Users/testuser",
				}),
			),
		).toBe("/Users/testuser/.local/share/agent-receipts/events.sock");
	});

	it("darwin: returns '' when HOME cannot be resolved", () => {
		// xdgDataHome bails on an unresolvable HOME; the public surface
		// surfaces this as '' so the Emitter constructor can raise a clean
		// "pass socketPath explicitly" error.
		expect(resolveSocketPath(deps({ platform: "darwin", home: "" }))).toBe("");
	});

	it("linux: prefers XDG_RUNTIME_DIR over the /run fallback", () => {
		expect(
			resolveSocketPath(
				deps({
					platform: "linux",
					env: { XDG_RUNTIME_DIR: "/run/user/1000" },
				}),
			),
		).toBe("/run/user/1000/agentreceipts/events.sock");
	});

	it("linux: falls back to /run/agentreceipts/events.sock without XDG_RUNTIME_DIR", () => {
		expect(resolveSocketPath(deps({ platform: "linux" }))).toBe(
			"/run/agentreceipts/events.sock",
		);
	});

	it("returns '' on unsupported platforms with no env override", () => {
		expect(resolveSocketPath(deps({ platform: "win32" }))).toBe("");
	});
});

describe("defaultSocketPath", () => {
	// Smoke check: defaultSocketPath must wire the real platform/env/homedir
	// into resolveSocketPath. The exhaustive branch coverage lives in the
	// resolveSocketPath suite above; this test exists so a future refactor
	// that breaks the wiring (drops a dep, swaps the order) fails loudly.
	it("returns a non-empty path on this host (darwin or linux)", () => {
		const original = process.env.AGENTRECEIPTS_SOCKET;
		delete process.env.AGENTRECEIPTS_SOCKET;
		try {
			const p = defaultSocketPath();
			const os = process.platform;
			if (os === "darwin" || os === "linux") {
				expect(p).not.toBe("");
				expect(p).toMatch(/events\.sock$/);
			}
		} finally {
			if (original !== undefined) {
				process.env.AGENTRECEIPTS_SOCKET = original;
			}
		}
	});
});

describe("DaemonEmitter — constructor", () => {
	it("throws when socketPath is an empty string and no env override is set", () => {
		// An explicit empty socketPath replicates the same failure code path
		// that occurs on platforms where defaultSocketPath() returns "".
		// (??-fallback only triggers on null/undefined, so "" reaches the
		// !socketPath guard.) The constructor must reject this with an
		// actionable error rather than silently producing an unusable emitter.
		const original = process.env.AGENTRECEIPTS_SOCKET;
		delete process.env.AGENTRECEIPTS_SOCKET;
		try {
			expect(() => new DaemonEmitter({ socketPath: "" })).toThrow(
				/no default socket path/,
			);
		} finally {
			if (original !== undefined) {
				process.env.AGENTRECEIPTS_SOCKET = original;
			}
		}
	});

	it("does not throw when given a valid explicit socket path", () => {
		expect(
			() => new DaemonEmitter({ socketPath: "/tmp/test.sock" }),
		).not.toThrow();
	});
});

describe("DaemonEmitter — socket-error robustness", () => {
	// Reach into the private conn to simulate Node firing an 'error' event on
	// the underlying socket (peer reset, daemon crash, EPIPE). Without a
	// permanent error listener the host process would crash via Node's
	// unhandled-'error' rule. These tests pin that contract.
	function getConn(emitter: DaemonEmitter): import("node:net").Socket | null {
		// @ts-expect-error accessing private conn for test assertions
		return emitter.conn;
	}

	it("surviving an 'error' event on a live conn does not crash the process", async () => {
		const sockPath = tempSockPath("err-survive");
		const server = startEchoServer(sockPath);
		await server.ready;
		const drops: string[] = [];
		const emitter = new DaemonEmitter({
			socketPath: sockPath,
			debugLog: (_msg, attrs) => {
				if (attrs.stage) drops.push(attrs.stage);
			},
		});

		// Establish a live connection.
		await emitter.emit(GOOD_EVENT);
		await waitFor(async () => (await server.frames()).length > 0);

		const conn = getConn(emitter);
		expect(conn).not.toBeNull();
		// At least one listener must be attached for 'error' so the next
		// peer-side mishap cannot crash the host.
		expect(conn?.listenerCount("error")).toBeGreaterThan(0);

		// Simulate a peer reset. Without the permanent listener this would
		// throw an unhandled 'error' and tear the process down.
		conn?.emit("error", new Error("synthetic ECONNRESET"));

		// Listener should have logged the drop and cleared the conn.
		expect(drops).toContain("socket");
		expect(getConn(emitter)).toBeNull();

		emitter.close();
		await server.stop();
	});

	it("re-dials transparently after a socket error event", async () => {
		const sockPath = tempSockPath("err-redial");
		const server = startEchoServer(sockPath);
		await server.ready;
		const emitter = new DaemonEmitter({ socketPath: sockPath });

		// First emit dials and delivers.
		await emitter.emit(GOOD_EVENT);
		await waitFor(async () => (await server.frames()).length > 0);

		// Inject a synthetic error on the live conn — the permanent listener
		// must clear it without throwing.
		getConn(emitter)?.emit("error", new Error("synthetic peer reset"));

		// Next emit should re-dial and deliver another frame to the SAME
		// echo server (it never went away).
		await emitter.emit(GOOD_EVENT);
		await waitFor(async () => (await server.frames()).length >= 2);
		expect(await server.frames()).toHaveLength(2);

		emitter.close();
		await server.stop();
	});

	it("is safe to close while a dial is in flight", async () => {
		// Connect to a server that exists, then call close() before the
		// connect callback has fired. The freshly connected socket must be
		// destroyed and not retained.
		const sockPath = tempSockPath("close-during-dial");
		const server = startEchoServer(sockPath);
		await server.ready;
		const emitter = new DaemonEmitter({ socketPath: sockPath });

		const emitPromise = emitter.emit(GOOD_EVENT);
		// Close immediately. Depending on timing this may or may not race
		// the connect callback, but neither outcome must crash or leak.
		emitter.close();

		const result = await emitPromise;
		// Either null (silently dropped) or the closed Error — both acceptable.
		if (result !== null) {
			expect(result.message).toMatch(/closed/);
		}

		await server.stop();
	});
});
