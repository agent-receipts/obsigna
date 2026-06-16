/**
 * Round-trip test: drive the real {@link ReceiptRecorder} (default
 * {@link DaemonEmitter} factory) against a fake daemon Unix socket and assert
 * the wire frames. This exercises the full emitter-only path the plugin uses
 * in production — channel, mapped action_type, verbatim input/output, decision,
 * and per-session session_id — without an OpenCode runtime or the Go daemon.
 *
 * Signed-chain verification (Ed25519, hash linkage) is the daemon's job and is
 * covered end-to-end by the `agent-receipts verify` walkthrough in the docs.
 * Here we assert the shape of what reaches the daemon socket.
 *
 * The echo-server harness mirrors sdk/ts `daemon-emitter.test.ts`.
 */

import { unlinkSync } from "node:fs";
import { createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolveConfig } from "./config.js";
import { ReceiptRecorder } from "./recorder.js";

let sockSeq = 0;
function tempSockPath(): string {
	const base = process.platform === "darwin" ? "/tmp" : tmpdir();
	return join(base, `ar-oc-${process.pid}-${++sockSeq}.sock`);
}

/** Length-prefixed frame collector over AF_UNIX. */
function startEchoServer(sockPath: string): {
	frames: () => string[];
	stop: () => Promise<void>;
	ready: Promise<void>;
} {
	const received: string[] = [];
	const open = new Set<Socket>();
	const server = createServer((socket) => {
		open.add(socket);
		socket.once("close", () => open.delete(socket));
		let buf = Buffer.alloc(0);
		socket.on("data", (chunk: Buffer) => {
			buf = Buffer.concat([buf, chunk]);
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
	try {
		unlinkSync(sockPath);
	} catch {
		// no stale socket — fine
	}
	const ready = new Promise<void>((resolve, reject) => {
		server.once("listening", resolve);
		server.once("error", reject);
	});
	server.listen(sockPath);
	return {
		frames: () => [...received],
		stop: () =>
			new Promise<void>((resolve, reject) => {
				for (const s of open) {
					s.destroy();
				}
				server.close((err) => {
					try {
						unlinkSync(sockPath);
					} catch {
						// already gone — fine
					}
					err ? reject(err) : resolve();
				});
			}),
		ready,
	};
}

async function waitForFrames(
	server: ReturnType<typeof startEchoServer>,
	n: number,
	ms = 1000,
): Promise<void> {
	const deadline = Date.now() + ms;
	while (Date.now() < deadline) {
		if (server.frames().length >= n) {
			return;
		}
		await new Promise((r) => setTimeout(r, 5));
	}
	throw new Error(
		`timed out waiting for ${n} frames (got ${server.frames().length})`,
	);
}

describe("round-trip against a fake daemon socket", () => {
	let sockPath: string;
	let server: ReturnType<typeof startEchoServer>;
	let recorder: ReceiptRecorder;

	beforeEach(async () => {
		sockPath = tempSockPath();
		server = startEchoServer(sockPath);
		await server.ready;
		recorder = new ReceiptRecorder(
			resolveConfig({ socketPath: sockPath, debugLog: () => {} }, {}),
		);
	});

	afterEach(async () => {
		recorder.close();
		await server.stop();
	});

	it("delivers one frame per native tool call with mapped fields", async () => {
		recorder.recordIntent({
			tool: "bash",
			sessionID: "root",
			callID: "c1",
			args: { command: "ls" },
		});
		await recorder.recordResult({
			tool: "bash",
			sessionID: "root",
			callID: "c1",
			args: { command: "ls" },
			title: "ls",
			output: "file.txt",
			metadata: { exit: 0 },
		});

		await waitForFrames(server, 1);
		const frames = server.frames().map((f) => JSON.parse(f));
		expect(frames).toHaveLength(1);
		const f = frames[0];
		expect(f.channel).toBe("opencode");
		expect(f.tool).toEqual({ name: "bash" });
		expect(f.action_type).toBe("system.command.execute");
		expect(f.decision).toBe("allowed");
		expect(f.session_id).toBe("root");
		expect(f.input).toEqual({ command: "ls" });
		expect(f.output).toEqual({
			title: "ls",
			output: "file.txt",
			metadata: { exit: 0 },
		});
	});

	it("tags each session's frames with its own session_id (chain shape)", async () => {
		await recorder.recordResult({
			tool: "bash",
			sessionID: "root",
			callID: "c1",
			args: { command: "ls" },
		});
		await recorder.recordResult({
			tool: "write",
			sessionID: "subagent",
			callID: "c2",
			args: { filePath: "out.txt" },
		});
		await recorder.recordResult({
			tool: "edit",
			sessionID: "root",
			callID: "c3",
			args: { filePath: "out.txt" },
		});

		await waitForFrames(server, 3);
		const frames = server.frames().map((f) => JSON.parse(f));
		// Group by session_id and assert the per-session action sequence.
		const bySession = new Map<string, string[]>();
		for (const f of frames) {
			const list = bySession.get(f.session_id) ?? [];
			list.push(f.action_type ?? f.tool.name);
			bySession.set(f.session_id, list);
		}
		expect(bySession.get("root")).toEqual([
			"system.command.execute",
			"filesystem.file.modify",
		]);
		expect(bySession.get("subagent")).toEqual(["filesystem.file.modify"]);
	});

	it("preserves input bytes verbatim for the daemon to hash", async () => {
		// Whitespace and key order are preserved exactly so the daemon's
		// RFC 8785 canonicalisation hashes the bytes the plugin produced.
		const args = { b: 2, a: 1 };
		await recorder.recordResult({
			tool: "bash",
			sessionID: "root",
			callID: "c1",
			args,
		});
		await waitForFrames(server, 1);
		const raw = server.frames()[0] ?? "";
		expect(raw).toContain(`"input":${JSON.stringify(args)}`);
	});
});
