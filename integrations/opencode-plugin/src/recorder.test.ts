import type { EmitEvent } from "@obsigna/sdk-ts/emitter";
import { describe, expect, it, vi } from "vitest";
import { type ResolvedConfig, resolveConfig } from "./config.js";
import {
	type EmitterFactory,
	type ReceiptEmitter,
	ReceiptRecorder,
} from "./recorder.js";

/** A capturing emitter: records every event and reports whether it was closed. */
class FakeEmitter implements ReceiptEmitter {
	readonly events: EmitEvent[] = [];
	closed = false;
	constructor(
		readonly sessionID: string,
		private readonly failWith: Error | null = null,
	) {}
	emit(ev: EmitEvent): Promise<Error | null> {
		this.events.push(ev);
		return Promise.resolve(this.failWith);
	}
	close(): void {
		this.closed = true;
	}
}

/** Build a recorder wired to a capturing factory; returns both for assertions. */
function harness(
	overrides: Parameters<typeof resolveConfig>[0] = {},
	failWith: Error | null = null,
): {
	recorder: ReceiptRecorder;
	emitters: Map<string, FakeEmitter>;
	config: ResolvedConfig;
} {
	const emitters = new Map<string, FakeEmitter>();
	const config = resolveConfig({ debugLog: () => {}, ...overrides }, {});
	const factory: EmitterFactory = (sessionID) => {
		const e = new FakeEmitter(sessionID, failWith);
		emitters.set(sessionID, e);
		return e;
	};
	return { recorder: new ReceiptRecorder(config, factory), emitters, config };
}

describe("ReceiptRecorder — one receipt per native tool call", () => {
	it("emits an allowed receipt with mapped action_type, input and output", async () => {
		const { recorder, emitters } = harness();
		await recorder.recordResult({
			tool: "bash",
			sessionID: "s1",
			callID: "c1",
			args: { command: "go test ./..." },
			title: "go test",
			output: "ok",
			metadata: { exit: 0 },
		});

		const ev = emitters.get("s1")?.events[0];
		expect(ev).toBeDefined();
		expect(ev?.channel).toBe("opencode");
		expect(ev?.tool).toEqual({ name: "bash" });
		expect(ev?.actionType).toBe("system.command.execute");
		expect(ev?.decision).toBe("allowed");
		expect(JSON.parse(ev?.input ?? "null")).toEqual({
			command: "go test ./...",
		});
		expect(JSON.parse(ev?.output ?? "null")).toEqual({
			title: "go test",
			output: "ok",
			metadata: { exit: 0 },
		});
	});

	it("omits action_type for unmapped tools so the daemon falls back", async () => {
		const { recorder, emitters } = harness();
		await recorder.recordResult({
			tool: "task",
			sessionID: "s1",
			callID: "c1",
			args: {},
		});
		expect(emitters.get("s1")?.events[0]?.actionType).toBeUndefined();
	});

	it("forwards a tool error message", async () => {
		const { recorder, emitters } = harness();
		await recorder.recordResult({
			tool: "bash",
			sessionID: "s1",
			callID: "c1",
			args: {},
			error: "exit status 1",
		});
		expect(emitters.get("s1")?.events[0]?.error).toBe("exit status 1");
	});
});

describe("ReceiptRecorder — file-identity target", () => {
	it.each(["edit", "write", "read"])(
		"sets a filesystem target from filePath for %s",
		async (tool) => {
			const { recorder, emitters } = harness();
			await recorder.recordResult({
				tool,
				sessionID: "s1",
				callID: "c1",
				args: { filePath: "src/recorder.ts" },
			});
			expect(emitters.get("s1")?.events[0]?.target).toEqual({
				system: "filesystem",
				resource: "src/recorder.ts",
			});
		},
	);

	it("trims surrounding whitespace from the resource path", async () => {
		const { recorder, emitters } = harness();
		await recorder.recordResult({
			tool: "write",
			sessionID: "s1",
			callID: "c1",
			args: { filePath: "  a.ts  " },
		});
		expect(emitters.get("s1")?.events[0]?.target).toEqual({
			system: "filesystem",
			resource: "a.ts",
		});
	});

	it("leaves target unset for a tool with no filePath (bash command)", async () => {
		const { recorder, emitters } = harness();
		await recorder.recordResult({
			tool: "bash",
			sessionID: "s1",
			callID: "c1",
			args: { command: "go test ./..." },
		});
		expect(emitters.get("s1")?.events[0]?.target).toBeUndefined();
	});

	it("leaves target unset for grep (pattern arg, no filePath)", async () => {
		const { recorder, emitters } = harness();
		await recorder.recordResult({
			tool: "grep",
			sessionID: "s1",
			callID: "c1",
			args: { pattern: "TODO" },
		});
		expect(emitters.get("s1")?.events[0]?.target).toBeUndefined();
	});

	it("leaves target unset for an empty or whitespace filePath", async () => {
		const { recorder, emitters } = harness();
		await recorder.recordResult({
			tool: "write",
			sessionID: "s1",
			callID: "c1",
			args: { filePath: "   " },
		});
		await recorder.recordResult({
			tool: "write",
			sessionID: "s1",
			callID: "c2",
			args: { filePath: "" },
		});
		const events = emitters.get("s1")?.events ?? [];
		expect(events[0]?.target).toBeUndefined();
		expect(events[1]?.target).toBeUndefined();
	});

	it("leaves target unset for a non-string filePath", async () => {
		const { recorder, emitters } = harness();
		await recorder.recordResult({
			tool: "write",
			sessionID: "s1",
			callID: "c1",
			args: { filePath: 42 },
		});
		expect(emitters.get("s1")?.events[0]?.target).toBeUndefined();
	});
});

describe("ReceiptRecorder — intent/params bridging", () => {
	it("falls back to before-hook args when the after-hook omits them", async () => {
		const { recorder, emitters } = harness();
		recorder.recordIntent({
			tool: "edit",
			sessionID: "s1",
			callID: "c1",
			args: { filePath: "a.ts" },
		});
		await recorder.recordResult({
			tool: "edit",
			sessionID: "s1",
			callID: "c1",
			// no args here — must use the stashed intent args
			output: "edited",
		});
		expect(JSON.parse(emitters.get("s1")?.events[0]?.input ?? "null")).toEqual({
			filePath: "a.ts",
		});
	});

	it("prefers after-hook args over stashed intent args", async () => {
		const { recorder, emitters } = harness();
		recorder.recordIntent({
			tool: "edit",
			sessionID: "s1",
			callID: "c1",
			args: { filePath: "old.ts" },
		});
		await recorder.recordResult({
			tool: "edit",
			sessionID: "s1",
			callID: "c1",
			args: { filePath: "new.ts" },
		});
		expect(JSON.parse(emitters.get("s1")?.events[0]?.input ?? "null")).toEqual({
			filePath: "new.ts",
		});
	});
});

describe("ReceiptRecorder — allow/deny filtering", () => {
	it("does not emit for denied tools", async () => {
		const { recorder, emitters } = harness({ deny: ["read"] });
		await recorder.recordResult({
			tool: "read",
			sessionID: "s1",
			callID: "c1",
			args: {},
		});
		expect(emitters.has("s1")).toBe(false);
	});

	it("emits only for allow-listed tools", async () => {
		const { recorder, emitters } = harness({ allow: ["bash"] });
		await recorder.recordResult({
			tool: "edit",
			sessionID: "s1",
			callID: "c1",
			args: {},
		});
		await recorder.recordResult({
			tool: "bash",
			sessionID: "s1",
			callID: "c2",
			args: {},
		});
		expect(emitters.get("s1")?.events.map((e) => e.tool.name)).toEqual([
			"bash",
		]);
	});
});

describe("ReceiptRecorder — per-session emitters (chain mapping)", () => {
	it("uses a distinct emitter per sessionID, including a subagent session", async () => {
		const { recorder, emitters } = harness();
		await recorder.recordResult({
			tool: "bash",
			sessionID: "root",
			callID: "c1",
			args: {},
		});
		await recorder.recordResult({
			tool: "write",
			sessionID: "subagent",
			callID: "c2",
			args: {},
		});
		expect([...emitters.keys()].sort()).toEqual(["root", "subagent"]);
		expect(emitters.get("root")?.events).toHaveLength(1);
		expect(emitters.get("subagent")?.events).toHaveLength(1);
	});

	it("reuses one emitter across calls in the same session", async () => {
		const { recorder, emitters } = harness();
		await recorder.recordResult({
			tool: "bash",
			sessionID: "s1",
			callID: "c1",
			args: {},
		});
		await recorder.recordResult({
			tool: "bash",
			sessionID: "s1",
			callID: "c2",
			args: {},
		});
		expect(emitters.size).toBe(1);
		expect(emitters.get("s1")?.events).toHaveLength(2);
	});

	it("closeSession closes and forgets the emitter", async () => {
		const { recorder, emitters } = harness();
		await recorder.recordResult({
			tool: "bash",
			sessionID: "s1",
			callID: "c1",
			args: {},
		});
		const first = emitters.get("s1");
		recorder.closeSession("s1");
		expect(first?.closed).toBe(true);

		// A later call re-creates a fresh emitter.
		await recorder.recordResult({
			tool: "bash",
			sessionID: "s1",
			callID: "c2",
			args: {},
		});
		expect(emitters.get("s1")).not.toBe(first);
	});

	it("closeSession reclaims pending intents whose tool call never completed", async () => {
		const { recorder, emitters } = harness();
		// `before` fires for a call that is cancelled before `after` runs.
		recorder.recordIntent({
			tool: "edit",
			sessionID: "s1",
			callID: "orphan",
			args: { filePath: "stale.ts" },
		});
		recorder.closeSession("s1");

		// A later result for that callID (no args) must NOT resurrect the stale
		// intent — it was reclaimed, so no input is attached.
		await recorder.recordResult({
			tool: "edit",
			sessionID: "s1",
			callID: "orphan",
		});
		expect(emitters.get("s1")?.events[0]?.input).toBeUndefined();
	});
});

describe("ReceiptRecorder — failure posture (ADR-0025)", () => {
	it("default: logs loudly and does NOT throw on emit failure", async () => {
		const debugLog = vi.fn();
		const { recorder } = harness({ debugLog }, new Error("daemon unreachable"));
		await expect(
			recorder.recordResult({
				tool: "bash",
				sessionID: "s1",
				callID: "c1",
				args: {},
			}),
		).resolves.toBeUndefined();
		expect(debugLog).toHaveBeenCalledOnce();
		expect(debugLog.mock.calls[0]?.[1]).toMatchObject({
			tool: "bash",
			err: "daemon unreachable",
		});
	});

	it("strict: re-throws the emit failure", async () => {
		const { recorder } = harness(
			{ strict: true },
			new Error("daemon unreachable"),
		);
		await expect(
			recorder.recordResult({
				tool: "bash",
				sessionID: "s1",
				callID: "c1",
				args: {},
			}),
		).rejects.toThrow("daemon unreachable");
	});
});

describe("ReceiptRecorder — teardown", () => {
	it("close() closes all emitters and stops emitting", async () => {
		const { recorder, emitters } = harness();
		await recorder.recordResult({
			tool: "bash",
			sessionID: "s1",
			callID: "c1",
			args: {},
		});
		recorder.close();
		expect(emitters.get("s1")?.closed).toBe(true);

		await recorder.recordResult({
			tool: "bash",
			sessionID: "s2",
			callID: "c2",
			args: {},
		});
		expect(emitters.has("s2")).toBe(false);
	});
});
