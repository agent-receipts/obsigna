import { describe, expect, it } from "vitest";
import {
	ALL_ACTIONS,
	FILESYSTEM_ACTIONS,
	getActionType,
	resolveActionType,
	SYSTEM_ACTIONS,
	UNKNOWN_ACTION,
} from "./actions.js";

describe("action taxonomy", () => {
	it("has 8 filesystem actions", () => {
		expect(FILESYSTEM_ACTIONS).toHaveLength(8);
	});

	it("has 10 system actions", () => {
		expect(SYSTEM_ACTIONS).toHaveLength(10);
	});

	it("has 23 total actions (filesystem + system + data + network + unknown)", () => {
		expect(ALL_ACTIONS).toHaveLength(23);
	});

	it("all action types are unique", () => {
		const types = ALL_ACTIONS.map((a) => a.type);
		expect(new Set(types).size).toBe(types.length);
	});

	it("all actions have valid risk levels", () => {
		for (const action of ALL_ACTIONS) {
			expect(["low", "medium", "high", "critical"]).toContain(
				action.risk_level,
			);
		}
	});
});

describe("getActionType", () => {
	it("returns the entry for a known action type", () => {
		const entry = getActionType("filesystem.file.read");
		expect(entry).toEqual({
			type: "filesystem.file.read",
			description: "Read a file",
			risk_level: "low",
		});
	});

	it("returns undefined for an unknown action type", () => {
		expect(getActionType("nonexistent.action")).toBeUndefined();
	});

	it("returns the unknown action entry for 'unknown'", () => {
		expect(getActionType("unknown")).toEqual(UNKNOWN_ACTION);
	});
});

describe("resolveActionType", () => {
	it("returns the correct entry for known types", () => {
		expect(resolveActionType("filesystem.file.delete").risk_level).toBe("high");
		expect(resolveActionType("system.browser.navigate").risk_level).toBe("low");
	});

	it("falls back to unknown for unrecognized types", () => {
		const result = resolveActionType("something.totally.new");
		expect(result.type).toBe("unknown");
		expect(result.risk_level).toBe("medium");
	});
});
