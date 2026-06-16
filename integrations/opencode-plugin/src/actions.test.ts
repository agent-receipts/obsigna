import { describe, expect, it } from "vitest";
import { DEFAULT_ACTION_MAP, resolveActionType } from "./actions.js";

describe("resolveActionType", () => {
	it("maps the documented native tools to taxonomy types", () => {
		expect(resolveActionType("bash")).toBe("system.command.execute");
		expect(resolveActionType("write")).toBe("filesystem.file.modify");
		expect(resolveActionType("edit")).toBe("filesystem.file.modify");
		expect(resolveActionType("read")).toBe("filesystem.file.read");
		expect(resolveActionType("webfetch")).toBe("data.api.read");
	});

	it("maps patch/apply_patch as a file modification", () => {
		expect(resolveActionType("patch")).toBe("filesystem.file.modify");
		expect(resolveActionType("apply_patch")).toBe("filesystem.file.modify");
	});

	it("returns undefined for unmapped tools so the daemon falls back", () => {
		expect(resolveActionType("task")).toBeUndefined();
		expect(resolveActionType("todowrite")).toBeUndefined();
		expect(resolveActionType("totally_unknown")).toBeUndefined();
	});

	it("lets overrides take precedence over the defaults", () => {
		expect(
			resolveActionType("webfetch", { webfetch: "system.browser.navigate" }),
		).toBe("system.browser.navigate");
	});

	it("uses overrides for tools with no default mapping", () => {
		expect(resolveActionType("task", { task: "data.api.write" })).toBe(
			"data.api.write",
		);
	});

	it("every default target is a dotted taxonomy type", () => {
		for (const type of Object.values(DEFAULT_ACTION_MAP)) {
			expect(type).toMatch(/^[a-z]+\.[a-z]+\.[a-z_]+$/);
		}
	});
});
