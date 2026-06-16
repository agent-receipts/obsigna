import { describe, expect, it } from "vitest";
import { resolveConfig, shouldEmit } from "./config.js";

describe("resolveConfig — defaults", () => {
	it("uses opencode channel, non-strict, no allow/deny by default", () => {
		const c = resolveConfig({}, {});
		expect(c.channel).toBe("opencode");
		expect(c.strict).toBe(false);
		expect(c.allow).toBeNull();
		expect(c.deny.size).toBe(0);
		expect(c.socketPath).toBeUndefined();
	});
});

describe("resolveConfig — explicit config wins over env", () => {
	it("prefers explicit channel and strict over env", () => {
		const c = resolveConfig(
			{ channel: "explicit", strict: false },
			{ AGENT_RECEIPTS_CHANNEL: "from-env", AGENT_RECEIPTS_STRICT: "1" },
		);
		expect(c.channel).toBe("explicit");
		expect(c.strict).toBe(false);
	});
});

describe("resolveConfig — environment variables", () => {
	it("reads channel, strict, allow, deny from env", () => {
		const c = resolveConfig(
			{},
			{
				AGENT_RECEIPTS_CHANNEL: "opencode-ci",
				AGENT_RECEIPTS_STRICT: "true",
				AGENT_RECEIPTS_ALLOW: "bash, edit ,write",
				AGENT_RECEIPTS_DENY: "read",
			},
		);
		expect(c.channel).toBe("opencode-ci");
		expect(c.strict).toBe(true);
		expect(c.allow).toEqual(new Set(["bash", "edit", "write"]));
		expect(c.deny).toEqual(new Set(["read"]));
	});

	it("treats non-truthy strict env values as false", () => {
		expect(resolveConfig({}, { AGENT_RECEIPTS_STRICT: "0" }).strict).toBe(
			false,
		);
		expect(resolveConfig({}, { AGENT_RECEIPTS_STRICT: "off" }).strict).toBe(
			false,
		);
	});
});

describe("shouldEmit", () => {
	it("allows everything when no allow/deny configured", () => {
		const c = resolveConfig({}, {});
		expect(shouldEmit(c, "bash")).toBe(true);
		expect(shouldEmit(c, "anything")).toBe(true);
	});

	it("restricts to the allow-list when set", () => {
		const c = resolveConfig({ allow: ["bash"] }, {});
		expect(shouldEmit(c, "bash")).toBe(true);
		expect(shouldEmit(c, "edit")).toBe(false);
	});

	it("deny wins over allow", () => {
		const c = resolveConfig({ allow: ["bash"], deny: ["bash"] }, {});
		expect(shouldEmit(c, "bash")).toBe(false);
	});

	it("denies listed tools while allowing the rest", () => {
		const c = resolveConfig({ deny: ["read"] }, {});
		expect(shouldEmit(c, "read")).toBe(false);
		expect(shouldEmit(c, "bash")).toBe(true);
	});
});
