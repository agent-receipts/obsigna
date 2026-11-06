import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ALL_ACTIONS, getActionType, resolveActionType } from "./actions.js";

// Pins the TS SDK's built-in taxonomy against the spec's canonical
// action-types.json, mirroring sdk/go/taxonomy/spec_test.go. risk_level is a
// signed receipt field, so any drift here changes signed audit records.

interface SpecAction {
	type: string;
	description: string;
	risk_level: string;
}

interface SpecTaxonomy {
	version: string;
	domains: Record<string, { description: string; actions: SpecAction[] }>;
}

const SPEC_PATH = join(
	import.meta.dirname,
	"../../../../spec/spec/taxonomy/action-types.json",
);

const spec: SpecTaxonomy = JSON.parse(readFileSync(SPEC_PATH, "utf8"));

const IMPLEMENTED_DOMAINS = ["filesystem", "system", "network"];
const IMPLEMENTED_DATA_ACTIONS = [
	"data.api.read",
	"data.api.write",
	"data.api.delete",
];

function specDomain(name: string): SpecAction[] {
	const domain = spec.domains[name];
	if (domain === undefined) {
		throw new Error(`spec missing domain ${name}`);
	}
	return domain.actions;
}

const implementedSpecActions: SpecAction[] = [
	...IMPLEMENTED_DOMAINS.flatMap(specDomain),
	...specDomain("data").filter((a) =>
		IMPLEMENTED_DATA_ACTIONS.includes(a.type),
	),
];

describe("taxonomy matches spec action-types.json", () => {
	it("covers every implemented domain and data.api action", () => {
		// Guard against the filter silently matching nothing.
		const types = implementedSpecActions.map((a) => a.type);
		for (const t of IMPLEMENTED_DATA_ACTIONS) {
			expect(types).toContain(t);
		}
		expect(types).toContain("network.egress.observed");
	});

	it.each(implementedSpecActions)(
		"$type matches spec description and risk_level",
		(specAction) => {
			const entry = getActionType(specAction.type);
			expect(
				entry,
				`TS SDK missing action type ${specAction.type}`,
			).toBeDefined();
			expect(entry?.description).toBe(specAction.description);
			expect(entry?.risk_level).toBe(specAction.risk_level);
		},
	);

	it("every SDK action except unknown exists in the spec", () => {
		const specTypes = new Set(
			Object.values(spec.domains).flatMap((d) => d.actions.map((a) => a.type)),
		);
		const missing = ALL_ACTIONS.filter(
			(a) => a.type !== "unknown" && !specTypes.has(a.type),
		).map((a) => a.type);
		expect(missing).toEqual([]);
	});
});

describe("new spec action types resolve to the spec risk level", () => {
	it.each([
		["filesystem.directory.list", "List directory contents", "low"],
		[
			"system.code.execute",
			"Execute code in a sandbox code interpreter",
			"high",
		],
		["system.pty.open", "Open an interactive PTY session", "critical"],
		["system.pty.close", "Close a PTY session", "high"],
		[
			"network.egress.observed",
			"Observed outbound network connection crossing a sandbox boundary",
			"medium",
		],
	])("%s", (type, description, riskLevel) => {
		const entry = resolveActionType(type);
		expect(entry.type).toBe(type);
		expect(entry.description).toBe(description);
		expect(entry.risk_level).toBe(riskLevel);
	});
});
