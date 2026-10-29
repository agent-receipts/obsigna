import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ALL_ACTIONS, getActionType, resolveActionType } from "./actions.js";

const currentDir = dirname(fileURLToPath(import.meta.url));
const specPath = resolve(
	currentDir,
	"../../../../spec/spec/taxonomy/action-types.json",
);

interface SpecAction {
	type: string;
	description: string;
	risk_level: string;
}

interface SpecTaxonomy {
	version: string;
	domains: Record<string, { description: string; actions: SpecAction[] }>;
}

const spec: SpecTaxonomy = JSON.parse(readFileSync(specPath, "utf8"));

// The TS SDK implements the filesystem, system and network domains (matching
// the Go SDK); data is partially implemented and checked by the reverse test.
const IMPLEMENTED_DOMAINS = ["filesystem", "system", "network"];

// "unknown" is the SDK fallback entry; doctor.* types classify daemon/CLI
// self-checks rather than agent tool calls. Neither is in the spec.
function isSpecTracked(type: string): boolean {
	return type !== "unknown" && !type.startsWith("doctor.");
}

describe("taxonomy matches spec", () => {
	for (const domainName of IMPLEMENTED_DOMAINS) {
		const domain = spec.domains[domainName];

		it(`spec defines the ${domainName} domain`, () => {
			expect(domain).toBeDefined();
		});

		for (const specAction of domain?.actions ?? []) {
			it(`${specAction.type} matches spec`, () => {
				const entry = getActionType(specAction.type);
				expect(entry, `TS SDK missing ${specAction.type}`).toBeDefined();
				expect(entry?.description).toBe(specAction.description);
				expect(entry?.risk_level).toBe(specAction.risk_level);
			});
		}
	}

	it("every built-in action type exists in the spec", () => {
		const specTypes = new Set(
			Object.values(spec.domains).flatMap((d) => d.actions.map((a) => a.type)),
		);
		const extra = ALL_ACTIONS.map((a) => a.type).filter(
			(t) => isSpecTracked(t) && !specTypes.has(t),
		);
		expect(extra).toEqual([]);
	});

	it("every spec risk_level is valid", () => {
		for (const domain of Object.values(spec.domains)) {
			for (const action of domain.actions) {
				expect(["low", "medium", "high", "critical"]).toContain(
					action.risk_level,
				);
			}
		}
	});
});

describe("spec action types missing from older TS taxonomy", () => {
	it("filesystem.directory.list is low", () => {
		expect(resolveActionType("filesystem.directory.list")).toEqual({
			type: "filesystem.directory.list",
			description: "List directory contents",
			risk_level: "low",
		});
	});

	it("system.code.execute is high", () => {
		const entry = resolveActionType("system.code.execute");
		expect(entry.type).toBe("system.code.execute");
		expect(entry.risk_level).toBe("high");
	});

	it("system.pty.open is critical", () => {
		const entry = resolveActionType("system.pty.open");
		expect(entry.type).toBe("system.pty.open");
		expect(entry.risk_level).toBe("critical");
	});

	it("system.pty.close is high", () => {
		const entry = resolveActionType("system.pty.close");
		expect(entry.type).toBe("system.pty.close");
		expect(entry.risk_level).toBe("high");
	});

	it("network.egress.observed resolves to the spec entry, not unknown", () => {
		expect(resolveActionType("network.egress.observed")).toEqual({
			type: "network.egress.observed",
			description:
				"Observed outbound network connection crossing a sandbox boundary",
			risk_level: "medium",
		});
	});
});
