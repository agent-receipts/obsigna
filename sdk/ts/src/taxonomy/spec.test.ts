import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ALL_ACTIONS, getActionType } from "./actions.js";

const specPath = join(
	import.meta.dirname,
	"../../../../spec/spec/taxonomy/action-types.json",
);

interface SpecAction {
	type: string;
	description: string;
	risk_level: string;
}

interface SpecDomain {
	description: string;
	actions: SpecAction[];
}

interface SpecTaxonomy {
	version: string;
	domains: Record<string, SpecDomain>;
}

const spec: SpecTaxonomy = JSON.parse(readFileSync(specPath, "utf-8"));

// Domains the SDK implements; must match sdk/go/taxonomy/spec_test.go so all
// three SDKs sign the same risk_level for the same action type.
const IMPLEMENTED_DOMAINS = ["filesystem", "system", "network"];

describe("taxonomy matches spec action-types.json", () => {
	for (const domainName of IMPLEMENTED_DOMAINS) {
		describe(domainName, () => {
			it("exists in the spec", () => {
				expect(spec.domains[domainName]).toBeDefined();
			});

			for (const specAction of spec.domains[domainName]?.actions ?? []) {
				it(specAction.type, () => {
					const entry = getActionType(specAction.type);
					expect(entry, `TS SDK missing ${specAction.type}`).toBeDefined();
					expect(entry?.description).toBe(specAction.description);
					expect(entry?.risk_level).toBe(specAction.risk_level);
				});
			}
		});
	}
});

describe("every SDK action type is in the spec", () => {
	const specTypes = new Set<string>();
	for (const domain of Object.values(spec.domains)) {
		for (const action of domain.actions) {
			specTypes.add(action.type);
		}
	}

	// "unknown" is the SDK fallback and doctor.* types classify a daemon/CLI
	// self-check rather than an agent tool call; neither is in the spec.
	const sdkTypes = ALL_ACTIONS.map((a) => a.type).filter(
		(t) => t !== "unknown" && !t.startsWith("doctor."),
	);

	for (const type of sdkTypes) {
		it(type, () => {
			expect(specTypes.has(type)).toBe(true);
		});
	}
});

describe("spec risk levels are valid", () => {
	it("every spec action has a valid risk_level", () => {
		for (const domain of Object.values(spec.domains)) {
			for (const action of domain.actions) {
				expect(["low", "medium", "high", "critical"]).toContain(
					action.risk_level,
				);
			}
		}
	});
});
