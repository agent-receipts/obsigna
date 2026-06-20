import { describe, expect, it } from "vitest";
import {
	type GrantInfo,
	type GrantResolver,
	GroundedOutcome,
	type GroundedPrincipalViolation,
	verifyGroundedPrincipalTier,
} from "./grant-resolver.js";
import { generateKeyPair, signReceipt } from "./signing.js";
import type { AgentReceipt, RiskLevel } from "./types.js";

// --- test helpers ---

function makeGroundedReceipt(
	principalId: string,
	riskLevel: RiskLevel,
	grantRef: string | undefined,
): AgentReceipt {
	const unsigned = {
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://agentreceipts.ai/context/v2",
		] as const,
		id: "urn:receipt:00000000-0000-0000-0000-000000000001",
		type: ["VerifiableCredential", "AgentReceipt"] as const,
		version: "0.5.0",
		issuer: { id: "did:key:z6Mk1" },
		issuanceDate: new Date().toISOString(),
		credentialSubject: {
			principal: { id: principalId },
			action: {
				id: "act_00000000-0000-0000-0000-000000000001",
				type: "filesystem.file.write",
				risk_level: riskLevel,
				timestamp: new Date().toISOString(),
			},
			outcome: { status: "success" as const },
			chain: {
				sequence: 1,
				previous_receipt_hash: null,
				chain_id: "chain-grounded-1",
			},
			...(grantRef !== undefined
				? {
						authorization: {
							scopes: ["files:write"],
							granted_at: new Date().toISOString(),
							grant_ref: grantRef,
						},
					}
				: {}),
		},
	};
	const { privateKey } = generateKeyPair();
	return signReceipt(unsigned, privateKey, "did:key:z6Mk1#key-1");
}

class StubResolver implements GrantResolver {
	constructor(
		private readonly grants: Map<string, GrantInfo>,
		private readonly errorRefs: Set<string> = new Set(),
	) {}

	resolveGrant(grantRef: string, _principalId: string): Promise<GrantInfo> {
		if (this.errorRefs.has(grantRef)) {
			return Promise.reject(new Error("resolver: grant not found"));
		}
		const g = this.grants.get(grantRef);
		if (g === undefined) {
			return Promise.reject(new Error("resolver: unknown grant ref"));
		}
		return Promise.resolve(g);
	}
}

// --- tests ---

describe("verifyGroundedPrincipalTier", () => {
	it("returns no violations when resolver is null (base-tier verifier)", async () => {
		const r = makeGroundedReceipt("did:user:alice", "high", undefined);
		const violations = await verifyGroundedPrincipalTier([r], null);
		expect(violations).toHaveLength(0);
	});

	it("skips low and medium receipts even with a resolver configured", async () => {
		const resolver = new StubResolver(new Map());
		const low = makeGroundedReceipt("did:user:alice", "low", undefined);
		const med = makeGroundedReceipt("did:user:alice", "medium", undefined);
		const violations = await verifyGroundedPrincipalTier([low, med], resolver);
		expect(violations).toHaveLength(0);
	});

	it("returns UNGROUNDED_PRINCIPAL for a high receipt with no grant_ref", async () => {
		const resolver = new StubResolver(new Map());
		const r = makeGroundedReceipt("did:user:alice", "high", undefined);
		const violations = await verifyGroundedPrincipalTier([r], resolver);
		expect(violations).toHaveLength(1);
		expect(violations[0]?.outcome).toBe(GroundedOutcome.UngroundedPrincipal);
	});

	it("returns UNGROUNDED_PRINCIPAL for a high receipt with empty grant_ref", async () => {
		const resolver = new StubResolver(new Map());
		const r = makeGroundedReceipt("did:user:alice", "high", "");
		const violations = await verifyGroundedPrincipalTier([r], resolver);
		expect(violations).toHaveLength(1);
		expect(violations[0]?.outcome).toBe(GroundedOutcome.UngroundedPrincipal);
	});

	it("returns UNGROUNDED_PRINCIPAL when the resolver rejects for the grant_ref", async () => {
		const resolver = new StubResolver(new Map(), new Set(["bad-ref"]));
		const r = makeGroundedReceipt("did:user:alice", "high", "bad-ref");
		const violations = await verifyGroundedPrincipalTier([r], resolver);
		expect(violations).toHaveLength(1);
		expect(violations[0]?.outcome).toBe(GroundedOutcome.UngroundedPrincipal);
	});

	it("returns PRINCIPAL_GRANT_MISMATCH when resolved subject does not equal principal.id", async () => {
		const resolver = new StubResolver(
			new Map([
				["grant-abc", { subject: "did:user:bob", scopes: ["files:write"] }],
			]),
		);
		const r = makeGroundedReceipt("did:user:alice", "high", "grant-abc");
		const violations = await verifyGroundedPrincipalTier([r], resolver);
		expect(violations).toHaveLength(1);
		expect(violations[0]?.outcome).toBe(GroundedOutcome.PrincipalGrantMismatch);
	});

	it("returns no violation when the grant resolves and subject equals principal.id", async () => {
		const resolver = new StubResolver(
			new Map([
				["grant-xyz", { subject: "did:user:alice", scopes: ["files:write"] }],
			]),
		);
		const r = makeGroundedReceipt("did:user:alice", "high", "grant-xyz");
		const violations = await verifyGroundedPrincipalTier([r], resolver);
		expect(violations).toHaveLength(0);
	});

	it("checks critical receipts alongside high receipts", async () => {
		const resolver = new StubResolver(new Map());
		const r = makeGroundedReceipt("did:user:alice", "critical", undefined);
		const violations = await verifyGroundedPrincipalTier([r], resolver);
		expect(violations).toHaveLength(1);
		expect(violations[0]?.outcome).toBe(GroundedOutcome.UngroundedPrincipal);
	});

	it("collects all violations rather than stopping at the first", async () => {
		const resolver = new StubResolver(
			new Map([["grant-good", { subject: "did:user:alice", scopes: [] }]]),
			new Set(["grant-bad"]),
		);
		const r1 = makeGroundedReceipt("did:user:alice", "high", undefined); // UNGROUNDED
		const r2 = makeGroundedReceipt("did:user:alice", "high", "grant-good"); // OK
		const r3 = makeGroundedReceipt("did:user:alice", "critical", "grant-bad"); // UNGROUNDED (resolve fails)
		const violations = await verifyGroundedPrincipalTier(
			[r1, r2, r3],
			resolver,
		);
		expect(violations).toHaveLength(2);
	});

	it("reports the correct receipt index in the violation", async () => {
		const resolver = new StubResolver(new Map());
		const low = makeGroundedReceipt("did:user:alice", "low", undefined); // index 0, skipped
		const high = makeGroundedReceipt("did:user:alice", "high", undefined); // index 1, violation
		const violations = await verifyGroundedPrincipalTier([low, high], resolver);
		expect(violations).toHaveLength(1);
		expect(violations[0]?.index).toBe(1);
	});

	it("returns no violations for an empty receipt slice", async () => {
		const resolver = new StubResolver(new Map());
		const violations = await verifyGroundedPrincipalTier([], resolver);
		expect(violations).toHaveLength(0);
	});
});

// Type-level smoke test: ensure the exported types satisfy expected shapes.
const _typeCheck: GroundedPrincipalViolation = {
	index: 0,
	receiptId: "urn:receipt:00000000-0000-0000-0000-000000000001",
	principalId: "did:user:alice",
	grantRef: "grant-abc",
	outcome: GroundedOutcome.UngroundedPrincipal,
	detail: "authorization.grant_ref is absent on a high receipt",
};
void _typeCheck;
