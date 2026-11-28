/**
 * Cross-SDK grounded-tier corpus (cross-sdk-tests/grounded_tier_vectors.json,
 * spec v0.7.0 §7.9, ADR-0041). The Go and Python SDKs run the same file; all
 * three must agree on every case.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	type GrantInfo,
	type GrantResolver,
	type Revocation,
	verifyGroundedPrincipalTier,
} from "./grant-resolver.js";
import type { AgentReceipt, Authorization, RiskLevel } from "./types.js";

const currentDir = dirname(fileURLToPath(import.meta.url));
const corpusPath = resolve(
	currentDir,
	"../../../../cross-sdk-tests/grounded_tier_vectors.json",
);

interface CorpusGrant {
	subject?: string;
	scopes?: string[];
	valid_from?: string;
	expires_at?: string;
	revocation?: string;
	revoked_at?: string;
	issuer?: string;
}

interface CorpusCase {
	name: string;
	clock_skew_ms: number;
	receipt: {
		risk_level: RiskLevel;
		principal_id: string;
		action_timestamp: string;
		authorization: Authorization | null;
	};
	resolver: { grant?: CorpusGrant; error?: string };
	expected: {
		config_error?: boolean;
		checked?: boolean;
		outcome?: string | null;
		warnings?: string[];
	};
}

const corpus = JSON.parse(readFileSync(corpusPath, "utf8")) as {
	cases: CorpusCase[];
};

function toDate(s: string | undefined): Date | undefined {
	return s === undefined ? undefined : new Date(s);
}

/**
 * Build a GrantInfo exactly as the corpus states it. Missing required fields
 * stay missing, so the malformed-grant cases reach the verifier as a resolver
 * written in plain JavaScript could send them.
 */
function toGrantInfo(g: CorpusGrant): GrantInfo {
	const info: Record<string, unknown> = {
		subject: g.subject,
		scopes: g.scopes,
		validFrom: toDate(g.valid_from),
		revocation: g.revocation as Revocation | undefined,
		issuer: g.issuer,
	};
	if (g.expires_at !== undefined) info.expiresAt = toDate(g.expires_at);
	if (g.revoked_at !== undefined) info.revokedAt = toDate(g.revoked_at);
	return info as unknown as GrantInfo;
}

function toReceipt(c: CorpusCase): AgentReceipt {
	return {
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://agentreceipts.ai/context/v3",
		],
		id: `urn:receipt:${c.name}`,
		type: ["VerifiableCredential", "AgentReceipt"],
		version: "0.6.0",
		issuer: { id: "did:key:z6Mk1" },
		issuanceDate: c.receipt.action_timestamp,
		credentialSubject: {
			principal: { id: c.receipt.principal_id },
			action: {
				id: "act_00000000-0000-0000-0000-000000000001",
				type: "filesystem.file.write",
				risk_level: c.receipt.risk_level,
				timestamp: c.receipt.action_timestamp,
			},
			outcome: { status: "success" },
			chain: { sequence: 1, previous_receipt_hash: null, chain_id: "chain-1" },
			...(c.receipt.authorization === null
				? {}
				: { authorization: c.receipt.authorization }),
		},
		proof: {
			type: "Ed25519Signature2020",
			created: c.receipt.action_timestamp,
			verificationMethod: "did:key:z6Mk1#key-1",
			proofPurpose: "assertionMethod",
			proofValue: "u",
		},
	} as AgentReceipt;
}

describe("grounded-tier cross-SDK corpus", () => {
	it("has cases", () => {
		expect(corpus.cases.length).toBeGreaterThan(0);
	});

	for (const c of corpus.cases) {
		it(c.name, async () => {
			const resolver: GrantResolver = {
				resolveGrant: () =>
					c.resolver.error !== undefined
						? Promise.reject(new Error(c.resolver.error))
						: Promise.resolve(toGrantInfo(c.resolver.grant ?? {})),
			};
			const run = verifyGroundedPrincipalTier([toReceipt(c)], resolver, {
				clockSkewMs: c.clock_skew_ms,
			});

			if (c.expected.config_error) {
				await expect(run).rejects.toThrow(RangeError);
				return;
			}
			const results = await run;
			if (!c.expected.checked) {
				expect(results).toEqual([]);
				return;
			}
			expect(results).toHaveLength(1);
			const [result] = results;
			expect(result?.outcome, result?.detail).toBe(c.expected.outcome ?? null);
			expect(result?.grounded).toBe((c.expected.outcome ?? null) === null);
			expect(result?.warnings.map((w) => w.code)).toEqual(
				c.expected.warnings ?? [],
			);
		});
	}
});
