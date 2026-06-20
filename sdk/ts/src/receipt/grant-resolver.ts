import type { AgentReceipt } from "./types.js";

/**
 * The resolved representation of an externally-minted authorization grant
 * (e.g. an RFC 8693 OBO token or a Grantex grant token).
 *
 * `subject` MUST be populated by all resolvers. The remaining fields are
 * advisory and MAY be omitted when the resolver's backend does not expose them.
 */
export interface GrantInfo {
	/**
	 * The principal on whose behalf the grant was issued. MUST equal
	 * `credentialSubject.principal.id` for the grounded-principal tier check
	 * to pass (spec §7.9, ADR-0038 D2).
	 */
	subject: string;
	/** Authorization scopes active under the grant. */
	scopes?: string[];
	/** When the authorization server minted the grant. */
	issuedAt?: Date;
	/** When the grant expires. */
	expiresAt?: Date;
	/** Identifies the authorization server that minted the grant. */
	issuer?: string;
}

/**
 * Resolves an authorization grant reference to its minted grant, confirming
 * the named principal delegated authority to the agent.
 *
 * Input:
 * - `grantRef` — the `authorization.grant_ref` value from the receipt.
 * - `principalId` — the `credentialSubject.principal.id` from the receipt
 *   (supplied as a hint; resolvers MAY use it to select a cached entry).
 *
 * Output: the resolved `GrantInfo`. Throw an `Error` on resolution failure
 * (network error, token not found, token revoked, etc.).
 *
 * Implementations MAY perform network I/O (token introspection, OIDC
 * userinfo). Caching is an implementation concern.
 *
 * The SDK ships this interface only. Integrators supply a resolver for their
 * authorization server (RFC 8693 token introspection, OIDC, Grantex). The
 * project does not endorse a single authorization server, mirroring the
 * ADR-0007 stance on DID methods.
 */
export interface GrantResolver {
	resolveGrant(grantRef: string, principalId: string): Promise<GrantInfo>;
}

/**
 * The outcome of a grounded-principal tier check on a single receipt
 * (spec §7.9, ADR-0038).
 */
export const GroundedOutcome = {
	/**
	 * A high/critical receipt lacks a resolvable `grant_ref`.
	 * Corresponds to `UNGROUNDED_PRINCIPAL` in spec §7.9.
	 */
	UngroundedPrincipal: "UNGROUNDED_PRINCIPAL",
	/**
	 * The resolved grant's subject does not equal the receipt's `principal.id`.
	 * Corresponds to `PRINCIPAL_GRANT_MISMATCH` in spec §7.9.
	 */
	PrincipalGrantMismatch: "PRINCIPAL_GRANT_MISMATCH",
} as const;

export type GroundedOutcome =
	(typeof GroundedOutcome)[keyof typeof GroundedOutcome];

/** A grounded-principal tier failure for a single receipt. */
export interface GroundedPrincipalViolation {
	/** Position of the offending receipt in the input array. */
	index: number;
	/** The receipt's `id` field. */
	receiptId: string;
	/** The receipt's `credentialSubject.principal.id`. */
	principalId: string;
	/**
	 * The `authorization.grant_ref` value. May be empty for
	 * `UNGROUNDED_PRINCIPAL` violations where no `grant_ref` is present.
	 */
	grantRef: string;
	/** The specific failure outcome. */
	outcome: GroundedOutcome;
	/** Human-readable description, including resolver error messages. */
	detail: string;
}

/**
 * Apply the grounded-principal conformance tier checks (spec §7.9,
 * ADR-0038 D1–D3) to a set of receipts.
 *
 * For each receipt whose `action.risk_level` is `"high"` or `"critical"`:
 * 1. If `authorization.grant_ref` is absent or empty → `UNGROUNDED_PRINCIPAL`.
 * 2. If the resolver throws → `UNGROUNDED_PRINCIPAL`.
 * 3. If the resolved grant's `subject` ≠ `principal.id` →
 *    `PRINCIPAL_GRANT_MISMATCH`.
 *
 * Receipts at `risk_level` `"low"` or `"medium"` are not checked.
 *
 * When `resolver` is `null`, no checks are performed and an empty array is
 * returned — this is the correct behaviour for base-tier verifiers that have
 * not configured a resolver (ADR-0038 D3: "absence of a resolver in the base
 * tier is not a verification failure").
 *
 * All violations are collected and returned; the function does not stop at
 * the first failure so callers get a complete picture of the tier's state.
 */
export async function verifyGroundedPrincipalTier(
	receipts: AgentReceipt[],
	resolver: GrantResolver | null,
): Promise<GroundedPrincipalViolation[]> {
	if (resolver == null) {
		return [];
	}

	const violations: GroundedPrincipalViolation[] = [];

	for (let i = 0; i < receipts.length; i++) {
		const r = receipts[i];
		if (!r) continue;

		const riskLevel = r.credentialSubject.action.risk_level;
		if (riskLevel !== "high" && riskLevel !== "critical") {
			continue;
		}

		const principalId = r.credentialSubject.principal.id;
		const auth = r.credentialSubject.authorization;
		const grantRef = auth?.grant_ref ?? "";

		// Step 1: grant_ref must be present and non-empty.
		if (!grantRef) {
			violations.push({
				index: i,
				receiptId: r.id,
				principalId,
				grantRef: "",
				outcome: GroundedOutcome.UngroundedPrincipal,
				detail: `authorization.grant_ref is absent on a ${riskLevel} receipt`,
			});
			continue;
		}

		// Step 2: resolve the grant.
		let grant: GrantInfo;
		try {
			grant = await resolver.resolveGrant(grantRef, principalId);
		} catch (err) {
			const reason = err instanceof Error ? err.message : String(err);
			violations.push({
				index: i,
				receiptId: r.id,
				principalId,
				grantRef,
				outcome: GroundedOutcome.UngroundedPrincipal,
				detail: `grant resolution failed: ${reason}`,
			});
			continue;
		}

		// Step 3: subject must equal principal.id.
		if (grant.subject !== principalId) {
			violations.push({
				index: i,
				receiptId: r.id,
				principalId,
				grantRef,
				outcome: GroundedOutcome.PrincipalGrantMismatch,
				detail: `grant subject ${grant.subject} does not match principal.id ${principalId}`,
			});
		}
	}

	return violations;
}
