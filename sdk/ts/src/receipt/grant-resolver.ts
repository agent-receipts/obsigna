import { parseReceiptTimeMs } from "./receipt-time.js";
import type { AgentReceipt, Authorization } from "./types.js";

/** A resolved grant's revocation status (spec §7.9.1). */
export type Revocation = "not_revoked" | "revoked" | "unknown";

const REVOCATIONS: readonly string[] = ["not_revoked", "revoked", "unknown"];

/**
 * The resolved representation of an externally-minted authorization grant,
 * such as an RFC 8693 token-exchange token or a Grantex grant token
 * (spec §7.9.1, ADR-0041 D2).
 *
 * A grant that is missing a required field, has empty `scopes`, has
 * `expiresAt` not after `validFrom`, or has `revokedAt` without
 * `revocation: "revoked"` is malformed, and the verifier treats it as a
 * resolution failure.
 */
export interface GrantInfo {
	/** The principal the grant was issued for. Must equal `principal.id`. */
	subject: string;
	/** The scopes the grant conferred. Non-empty. */
	scopes: string[];
	/**
	 * When the grant took effect. For a JWT access token this is `nbf` when
	 * present, otherwise `iat`.
	 */
	validFrom: Date;
	/** When the grant expires. Absent means no expiry. */
	expiresAt?: Date;
	/**
	 * `"not_revoked"` means not revoked as of resolution, which covers any
	 * earlier action. A resolver that cannot see revocation must report
	 * `"unknown"`.
	 */
	revocation: Revocation;
	/** When the grant was revoked, if known. Only with `revocation: "revoked"`. */
	revokedAt?: Date;
	/** The authorization server that minted the grant. */
	issuer: string;
}

/**
 * Resolves an authorization grant reference to the grant's terms
 * (spec §7.9.1).
 *
 * - `grantRef`: the `authorization.grant_ref` value from the receipt.
 * - `principalId`: the receipt's `credentialSubject.principal.id`, supplied
 *   as a hint; resolvers MAY use it to select a cached entry.
 *
 * A grant that has expired or been revoked is still a resolved grant: when the
 * resolver can establish its terms it must return them, not reject. Reject
 * only when the grant cannot be found, the backend cannot be reached, or its
 * response cannot be interpreted. A resolver that learns only that a grant is
 * inactive, without its terms (as with plain RFC 7662 token introspection),
 * must reject. Document whether your resolver returns the terms of lapsed
 * grants and whether it can see revocation.
 *
 * The SDK ships this interface only; integrators supply a resolver for their
 * authorization server, mirroring the ADR-0007 stance on DID methods.
 */
export interface GrantResolver {
	resolveGrant(grantRef: string, principalId: string): Promise<GrantInfo>;
}

/** Failure outcomes of the grounded-principal tier (spec §7.9.6). */
export const GroundedOutcome = {
	/** No `grant_ref`, or the grant cannot be resolved or is malformed. */
	UngroundedPrincipal: "UNGROUNDED_PRINCIPAL",
	/** The grant's subject does not equal `principal.id`. */
	PrincipalGrantMismatch: "PRINCIPAL_GRANT_MISMATCH",
	/** The grant was not in force at the action time. */
	GrantNotValidAtActionTime: "GRANT_NOT_VALID_AT_ACTION_TIME",
	/** The verifier cannot tell whether the grant was in force at the action time. */
	GrantValidityUnresolved: "GRANT_VALIDITY_UNRESOLVED",
	/** `authorization.scopes` contains a scope the grant does not confer. */
	GrantScopeExceeded: "GRANT_SCOPE_EXCEEDED",
} as const;

export type GroundedOutcome =
	(typeof GroundedOutcome)[keyof typeof GroundedOutcome];

/** Warnings raised alongside a grounded-tier result (spec §7.9.4). */
export const GroundedWarningCode = {
	/** `authorization.granted_at` differs from the grant's `validFrom`. */
	GrantedAtDisagrees: "GRANTED_AT_DISAGREES",
	/** `authorization.expires_at` differs from the grant's expiry, including when it has none. */
	ExpiresAtDisagrees: "EXPIRES_AT_DISAGREES",
} as const;

export type GroundedWarningCode =
	(typeof GroundedWarningCode)[keyof typeof GroundedWarningCode];

/** A warning raised alongside a grounded-tier result. It never changes the outcome. */
export interface GroundedWarning {
	code: GroundedWarningCode;
	detail: string;
}

/** The grounded-principal tier result for one checked receipt. */
export interface GroundedResult {
	/** Position of the receipt in the input array. */
	index: number;
	/** The receipt's `id`. */
	receiptId: string;
	/** The receipt's `credentialSubject.principal.id`. */
	principalId: string;
	/** `authorization.grant_ref`; empty when absent. */
	grantRef: string;
	/** `null` when the receipt is grounded. */
	outcome: GroundedOutcome | null;
	/** Whether the receipt passed every check (`outcome === null`). */
	grounded: boolean;
	/**
	 * Explains the outcome. For a grounded receipt it states that validity was
	 * established at the issuer-asserted action time (§7.9.3).
	 */
	detail: string;
	/** Raised once the grant has resolved, whatever the outcome. */
	warnings: GroundedWarning[];
}

/** Options for {@link verifyGroundedPrincipalTier}. */
export interface GroundedOptions {
	/**
	 * Clock-skew tolerance δ around the action time, in milliseconds
	 * (§7.9.3). Defaults to 0. A negative or non-finite value throws a
	 * `RangeError`.
	 */
	clockSkewMs?: number;
}

/**
 * Apply the grounded-principal tier checks (spec v0.7.0 §7.9, ADR-0038 and
 * ADR-0041) and return one result for every receipt checked: those at risk
 * level `"high"` or `"critical"`. Low and medium receipts produce no result.
 *
 * For each checked receipt the steps run in order, and the first failure is
 * the outcome: grant presence, grant resolution (including the malformed-
 * grant rules), subject match, validity at the action time, and scope
 * containment.
 *
 * A `null` resolver means the verifier is in the base tier: no checks run and
 * the result is empty.
 */
export async function verifyGroundedPrincipalTier(
	receipts: AgentReceipt[],
	resolver: GrantResolver | null,
	options: GroundedOptions = {},
): Promise<GroundedResult[]> {
	const skew = options.clockSkewMs ?? 0;
	if (!Number.isFinite(skew) || skew < 0) {
		throw new RangeError(
			"grounded-tier clockSkewMs must be a finite, non-negative number",
		);
	}
	if (resolver == null) {
		return [];
	}
	const skewMs = Math.floor(skew);

	const results: GroundedResult[] = [];
	for (let i = 0; i < receipts.length; i++) {
		const r = receipts[i];
		if (!r) continue;
		const riskLevel = r.credentialSubject.action.risk_level;
		if (riskLevel !== "high" && riskLevel !== "critical") continue;

		const result: GroundedResult = {
			index: i,
			receiptId: r.id,
			principalId: r.credentialSubject.principal.id,
			grantRef: "",
			outcome: null,
			grounded: false,
			detail: "",
			warnings: [],
		};
		await checkGrounded(r, resolver, skewMs, result);
		result.grounded = result.outcome === null;
		results.push(result);
	}
	return results;
}

function fail(
	result: GroundedResult,
	outcome: GroundedOutcome,
	detail: string,
): void {
	result.outcome = outcome;
	result.detail = detail;
}

async function checkGrounded(
	r: AgentReceipt,
	resolver: GrantResolver,
	skewMs: number,
	result: GroundedResult,
): Promise<void> {
	const auth = r.credentialSubject.authorization;
	if (!auth?.grant_ref) {
		fail(
			result,
			GroundedOutcome.UngroundedPrincipal,
			`authorization.grant_ref is absent on a ${r.credentialSubject.action.risk_level} receipt`,
		);
		return;
	}
	result.grantRef = auth.grant_ref;

	let grant: GrantInfo;
	try {
		grant = await resolver.resolveGrant(auth.grant_ref, result.principalId);
	} catch (err) {
		const reason = err instanceof Error ? err.message : String(err);
		fail(
			result,
			GroundedOutcome.UngroundedPrincipal,
			`grant resolution failed: ${reason}`,
		);
		return;
	}
	const malformed = malformedGrant(grant);
	if (malformed !== null) {
		fail(
			result,
			GroundedOutcome.UngroundedPrincipal,
			`resolved grant is malformed: ${malformed}`,
		);
		return;
	}
	result.warnings = grantFieldWarnings(auth, grant);

	if (grant.subject !== result.principalId) {
		fail(
			result,
			GroundedOutcome.PrincipalGrantMismatch,
			`grant subject ${grant.subject} does not match principal.id ${result.principalId}`,
		);
		return;
	}

	const t = parseReceiptTimeMs(r.credentialSubject.action.timestamp);
	if (t === null) {
		fail(
			result,
			GroundedOutcome.GrantValidityUnresolved,
			"action.timestamp is not a readable RFC 3339 date-time",
		);
		return;
	}
	const window = checkValidityWindow(grant, t, skewMs);
	if (window !== null) {
		fail(result, window.outcome, window.detail);
		return;
	}

	for (const s of auth.scopes ?? []) {
		if (!grant.scopes.includes(s)) {
			fail(
				result,
				GroundedOutcome.GrantScopeExceeded,
				`authorization.scopes contains ${s}, which the grant does not confer`,
			);
			return;
		}
	}
	result.detail = "grounded at the issuer-asserted action time";
}

/** Milliseconds since the epoch; JavaScript dates are already millisecond-precise. */
function ms(d: Date): number {
	return d.getTime();
}

function isDate(d: unknown): d is Date {
	return d instanceof Date && !Number.isNaN(d.getTime());
}

/** Why a resolved grant is malformed (§7.9.1), or `null`. */
function malformedGrant(g: GrantInfo | null | undefined): string | null {
	if (typeof g !== "object" || g === null)
		return "the resolver did not return a grant";
	if (typeof g.subject !== "string" || !g.subject) return "subject is missing";
	if (
		!Array.isArray(g.scopes) ||
		g.scopes.length === 0 ||
		!g.scopes.every((s) => typeof s === "string")
	) {
		return "scopes is missing, empty or not a list of strings";
	}
	if (!isDate(g.validFrom)) return "valid_from is missing or not a valid Date";
	if (typeof g.issuer !== "string" || !g.issuer) return "issuer is missing";
	if (g.revocation === undefined) return "revocation is missing";
	if (!REVOCATIONS.includes(g.revocation)) {
		return `revocation ${g.revocation} is not one of not_revoked, revoked, unknown`;
	}
	if (g.expiresAt !== undefined && !isDate(g.expiresAt)) {
		return "expires_at is not a valid Date";
	}
	if (g.revokedAt !== undefined && !isDate(g.revokedAt)) {
		return "revoked_at is not a valid Date";
	}
	if (g.expiresAt !== undefined && ms(g.expiresAt) <= ms(g.validFrom)) {
		return "expires_at is not after valid_from";
	}
	if (g.revokedAt !== undefined && g.revocation !== "revoked") {
		return `revoked_at is set but revocation is ${g.revocation}`;
	}
	return null;
}

/** Apply §7.9.3 to action time `t` (ms since the epoch); `null` when in force. */
function checkValidityWindow(
	g: GrantInfo,
	t: number,
	skewMs: number,
): { outcome: GroundedOutcome; detail: string } | null {
	const start = ms(g.validFrom);
	const ends: number[] = [];
	if (g.expiresAt !== undefined) ends.push(ms(g.expiresAt));
	if (g.revocation === "revoked" && g.revokedAt !== undefined) {
		ends.push(ms(g.revokedAt));
	}
	const end = ends.length > 0 ? Math.min(...ends) : null;

	const lo = t - skewMs;
	const hi = t + skewMs;
	const emptyWindow = end !== null && end <= start;
	const overlaps = !emptyWindow && hi >= start && (end === null || lo < end);
	if (!overlaps) {
		return {
			outcome: GroundedOutcome.GrantNotValidAtActionTime,
			detail: "the grant was not in force at the issuer-asserted action time",
		};
	}
	const inside = lo >= start && (end === null || hi < end);
	if (!inside) {
		return {
			outcome: GroundedOutcome.GrantValidityUnresolved,
			detail:
				"the action time is within the clock-skew tolerance of a grant boundary",
		};
	}
	if (g.revocation === "unknown") {
		return {
			outcome: GroundedOutcome.GrantValidityUnresolved,
			detail: "the resolver cannot see whether the grant was revoked",
		};
	}
	if (g.revocation === "revoked" && g.revokedAt === undefined) {
		return {
			outcome: GroundedOutcome.GrantValidityUnresolved,
			detail: "the grant was revoked at an unknown time",
		};
	}
	return null;
}

/**
 * Compare the receipt's stated grant fields with the grant (§7.9.4). A stated
 * value that is not a readable RFC 3339 date-time raises no warning.
 */
function grantFieldWarnings(
	auth: Authorization,
	g: GrantInfo,
): GroundedWarning[] {
	const warnings: GroundedWarning[] = [];
	const grantedAt = parseReceiptTimeMs(auth.granted_at);
	if (grantedAt !== null && grantedAt !== ms(g.validFrom)) {
		warnings.push({
			code: GroundedWarningCode.GrantedAtDisagrees,
			detail: "authorization.granted_at differs from the grant's valid_from",
		});
	}
	const expiresAt = parseReceiptTimeMs(auth.expires_at);
	if (
		expiresAt !== null &&
		(g.expiresAt === undefined || expiresAt !== ms(g.expiresAt))
	) {
		warnings.push({
			code: GroundedWarningCode.ExpiresAtDisagrees,
			detail: "authorization.expires_at differs from the grant's expiry",
		});
	}
	return warnings;
}
