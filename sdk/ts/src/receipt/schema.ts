/**
 * Zod runtime schemas mirroring the interfaces in types.ts.
 *
 * Every object uses .passthrough() so unknown extra fields written by a newer
 * SDK are preserved on load — required for forward-compatibility of canonical
 * JSON / signature verification, since stripping unknown keys would break the
 * RFC 8785 hash on receipts written by future SDK versions.
 */
import { z } from "zod";
import type { AgentReceipt } from "./types.js";

// --- Risk levels ---

const riskLevelSchema = z.enum(["low", "medium", "high", "critical"]);

// --- Outcome status ---

const outcomeStatusSchema = z.enum(["success", "failure", "pending"]);

// --- Issuer ---

const operatorSchema = z
	.object({
		id: z.string(),
		name: z.string(),
	})
	.passthrough();

// Open runtime/observability metadata container (ADR-0026). Known members are
// declared for documentation; `.passthrough()` keeps it extensible so future
// runtime keys validate without a schema change.
const runtimeSchema = z
	.object({
		agent_id: z.string().optional(),
		agent_type: z.string().optional(),
	})
	.passthrough();

const issuerSchema = z
	.object({
		id: z.string(),
		type: z.string().optional(),
		name: z.string().optional(),
		operator: operatorSchema.optional(),
		model: z.string().optional(),
		session_id: z.string().optional(),
		runtime: runtimeSchema.optional(),
	})
	.passthrough();

// --- Principal ---

const principalSchema = z
	.object({
		id: z.string(),
		type: z.string().optional(),
	})
	.passthrough();

// --- Action ---

const actionTargetSchema = z
	.object({
		system: z.string(),
		resource: z.string().optional(),
	})
	.passthrough();

// Envelope shape per spec v0.3.0 / ADR-0012 amendment. Length checks on
// recipient.enc and ct mirror the spec's regex bounds (43 chars for X25519
// `enc`, ≥24 chars for the AEAD ciphertext) so malformed envelopes are
// rejected at the SDK boundary. .passthrough() preserves unknown future
// fields for forward-compatible verification.
// Pattern enforces unpadded base64url alphabet (no `+`, `/`, or `=`) at
// exactly 43 chars — the encoded length of a 32-byte X25519 public key.
const ENC_PATTERN = /^[A-Za-z0-9_-]{43}$/;

// Pattern enforces unpadded base64url alphabet AND decodable length
// (`len % 4 !== 1`, the one residue invalid for base64url without padding).
// Length floor of 24 (= 18 bytes = AES-256-GCM 16-byte tag + 2-byte minimum
// plaintext `{}`) is enforced separately so error messages distinguish
// "too short" from "wrong alphabet".
const CT_PATTERN = /^([A-Za-z0-9_-]{4})*([A-Za-z0-9_-]{2,3})?$/;

const parametersDisclosureRecipientSchema = z
	.object({
		kid: z.string().min(1),
		enc: z
			.string()
			.regex(ENC_PATTERN, "enc must be 43 unpadded base64url chars"),
	})
	.passthrough();

const parametersDisclosureEnvelopeSchema = z
	.object({
		v: z.literal("1"),
		alg: z.literal("hpke-x25519-hkdf-sha256-aes-256-gcm"),
		recipients: z.tuple([parametersDisclosureRecipientSchema]),
		ct: z
			.string()
			.min(24)
			.regex(CT_PATTERN, "ct must be unpadded base64url with decodable length"),
	})
	.passthrough();

const peerCredentialSchema = z
	.object({
		platform: z.string(),
		pid: z.number().int(),
		uid: z.number().int().min(0).optional(),
		gid: z.number().int().min(0).optional(),
		exe_path: z.string().optional(),
	})
	.passthrough();

const emitterMetadataSchema = z
	.object({
		drop_count: z.number().int().min(0).optional(),
	})
	.passthrough();

// parameters_disclosure is the v0.3.0 envelope (ADR-0012 amendment). The TS
// SDK only emits and ingests this shape; the legacy v0.2.x flat-map is not
// accepted by the load-time schema. The spec's `oneOf` still admits the
// legacy form for cross-version interop, but verifiers that need to ingest
// legacy receipts must use raw spec-schema validation rather than this Zod
// schema, per the SDK type contract (Action.parameters_disclosure).
const actionSchema = z
	.object({
		id: z.string(),
		type: z.string(),
		tool_name: z.string().optional(),
		risk_level: riskLevelSchema,
		target: actionTargetSchema.optional(),
		parameters_hash: z.string().optional(),
		parameters_disclosure: parametersDisclosureEnvelopeSchema.optional(),
		peer_credential: peerCredentialSchema.optional(),
		emitter_metadata: emitterMetadataSchema.optional(),
		timestamp: z.string(),
		trusted_timestamp: z.string().optional(),
		idempotency_key: z.string().min(1).optional(),
	})
	.passthrough();

// --- Intent ---

const intentSchema = z
	.object({
		conversation_hash: z.string().optional(),
		prompt_preview: z.string().optional(),
		prompt_preview_truncated: z.boolean().optional(),
		reasoning_hash: z.string().optional(),
	})
	.passthrough();

// --- Outcome ---

const stateChangeSchema = z
	.object({
		before_hash: z.string(),
		after_hash: z.string(),
	})
	.passthrough();

const outcomeSchema = z
	.object({
		status: outcomeStatusSchema,
		error: z.string().optional(),
		reversible: z.boolean().optional(),
		reversal_method: z.string().optional(),
		reversal_window_seconds: z.number().optional(),
		reversal_of: z.string().optional(),
		state_change: stateChangeSchema.optional(),
		response_hash: z.string().optional(),
	})
	.passthrough();

// --- Authorization ---

const authorizationSchema = z
	.object({
		scopes: z.array(z.string()),
		granted_at: z.string(),
		expires_at: z.string().optional(),
		grant_ref: z.string().optional(),
	})
	.passthrough();

// --- Chain ---

const chainSchema = z
	.object({
		sequence: z.number(),
		previous_receipt_hash: z.string().nullable(),
		chain_id: z.string(),
		// When present, MUST be true. Explicit false is not valid per the spec.
		terminal: z.literal(true).optional(),
		// Issuer-asserted termination reason. Only valid alongside terminal: true.
		// Verifier-derived "unknown" is never written on the wire.
		status: z.enum(["complete", "interrupted"]).optional(),
	})
	.passthrough()
	.refine((c) => c.status === undefined || c.terminal === true, {
		message: "chain.status requires chain.terminal: true",
		path: ["status"],
	});

// --- Delegation ---

const delegatorSchema = z.object({ id: z.string() }).passthrough();

const delegationSchema = z
	.object({
		parent_chain_id: z.string(),
		parent_receipt_id: z.string(),
		delegator: delegatorSchema,
	})
	.passthrough();

// --- Key rotation ---

const keyRotationSchema = z
	.object({
		event_type: z.literal("key_rotated"),
		new_public_key: z.string().regex(/^u[A-Za-z0-9_-]+$/),
		old_key_fingerprint: z.string().regex(/^sha256:[0-9a-f]{64}$/),
		new_key_fingerprint: z.string().regex(/^sha256:[0-9a-f]{64}$/),
		old_algorithm: z.string().min(1),
		new_algorithm: z.string().min(1),
		signed_with: z.literal("old"),
	})
	.passthrough();

// --- Credential Subject ---

const credentialSubjectSchema = z
	.object({
		principal: principalSchema,
		action: actionSchema,
		intent: intentSchema.optional(),
		outcome: outcomeSchema,
		authorization: authorizationSchema.optional(),
		chain: chainSchema,
		keyRotation: keyRotationSchema.optional(),
		correlation_id: z.string().min(1).optional(),
		delegation: delegationSchema.optional(),
	})
	.passthrough();

// --- Proof ---

const proofSchema = z
	.object({
		type: z.string(),
		created: z.string().optional(),
		verificationMethod: z.string().optional(),
		proofPurpose: z.string().optional(),
		proofValue: z.string(),
	})
	.passthrough();

// --- Agent Receipt ---

// Annotated as ZodType<AgentReceipt> so .parse() returns AgentReceipt directly
// at the call site, avoiding an `as` cast at the validation boundary.
export const agentReceiptSchema: z.ZodType<AgentReceipt> = z
	.object({
		"@context": z.array(z.string()),
		id: z.string(),
		type: z.array(z.string()),
		version: z.string(),
		issuer: issuerSchema,
		issuanceDate: z.string(),
		credentialSubject: credentialSubjectSchema,
		proof: proofSchema,
	})
	.passthrough();
