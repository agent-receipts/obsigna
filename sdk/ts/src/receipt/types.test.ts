import { describe, expect, it } from "vitest";
import type { DisclosureEnvelope } from "./disclosure.js";
import { canonicalize } from "./hash.js";
import {
	type AgentReceipt,
	CONTEXT,
	CREDENTIAL_TYPE,
	type EmitterMetadata,
	type PeerCredential,
	type UnsignedAgentReceipt,
	VERSION,
} from "./types.js";

// Envelope fixture pinned by spec/test-vectors/disclosure-envelope/vectors.json
// vector-1 (RFC 9180 §A.1.1 ikmE → RFC 7748 §6.1 Alice). Reused across tests
// so structural assertions match the byte values produced by the deterministic
// HPKE encrypt path; no live HPKE invocation needed.
const envelopeFixture: DisclosureEnvelope = {
	v: "1",
	alg: "hpke-x25519-hkdf-sha256-aes-256-gcm",
	recipients: [
		{
			kid: "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQUQUaHL9XJ7Z5W#enc-1",
			enc: "N_2jVnvb1ijohmjDyNfpfR0SU7bU6m1EwVD3QfG_RDE",
		},
	],
	ct: "YGn3i4NpiZxHjeZVggTP8lTxb0ZVdLl-2HjW31qsvo28PjQ_Lt_UQgAMidEXjzwhJPHM7OM",
};

describe("receipt schema constants", () => {
	it("has the correct context URIs", () => {
		expect(CONTEXT).toEqual([
			"https://www.w3.org/ns/credentials/v2",
			"https://agentreceipts.ai/context/v3",
		]);
	});

	it("has the correct credential type", () => {
		expect(CREDENTIAL_TYPE).toEqual(["VerifiableCredential", "AgentReceipt"]);
	});

	it("has version 0.6.0", () => {
		expect(VERSION).toBe("0.6.0");
	});
});

describe("receipt types", () => {
	it("accepts a minimal receipt", () => {
		const receipt: AgentReceipt = {
			"@context": CONTEXT,
			id: "urn:receipt:550e8400-e29b-41d4-a716-446655440000",
			type: CREDENTIAL_TYPE,
			version: VERSION,
			issuer: { id: "did:agent:test-agent" },
			issuanceDate: "2026-03-29T14:31:00Z",
			credentialSubject: {
				principal: { id: "did:user:test-user" },
				action: {
					id: "act_001",
					type: "filesystem.file.read",
					risk_level: "low",
					timestamp: "2026-03-29T14:31:00Z",
				},
				outcome: { status: "success" },
				chain: {
					sequence: 1,
					previous_receipt_hash: null,
					chain_id: "chain_test",
				},
			},
			proof: { type: "Ed25519Signature2020", proofValue: "z..." },
		};

		expect(receipt.id).toBe("urn:receipt:550e8400-e29b-41d4-a716-446655440000");
		expect(receipt.credentialSubject.action.risk_level).toBe("low");
	});

	it("accepts a full receipt with all optional fields", () => {
		const receipt: AgentReceipt = {
			"@context": CONTEXT,
			id: "urn:receipt:550e8400-e29b-41d4-a716-446655440000",
			type: CREDENTIAL_TYPE,
			version: VERSION,
			issuer: {
				id: "did:agent:claude-cowork-instance-abc123",
				type: "AIAgent",
				name: "Claude Cowork",
				operator: { id: "did:org:anthropic", name: "Anthropic" },
				model: "claude-sonnet-4.6",
				session_id: "session_xyz789",
			},
			issuanceDate: "2026-03-29T14:30:00Z",
			credentialSubject: {
				principal: { id: "did:user:otto-abc", type: "HumanPrincipal" },
				action: {
					id: "act_001",
					type: "communication.email.send",
					risk_level: "high",
					target: { system: "mail.google.com", resource: "email:compose" },
					parameters_hash: "sha256:abc123",
					parameters_disclosure: envelopeFixture,
					timestamp: "2026-03-29T14:30:00Z",
				},
				intent: {
					conversation_hash: "sha256:def456",
					prompt_preview: "Send the Q3 report to the team",
					prompt_preview_truncated: true,
					reasoning_hash: "sha256:ghi789",
				},
				outcome: {
					status: "success",
					reversible: true,
					reversal_method: "gmail:undo_send",
					reversal_window_seconds: 30,
					state_change: {
						before_hash: "sha256:before",
						after_hash: "sha256:after",
					},
				},
				authorization: {
					scopes: ["email:send", "drive:read"],
					granted_at: "2026-03-29T14:00:00Z",
					expires_at: "2026-03-29T15:00:00Z",
				},
				chain: {
					sequence: 1,
					previous_receipt_hash: null,
					chain_id: "chain_session_xyz789",
				},
			},
			proof: {
				type: "Ed25519Signature2020",
				created: "2026-03-29T14:30:01Z",
				verificationMethod: "did:agent:claude-cowork-instance-abc123#key-1",
				proofPurpose: "assertionMethod",
				proofValue: "z...",
			},
		};

		expect(receipt.credentialSubject.intent?.prompt_preview).toBe(
			"Send the Q3 report to the team",
		);
		expect(receipt.credentialSubject.authorization?.scopes).toEqual([
			"email:send",
			"drive:read",
		]);
	});

	it("UnsignedAgentReceipt omits proof", () => {
		const unsigned: UnsignedAgentReceipt = {
			"@context": CONTEXT,
			id: "urn:receipt:test",
			type: CREDENTIAL_TYPE,
			version: VERSION,
			issuer: { id: "did:agent:test" },
			issuanceDate: "2026-03-29T14:31:00Z",
			credentialSubject: {
				principal: { id: "did:user:test" },
				action: {
					id: "act_001",
					type: "filesystem.file.read",
					risk_level: "low",
					timestamp: "2026-03-29T14:31:00Z",
				},
				outcome: { status: "success" },
				chain: {
					sequence: 1,
					previous_receipt_hash: null,
					chain_id: "chain_test",
				},
			},
		};

		expect(unsigned).not.toHaveProperty("proof");
	});
});

// Helper: minimal unsigned receipt wrapping a single Action — keeps the v0.3.0
// field tests focused on the new action.parameters_disclosure /
// action.peer_credential / action.emitter_metadata fields without repeating
// the boilerplate above. Returns an UnsignedAgentReceipt because the round-trip
// assertions don't depend on the proof.
function wrapAction(
	action: UnsignedAgentReceipt["credentialSubject"]["action"],
): UnsignedAgentReceipt {
	return {
		"@context": CONTEXT,
		id: "urn:receipt:v030-test",
		type: CREDENTIAL_TYPE,
		version: "0.3.0",
		issuer: { id: "did:agent:test" },
		issuanceDate: "2026-05-21T00:00:00Z",
		credentialSubject: {
			principal: { id: "did:user:test" },
			action,
			outcome: { status: "success" },
			chain: {
				sequence: 1,
				previous_receipt_hash: null,
				chain_id: "chain_v030_test",
			},
		},
	};
}

describe("Action.parameters_disclosure (v0.3.0 envelope)", () => {
	it("round-trips through JSON.stringify / JSON.parse", () => {
		const unsigned = wrapAction({
			id: "act_001",
			type: "system.command.execute",
			risk_level: "high",
			parameters_disclosure: envelopeFixture,
			timestamp: "2026-05-21T00:00:00Z",
		});
		const round: UnsignedAgentReceipt = JSON.parse(JSON.stringify(unsigned));
		expect(round.credentialSubject.action.parameters_disclosure).toEqual(
			envelopeFixture,
		);
	});

	it("JCS canonical output sorts envelope keys alphabetically (alg, ct, recipients, v)", () => {
		const canonical = canonicalize(envelopeFixture);
		// alg < ct < recipients < v in lex order — verify the canonicalization
		// preserves this rather than the field-declaration order on the TS type.
		const algIdx = canonical.indexOf('"alg"');
		const ctIdx = canonical.indexOf('"ct"');
		const recipientsIdx = canonical.indexOf('"recipients"');
		const vIdx = canonical.indexOf('"v"');
		expect(algIdx).toBeGreaterThan(-1);
		expect(algIdx).toBeLessThan(ctIdx);
		expect(ctIdx).toBeLessThan(recipientsIdx);
		expect(recipientsIdx).toBeLessThan(vIdx);
	});
});

describe("Action.peer_credential (ADR-0010)", () => {
	it("round-trips a fully-populated POSIX peer_credential", () => {
		const peer: PeerCredential = {
			platform: "linux",
			pid: 12345,
			uid: 1000,
			gid: 1000,
			exe_path: "/usr/local/bin/some-tool",
		};
		const unsigned = wrapAction({
			id: "act_001",
			type: "system.command.execute",
			risk_level: "low",
			peer_credential: peer,
			timestamp: "2026-05-21T00:00:00Z",
		});
		const round: UnsignedAgentReceipt = JSON.parse(JSON.stringify(unsigned));
		expect(round.credentialSubject.action.peer_credential).toEqual(peer);
	});

	it("round-trips a minimal peer_credential (platform + pid only)", () => {
		// Windows / sandboxed platforms produce this shape — uid/gid/exe_path
		// omitted entirely (ADR-0009 Rule 2: optional fields MUST be absent).
		const peer: PeerCredential = {
			platform: "windows",
			pid: 4242,
		};
		const unsigned = wrapAction({
			id: "act_001",
			type: "system.command.execute",
			risk_level: "low",
			peer_credential: peer,
			timestamp: "2026-05-21T00:00:00Z",
		});
		const round: UnsignedAgentReceipt = JSON.parse(JSON.stringify(unsigned));
		expect(round.credentialSubject.action.peer_credential).toEqual(peer);
		expect(round.credentialSubject.action.peer_credential).not.toHaveProperty(
			"uid",
		);
		expect(round.credentialSubject.action.peer_credential).not.toHaveProperty(
			"gid",
		);
		expect(round.credentialSubject.action.peer_credential).not.toHaveProperty(
			"exe_path",
		);
	});

	it("JCS canonical output orders peer_credential keys alphabetically", () => {
		// Spec keys: exe_path, gid, pid, platform, uid — verify lex order, not
		// field-declaration order on the TS interface.
		const peer: PeerCredential = {
			platform: "linux",
			pid: 12345,
			uid: 1000,
			gid: 1000,
			exe_path: "/usr/local/bin/some-tool",
		};
		const canonical = canonicalize(peer);
		expect(canonical).toBe(
			'{"exe_path":"/usr/local/bin/some-tool","gid":1000,"pid":12345,"platform":"linux","uid":1000}',
		);
	});
});

describe("Action.emitter_metadata (ADR-0010)", () => {
	it("round-trips emitter_metadata.drop_count", () => {
		const meta: EmitterMetadata = { drop_count: 3 };
		const unsigned = wrapAction({
			id: "act_001",
			type: "system.events_dropped",
			risk_level: "low",
			emitter_metadata: meta,
			timestamp: "2026-05-21T00:00:00Z",
		});
		const round: UnsignedAgentReceipt = JSON.parse(JSON.stringify(unsigned));
		expect(round.credentialSubject.action.emitter_metadata).toEqual(meta);
	});
});

describe("Action canonical key ordering (peer_credential vs parameters_disclosure)", () => {
	it("places parameters_disclosure before peer_credential lexicographically", () => {
		// These two fields are adjacent in the canonical action key sort — the
		// test pins the order so a reordering bug in canonicalize() would surface
		// here rather than silently breaking the cross-SDK byte-identical hash.
		const unsigned = wrapAction({
			id: "act_001",
			type: "system.command.execute",
			risk_level: "high",
			parameters_disclosure: envelopeFixture,
			peer_credential: { platform: "linux", pid: 1 },
			timestamp: "2026-05-21T00:00:00Z",
		});
		const canonical = canonicalize(unsigned);
		const pdIdx = canonical.indexOf('"parameters_disclosure"');
		const pcIdx = canonical.indexOf('"peer_credential"');
		expect(pdIdx).toBeGreaterThan(-1);
		expect(pcIdx).toBeGreaterThan(-1);
		expect(pdIdx).toBeLessThan(pcIdx);
	});
});
