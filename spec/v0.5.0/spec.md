# Agent Receipt Protocol — Specification v0.5.0

> **Status:** Draft
> **Version:** 0.5.0
> **Date:** 2026-06-09
> **License:** MIT

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 1. Problem Statement

AI agents are increasingly acting on behalf of humans — sending emails, modifying documents, making purchases, booking travel, managing files. No open standard exists for recording what an agent did, why it did it, whether it succeeded, and whether it can be undone.

The current state:

- 93% of open-source AI agent projects use unscoped API keys with no audit trail (Grantex, March 2026)
- Only 13% include any form of action logging, and where it exists, it is opt-in and not tied to authorization
- No project produces an audit trail linking a specific action to a specific agent, user authorization, and set of scopes
- The EU AI Act mandates traceability for high-risk AI systems, but no standard format exists for agent action records

### What exists and what doesn't

| Layer | Existing standards | Gap |
|---|---|---|
| Agent identity | W3C DIDs, AgentStamp, MolTrust, Grantex | No adoption by major platforms |
| Action authorization | OAuth 2.0, Grantex (IETF draft) | No cross-platform standard for agent-specific scopes |
| Content provenance | C2PA Content Credentials | Designed for media assets, not agent actions |
| Action logging | Vendor-specific (LangSmith, Arize) | No standard format — everyone rolls their own |
| **Action receipts** | **Nothing** | **This specification** |

---

## 2. Design Principles

1. **Privacy-preserving by default.** Parameters are hashed, not stored in plaintext. The human principal controls what is disclosed. Sensitive data never appears in receipts — only hashes and user-controlled previews.

2. **Built on existing standards.** W3C Verifiable Credentials Data Model 2.0 for structure. Ed25519 for signing. SHA-256 for hashing. RFC 3161 for trusted timestamps. No novel cryptographic primitives.

3. **Hash-chained for integrity.** Each receipt includes the hash of the previous receipt, forming a tamper-evident chain. Breaking the chain is detectable.

4. **Agent-agnostic.** The spec does not assume MCP, OpenAI function calling, or any specific agent framework. Any agent that can produce JSON and sign it can emit receipts.

5. **Human-readable and machine-verifiable.** Receipts can be displayed as a timeline to end users and cryptographically verified by auditors and compliance tools.

6. **Reversibility-aware.** Every receipt declares whether the action can be undone, and if so, how. This enables downstream tooling to offer "undo" capabilities.

7. **Minimal by default, extensible by design.** The core schema is small. Domain-specific extensions (financial actions, healthcare, etc.) can be layered on via additional `@context` URIs.

---

## 3. Core Concepts

### 3.1 Agent Receipt

A cryptographically signed record of a single action taken by an AI agent on behalf of a human principal. Modeled as a W3C Verifiable Credential with type `AgentReceipt`.

### 3.2 Receipt Chain

An ordered sequence of Agent Receipts linked by hash references. Each receipt contains the hash of the previous receipt in the chain, creating a tamper-evident log. The first receipt in a chain has a `null` previous hash.

> **Note:** In this version, receipt chains are strictly linear — each receipt has exactly one predecessor. Concurrent action streams (e.g., parallel tool calls, sub-agent fan-out) cannot be represented within a single chain. See §9.8 for discussion of this limitation.

### 3.3 Action Taxonomy

A standardized vocabulary of action types, organized by domain and risk level. The taxonomy enables cross-agent comparison and risk classification.

### 3.4 Principal

The human (or organization) on whose behalf the agent acted. Identified by a DID or URI. The principal is the entity who authorized the action, not the entity that built or operates the agent.

### 3.5 Issuer

The agent (or agent platform) that performed the action and produced the receipt. The issuer signs the receipt with its private key.

---

## 4. Schema

### 4.1 Agent Receipt (full schema)

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://agentreceipts.ai/context/v2"
  ],
  "id": "urn:receipt:550e8400-e29b-41d4-a716-446655440000",
  "type": ["VerifiableCredential", "AgentReceipt"],
  "version": "0.5.0",

  "issuer": {
    "id": "did:agent:claude-cowork-instance-abc123",
    "type": "AIAgent",
    "name": "Claude Cowork",
    "operator": {
      "id": "did:org:anthropic",
      "name": "Anthropic"
    },
    "model": "claude-sonnet-4-6",
    "session_id": "session_xyz789",
    "runtime": {
      "agent_id": "a3e49db54342a92d4",
      "agent_type": "general-purpose"
    }
  },

  "issuanceDate": "2026-03-31T14:30:00Z",

  "credentialSubject": {
    "principal": {
      "id": "did:user:otto-abc",
      "type": "HumanPrincipal"
    },

    "action": {
      "id": "act_7f3a1b2c-d4e5-46f7-a8b9-c0d1e2f3a4b5",
      "type": "communication.email.send",
      "risk_level": "high",
      "target": {
        "system": "mail.google.com",
        "resource": "email:compose"
      },
      "parameters_hash": "sha256:a3f1c2d4e5b6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1d6",
      "timestamp": "2026-03-31T14:30:00Z",
      "trusted_timestamp": null
    },

    "intent": {
      "conversation_hash": "sha256:b4e2d1f3a5c6b7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1e7",
      "prompt_preview": "Send the Q3 report to the team",
      "prompt_preview_truncated": true,
      "reasoning_hash": "sha256:c5f3e2d4a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2f8"
    },

    "outcome": {
      "status": "success",
      "error": null,
      "reversible": true,
      "reversal_method": "gmail:undo_send",
      "reversal_window_seconds": 30,
      "state_change": {
        "before_hash": "sha256:d604f3e5a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3a9",
        "after_hash": "sha256:e7a504f6a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4ba"
      }
    },

    "authorization": {
      "scopes": ["email:send", "drive:read"],
      "granted_at": "2026-03-31T14:00:00Z",
      "expires_at": "2026-03-31T15:00:00Z",
      "grant_ref": null
    },

    "chain": {
      "sequence": 1,
      "previous_receipt_hash": null,
      "chain_id": "chain_session_xyz789"
    }
  },

  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-03-31T14:30:01Z",
    "verificationMethod": "did:agent:claude-cowork-instance-abc123#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "ul_wFLgGWlzFaYt2ckT4wZfoeRa7ZqL0tt3y10dgr7FdsVMivs5tc9ZrUYBJ_FKEE4aFApeAzPH6jp57irtgDCw"
  }
}
```

### 4.2 Minimal Receipt (required fields only)

For lightweight or high-frequency actions, a minimal receipt containing only required fields:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://agentreceipts.ai/context/v2"
  ],
  "id": "urn:receipt:660e8400-e29b-41d4-a716-446655440001",
  "type": ["VerifiableCredential", "AgentReceipt"],
  "version": "0.5.0",
  "issuer": { "id": "did:agent:claude-cowork-instance-abc123" },
  "issuanceDate": "2026-03-31T14:31:00Z",
  "credentialSubject": {
    "principal": { "id": "did:user:otto-abc" },
    "action": {
      "id": "act_8a4b2c3d-e5f6-47a8-b9c0-d1e2f3a4b5c6",
      "type": "filesystem.file.read",
      "risk_level": "low",
      "timestamp": "2026-03-31T14:31:00Z"
    },
    "outcome": { "status": "success" },
    "chain": {
      "sequence": 2,
      "previous_receipt_hash": "sha256:f806a507a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5cb",
      "chain_id": "chain_session_xyz789"
    }
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-03-31T14:31:01Z",
    "verificationMethod": "did:agent:claude-cowork-instance-abc123#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "ul_wFLgGWlzFaYt2ckT4wZfoeRa7ZqL0tt3y10dgr7FdsVMivs5tc9ZrUYBJ_FKEE4aFApeAzPH6jp57irtgDCw"
  }
}
```

All five `proof` fields are required even in the minimal form.

### 4.3 Field Reference

#### Top-level fields

| Field | Required | Description |
|---|---|---|
| `@context` | Yes | JSON-LD context. MUST include the W3C VC v2 and Agent Receipts context URIs in the order shown. Receipts at this version use `https://agentreceipts.ai/context/v2`. |
| `id` | Yes | Globally unique receipt identifier. MUST be a `urn:receipt:<uuid>`. |
| `type` | Yes | MUST be `["VerifiableCredential", "AgentReceipt"]`. |
| `version` | Yes | Spec version this receipt conforms to. MUST be `"0.5.0"` for this version. |
| `issuer` | Yes | The agent or platform that issued the receipt. See §4.3.1. |
| `issuanceDate` | Yes | ISO 8601 datetime when the receipt was issued. This is the *receipt* timestamp (when the issuer created and signed the credential), which MAY differ from `action.timestamp` (when the action itself was executed). In real-time emitters these will be near-identical; in batched or retroactive scenarios they may diverge significantly. Uses the VC Data Model 1.x field name; see ADR-0009 for the rationale. The VC 2.0 name `validFrom` is **not** used. |
| `credentialSubject` | Yes | The receipt payload. See §4.3.2. |
| `proof` | Yes | Cryptographic proof. See §4.3.3. |

#### 4.3.1 `issuer`

| Field | Required | Description |
|---|---|---|
| `id` | Yes | DID or URI identifying the agent instance. |
| `type` | No | SHOULD be `"AIAgent"`. |
| `name` | No | Human-readable agent name. |
| `operator.id` | Yes* | DID or URI of the entity operating the agent. *Required when `operator` is present. |
| `operator.name` | Yes* | Human-readable operator name. *Required when `operator` is present. |
| `model` | No | Model identifier (e.g. `claude-sonnet-4-6`). |
| `session_id` | No | Opaque session identifier. |
| `runtime` | No | Open container for runtime/observability metadata the issuing runtime attaches to the action. Absent for the root agent. Unlike the other issuer fields, `runtime` is intentionally extensible: it carries the members defined below plus any additional keys a runtime supplies, and is treated as an opaque JSON literal by JSON-LD processors (`@type: @json` in the context). New members MAY be added without a protocol-version bump. See ADR-0026. |
| `runtime.agent_id` | No | Identifier of the sub-agent that issued the receipt. Absent for the root agent. |
| `runtime.agent_type` | No | Runtime-reported agent type label (e.g. `general-purpose`). Absent for the root agent. |

#### 4.3.2 `credentialSubject`

| Field | Required | Description |
|---|---|---|
| `principal` | Yes | The human or org on whose behalf the action was taken. |
| `principal.id` | Yes | DID or URI identifying the principal. |
| `principal.type` | No | SHOULD be `"HumanPrincipal"` or `"OrganizationPrincipal"`. |
| `action` | Yes | Details of the action taken. |
| `action.id` | Yes | Unique action identifier. Format: `act_<uuid>`. |
| `action.type` | Yes | Action type from the taxonomy (§5). |
| `action.risk_level` | Yes | One of: `low`, `medium`, `high`, `critical`. |
| `action.target.system` | No | The system or service acted upon. |
| `action.target.resource` | No | The specific resource within the system. |
| `action.parameters_hash` | No | `sha256:`-prefixed hash of the action parameters (RFC 8785 canonical JSON). A verifier can independently canonicalize any disclosed parameters and recompute this hash; however, this version of the spec does not define per-action-type parameter schemas, so verifiers cannot reliably determine whether the disclosed parameters are complete or expected for the action type, and mismatches may be ambiguous. See §9.9. |
| `action.timestamp` | Yes | ISO 8601 datetime when the action was executed. |
| `action.trusted_timestamp` | No | Base64-encoded RFC 3161 `TimeStampToken` (DER encoding, then base64). The TSA MUST timestamp the same canonical JSON (proof field removed) used for signing. If no trusted timestamp is available, this field MAY be omitted or set explicitly to `null`. See §7.7. |
| `action.idempotency_key` | No | Stable identifier for the logical operation this action represents (e.g. a request ID). When an agent retries a tool call, the SDK or MCP proxy SHOULD stamp the same `idempotency_key` on every receipt emitted for that operation. Verifiers surface duplicate values across a chain as a warning, not a failure — retries are legitimate. MUST be a non-empty string when present; MUST NOT be `null`. See §7.3.6 and ADR-0019 §S5. |
| `intent` | No | Context about the agent's intent at time of action. |
| `intent.conversation_hash` | No | `sha256:` prefixed hash of the conversation context. |
| `intent.prompt_preview` | No | Plain-text preview of the prompt that triggered the action (may be truncated). |
| `intent.prompt_preview_truncated` | No | `true` if `prompt_preview` was truncated. |
| `intent.reasoning_hash` | No | `sha256:` prefixed hash of the agent's reasoning trace. |
| `outcome` | Yes | The result of the action. |
| `outcome.status` | Yes | One of: `success`, `failure`, `pending`. |
| `outcome.error` | No | Error message if `status` is `failure`. |
| `outcome.reversible` | No | `true` if the action can be undone. |
| `outcome.reversal_method` | No | Machine-readable reversal method identifier (e.g. `gmail:undo_send`). |
| `outcome.reversal_window_seconds` | No | Seconds within which reversal is possible. |
| `outcome.reversal_of` | No | `urn:receipt:<uuid>` referencing the `id` of the original receipt this receipt reverses. Present only on reversal receipts (see §7.4). |
| `outcome.state_change.before_hash` | Yes* | `sha256:` prefixed hash of relevant state before the action. *Required when `outcome.state_change` is present. |
| `outcome.state_change.after_hash` | Yes* | `sha256:` prefixed hash of relevant state after the action. *Required when `outcome.state_change` is present. |
| `outcome.response_hash` | No | SHA-256 hash of the RFC 8785 canonical JSON of the server's response, computed **after** secret redaction. Ordering: redact → hash → populate `outcome` → sign. When present and the response body is available, verifiers MUST recompute and compare; a mismatch is a verification failure. When the response body is absent, verifiers MUST continue and note "response hash present, body not supplied". Absence of this field is not a verification failure — it means the issuer did not commit to the response. |
| `authorization` | No | Authorization context under which the action was taken. |
| `authorization.scopes` | Yes* | List of authorization scopes active at time of action. *Required when `authorization` is present. |
| `authorization.granted_at` | Yes* | ISO 8601 datetime when authorization was granted. *Required when `authorization` is present. |
| `authorization.expires_at` | No | ISO 8601 datetime when authorization expires. |
| `authorization.grant_ref` | No | Reference to the authorization grant (e.g. a Grantex grant token). |
| `delegation` | No | Present when this chain was spawned by delegation from another agent. See §7.6. |
| `delegation.parent_chain_id` | Yes* | `chain_id` of the delegating agent's chain. *Required when `delegation` is present. |
| `delegation.parent_receipt_id` | Yes* | `id` of the receipt in the parent chain where delegation occurred. *Required when `delegation` is present. |
| `delegation.delegator` | Yes* | Identifies the delegating agent. *Required when `delegation` is present. |
| `delegation.delegator.id` | Yes* | DID or URI of the delegating agent (the parent chain's issuer). *Required when `delegation` is present. |
| `chain` | Yes | Hash-chain linkage fields. |
| `chain.chain_id` | Yes | Opaque identifier grouping receipts into a logical chain (e.g. per session). All receipts within a single chain MUST share the same value; verifiers MUST reject input that mixes receipts from different chains. See §7.3.4. |
| `chain.sequence` | Yes | Monotonically increasing integer position within the chain. Starts at `1`. |
| `chain.previous_receipt_hash` | Yes | `sha256:` prefixed hash of the previous receipt's canonical form. MUST be `null` for the first receipt in a chain (`sequence: 1`). The field MUST always be present; `null` is not the same as omitting it. |
| `chain.terminal` | No | When present, MUST be `true`. Asserts that no further receipts will be appended to this chain. Explicit `false` is schema-invalid; absence is the only valid way to express "no claim". Verifiers that observe any receipt following a terminal receipt in the verified input sequence MUST fail with a "receipt after terminal" error regardless of caller parameters. See §7.3.2. |
| `chain.status` | No | When present, MUST be one of `"complete"` or `"interrupted"`. Issuer-asserted reason the chain ended. `"complete"` means the issuer ran to normal end-of-session; `"interrupted"` means a best-effort terminal receipt was emitted on signal or known abort path. Only meaningful alongside `chain.terminal: true` — a non-terminal receipt with `chain.status` is schema-invalid. Absence on a terminal receipt is equivalent to `"complete"` for backwards compatibility. The verifier-derived classification `"unknown"` (chains with no terminal at all) is never written on the wire. See §7.3.3. |
| `keyRotation` | No | Present only on a key-rotation event (ADR-0015); a receipt that is not a rotation event MUST NOT include it. When present, all seven sub-fields are required and the receipt MUST be signed with the **outgoing** key. Note the camelCase field name, unlike its snake_case siblings. See §7.3.7. |
| `keyRotation.event_type` | Yes* | Constant `"key_rotated"`. *Required when `keyRotation` is present. |
| `keyRotation.new_public_key` | Yes* | The **incoming** public key inline: raw key bytes per the algorithm's canonical encoding (Ed25519: the 32-byte public key per RFC 8032 §5.1.5), multibase-encoded with the `u` base64url prefix (the encoding §7.2 uses for `proof.proofValue`, applied to raw public-key bytes). *Required when `keyRotation` is present. |
| `keyRotation.old_key_fingerprint` | Yes* | `sha256:` prefixed hash of the outgoing public key's **raw bytes** (not SPKI/PEM, not a backend handle). A consistency index against the outgoing key, which is resolved from `proof.verificationMethod` (or, at genesis, the out-of-band registered key). *Required when `keyRotation` is present. |
| `keyRotation.new_key_fingerprint` | Yes* | `sha256:` prefixed hash of the incoming public key's raw bytes. MUST equal the SHA-256 of the bytes decoded from `new_public_key`. *Required when `keyRotation` is present. |
| `keyRotation.old_algorithm` | Yes* | Algorithm tag of the outgoing key (e.g. `"ed25519"`). Used to verify the rotation event's own signature. *Required when `keyRotation` is present. |
| `keyRotation.new_algorithm` | Yes* | Algorithm tag of the incoming key. Equal to `old_algorithm` for same-algorithm rotations. Used to verify subsequent receipts. *Required when `keyRotation` is present. |
| `keyRotation.signed_with` | Yes* | Constant `"old"`: the rotation event is signed with the outgoing key, anchoring the transition to the key being retired. *Required when `keyRotation` is present. |

#### 4.3.2.1 Intent field guidance (non-normative)

The `intent` fields link an action to the context that triggered it. Because agent frameworks differ in how they structure conversations and reasoning, the following guidance is non-normative in this version. Capitalized keywords (e.g., "SHOULD") in this subsection are used for consistency with the rest of the document but are informational, not normative.

**`conversation_hash`** should be computed over the complete message history — including system prompts, user messages, assistant messages, and tool results — in the conversation thread that preceded this action, serialized as an RFC 8785 canonical JSON array of message objects. Implementations that truncate or filter the conversation context should document their truncation policy. If no conversation context exists (e.g., a scheduled autonomous action), this field should be omitted.

**`reasoning_hash`** should be computed over the agent's reasoning trace (e.g., chain-of-thought, planning steps, or extended thinking blocks) that led to this specific action. The content and format of reasoning traces vary across agent frameworks; implementations should document what content is included. If the agent framework does not expose a reasoning trace, this field should be omitted rather than hashed as empty.

> **Note:** Cross-agent intent comparison requires implementations to document their hashing inputs. Future versions may promote specific content boundaries to normative requirements.

#### 4.3.3 `proof`

| Field | Required | Description |
|---|---|---|
| `type` | Yes | MUST be `"Ed25519Signature2020"`. |
| `created` | Yes | ISO 8601 datetime when the proof was created. |
| `verificationMethod` | Yes | DID URL of the signing key (e.g. `did:agent:...#key-1`). |
| `proofPurpose` | Yes | MUST be `"assertionMethod"`. |
| `proofValue` | Yes | Multibase-encoded (`u`-prefixed base64url, no padding) Ed25519 signature over the canonical receipt (proof field excluded). |

### 4.4 JSON Schema

A machine-readable JSON Schema (draft 2020-12) for validating Agent Receipts is provided at:

→ [`schema/agent-receipt.schema.json`](../schema/agent-receipt.schema.json)

The schema encodes all required/optional field constraints, enum values, hash format patterns, and ID formats defined in §4.3. Implementations SHOULD validate receipts against this schema before signing or persisting.

---

## 5. Action Taxonomy

Hierarchical action types, organized by domain. Risk levels are defaults — implementations may override based on context.

A canonical machine-readable taxonomy is defined in [`spec/taxonomy/action-types.json`](../spec/taxonomy/action-types.json). Implementations SHOULD treat the JSON taxonomy as authoritative for type names and default risk levels. The tables below are illustrative; if discrepancies arise, the JSON file is the source of truth. Future versions of the taxonomy MAY include parameter schemas for each action type to support deterministic `parameters_hash` verification (see §9.9).

### 5.1 Filesystem

| Action type | Description | Default risk |
|---|---|---|
| `filesystem.file.create` | Create a file | low |
| `filesystem.file.read` | Read a file | low |
| `filesystem.file.modify` | Modify a file | medium |
| `filesystem.file.delete` | Delete a file | high |
| `filesystem.file.move` | Move or rename a file | medium |
| `filesystem.directory.create` | Create a directory | low |
| `filesystem.directory.delete` | Delete a directory | high |

### 5.2 System

| Action type | Description | Default risk |
|---|---|---|
| `system.application.launch` | Launch an application | low |
| `system.application.control` | Control an application via UI automation | medium |
| `system.settings.modify` | Modify system or app settings | high |
| `system.command.execute` | Execute a shell command | high |
| `system.browser.navigate` | Navigate to a URL | low |
| `system.browser.form_submit` | Submit a web form | medium |
| `system.browser.authenticate` | Log into a service | high |

### 5.3 Communication

| Action type | Description | Default risk |
|---|---|---|
| `communication.email.send` | Send an email | high |
| `communication.email.draft` | Create a draft email | medium |
| `communication.email.read` | Read email content | low |
| `communication.email.delete` | Delete an email | high |
| `communication.message.send` | Send a chat message (Slack, Teams, etc.) | high |
| `communication.calendar.create` | Create a calendar event | medium |
| `communication.calendar.modify` | Modify a calendar event | medium |
| `communication.calendar.delete` | Delete a calendar event | high |

### 5.4 Documents

| Action type | Description | Default risk |
|---|---|---|
| `document.file.create` | Create a new document | low |
| `document.file.modify` | Modify document content | medium |
| `document.file.delete` | Delete a document | high |
| `document.file.share` | Share a document with others | high |
| `document.spreadsheet.modify_cell` | Modify spreadsheet cell values | medium |
| `document.spreadsheet.modify_formula` | Modify spreadsheet formulas | high |
| `document.spreadsheet.modify_structure` | Add/remove sheets, rows, columns | medium |
| `document.presentation.modify_slide` | Modify presentation slide content | medium |

### 5.5 Financial

| Action type | Description | Default risk |
|---|---|---|
| `financial.payment.initiate` | Initiate a payment or purchase | critical |
| `financial.payment.authorize` | Authorize a pending payment | critical |
| `financial.subscription.create` | Create a subscription | critical |
| `financial.subscription.cancel` | Cancel a subscription | high |
| `financial.booking.create` | Book travel, accommodation, etc. | high |
| `financial.booking.cancel` | Cancel a booking | high |

### 5.6 Data

| Action type | Description | Default risk |
|---|---|---|
| `data.api.read` | Read data from an external API | low |
| `data.api.write` | Write data to an external API | medium |
| `data.api.delete` | Delete data via an external API | high |
| `data.database.query` | Query a database | low |
| `data.database.modify` | Modify database records | high |

### 5.7 Unknown

| Action type | Description | Default risk |
|---|---|---|
| `unknown` | Action that does not map to any known type | medium |

Any action that cannot be classified via the taxonomy falls back to `unknown` with a default risk level of `medium`. When `action.type` is `unknown`, `action.target` MUST be present and `action.target.system` MUST contain the original tool name or method identifier to preserve traceability for later classification. Implementations SHOULD track the frequency of `unknown`-typed receipts and surface unclassified action patterns for taxonomy extension.

### 5.8 Custom Action Types

Implementations MAY define action types beyond those listed above. Custom action types MUST use a reverse-domain prefix to avoid collisions with the standard taxonomy (e.g. `com.acme.crm.lead.create`, `io.example.ml.model.deploy`). Custom types MUST declare a default risk level. The `unknown` fallback still applies for any action that cannot be classified.

---

## 6. Risk Levels

Four levels, used for filtering, alerting, and authorization policy:

| Level | Description | Examples |
|---|---|---|
| `low` | Read-only or easily reversible | Read a file, navigate to a URL, create a draft |
| `medium` | Modifies state but reversible or low-impact | Edit a document, move a file, modify settings |
| `high` | Significant state change, may be hard to reverse | Send an email, delete a file, share a document |
| `critical` | Financial commitment or irreversible action | Make a purchase, authorize a payment, delete an account |

Risk levels are assigned by action type as defaults. Implementations MAY escalate but MUST NOT downgrade risk levels based on runtime context. For example, a `filesystem.file.delete` on a system backup SHOULD be escalated to `critical` even though the default is `high`. The no-downgrade rule ensures that risk levels serve as a reliable floor for compliance and audit tooling — a consumer of receipts can trust that any receipt marked `high` represents at least a `high`-risk action by the taxonomy's definition.

> **Note:** The `unknown` action type carries a default risk of `medium`. High volumes of `unknown` receipts reduce the effectiveness of risk-based filtering and alerting. Where possible, implementations SHOULD define custom action types (§5.8) rather than relying on the `unknown` fallback.

---

## 7. Receipt Chain Verification

### 7.1 Canonical form

For hashing and signing, receipts MUST be serialized using the JSON Canonicalization Scheme (RFC 8785) with the `proof` field removed before hashing. This canonicalization step is aligned with the use of RFC 8785 in the W3C Verifiable Credentials Data Integrity specification; however, the overall signing procedure defined in this document (see §7.2 and §10) is intentionally simplified and is not a full implementation of the W3C Data Integrity algorithm.

#### 7.1.1 Null and optional field handling

Implementations MUST apply the following normalisation before serializing to RFC 8785:

- **Required-nullable fields** — fields listed in the schema `required` array whose type permits `null` MUST be emitted with their value, including the explicit JSON `null` literal when the value is null. The only current required-nullable field is `credentialSubject.chain.previous_receipt_hash` (null for the first receipt in a chain, a hash string for all subsequent receipts).
- **Optional fields** — fields not listed in `required` MUST NOT be emitted when their value is null or absent. An SDK that receives `null` on an optional field MUST normalise it to absent before canonicalising. The form `"error":null` is not a valid canonical representation.

This rule ensures all three SDKs produce byte-identical canonical output for the same logical receipt regardless of whether an optional field is set to `null` or simply omitted by the caller. Cross-SDK test vectors in `cross-sdk-tests/canonicalization_vectors.json` pin the expected behaviour and are intended to enforce this invariant once integrated into each SDK's CI (tracked in #82, #86, #118).

### 7.2 Signing

The issuer MUST sign the canonical receipt (proof field excluded) with its Ed25519 private key. The signature MUST be encoded as a multibase string (`u`-prefixed base64url, no padding) and placed in `proof.proofValue`.

### 7.3 Chain integrity verification

To verify a receipt chain:

1. Retrieve all receipts for the chain, ordered by `chain.sequence`. Let _n_ be the number of receipts.
2. For each receipt _R(i)_ (0-based index):
   a. Verify the `proof` signature against the issuer's public key at `proof.verificationMethod`. (Note: resolving the public key from the `verificationMethod` DID URL requires a DID resolution mechanism, which is not specified by this version of the protocol. See §9.6.)
   b. Compute the hex-encoded SHA-256 digest of the RFC 8785 canonical form of _R(i)_ with the `proof` field removed.
   c. If _i < n - 1_, confirm _R(i+1)_'s `chain.previous_receipt_hash` equals `sha256:` concatenated with that hex digest.
3. For each receipt _R(i)_ where _i > 0_, confirm `chain.sequence` equals _R(i-1)_'s `chain.sequence` + 1.
4. Confirm _R(0)_'s `chain.previous_receipt_hash` is `null`.

#### 7.3.1 Chain truncation detection

Chain verification as defined in steps 1–4 does **not** detect tail truncation: dropping the last N receipts from a chain still produces `Valid: true`, because no in-chain field commits to the chain's total length or final state. This is a deliberate design floor — a receipt can only commit to values its issuer already knows at signing time.

Three mitigations are available:

1. **Out-of-band witness (`ExpectedLength` / `ExpectedFinalHash`).** Callers who maintain an external record of chain state (audit log, transparency log, signed checkpoint) MAY supply `ExpectedLength` and/or `ExpectedFinalHash` to `VerifyChain`. Verification fails when the observed chain does not match. When unsupplied, the verifier preserves current behaviour — `Valid: true` for a tail-truncated chain is intentional and documented.

2. **In-band terminal marker (`chain.terminal` + `chain.status` + `RequireTerminal`).** When the final receipt in a chain bears `chain.terminal: true`, no receipt referencing it via `previous_receipt_hash` is permitted — this check runs unconditionally (§7.3.2). The terminal receipt MAY also carry `chain.status` (§7.3.3) to distinguish normal `"complete"` termination from best-effort `"interrupted"` termination on signal. Callers MAY additionally supply `RequireTerminal`; verification then fails if the final observed receipt is not explicitly terminal. If the terminal receipt itself was dropped, `RequireTerminal` fires, but `chain.terminal` alone cannot detect this case — the verifier classifies the chain's termination status as `"unknown"` (§7.3.3) regardless of `RequireTerminal`.

3. **Floor.** Tail truncation of an open (non-terminal) chain without any external witness **cannot** be detected by any mechanism defined in this specification. Operators whose compliance requirements demand detection of such truncation MUST maintain an out-of-band chain record and supply `ExpectedFinalHash`.

#### 7.3.2 Receipt-after-terminal integrity check (automatic)

If any receipt R(i) in the verified input has `chain.terminal: true`, and a subsequent receipt R(i+1) exists at position i+1 in the input, verification MUST fail immediately with a clear "receipt after terminal" error. This check is unconditional — no caller parameter can suppress it. It does not depend on R(i+1)'s `previous_receipt_hash` field; the presence of any receipt after a terminal predecessor in the verified sequence is sufficient to trigger the failure. This is the verifier's enforcement mechanism against an issuer who marks a chain closed and then extends it, or an attacker who appends a receipt to a chain its issuer marked terminal.

If any step fails, the chain is broken at that point. Receipts before the break may still be individually valid; receipts after are suspect.

> **Note:** This algorithm assumes a linear chain where each receipt has exactly one predecessor. It does not cover concurrent or branching topologies (e.g., fan-out tool calls producing multiple receipts with the same predecessor). See §9.8.

#### 7.3.3 Chain termination status

A chain ends in one of three states; the verifier's `ChainVerification` result MUST surface which:

1. **`"complete"`** — the chain has a final receipt with `chain.terminal: true` and either `chain.status: "complete"` or no `chain.status` field. The issuer reached normal end-of-session and emitted a terminator deliberately.

2. **`"interrupted"`** — the chain has a final receipt with `chain.terminal: true` and `chain.status: "interrupted"`. The issuer (or the signing process on its behalf at shutdown — typically the daemon, since signing is daemon-side per ADR-0010) emitted a best-effort terminator before crashing or being killed. The chain is closed but the closure was not part of normal operation. Auditors SHOULD treat the chain as complete for integrity purposes but flag the imperfect termination for operational review.

3. **`"unknown"`** — the chain has no terminal receipt. The verifier cannot distinguish a chain whose issuer crashed mid-session (no terminator written) from a chain whose terminator was truncated off the end (which `ExpectedLength` / `ExpectedFinalHash` per §7.3.1 may detect). This classification is the verifier's signal that completeness cannot be determined from the chain alone.

The verifier classifies in this exact order: presence of `chain.terminal: true` and the value of `chain.status` on the final receipt determine `"complete"` or `"interrupted"`; absence of any terminal receipt yields `"unknown"`. The classification is independent of `RequireTerminal` — `RequireTerminal` controls whether `unknown` is a verification failure, but the classification is reported regardless.

Issuers MUST NOT write `chain.status: "unknown"` to the wire; it is a verifier-derived value. Implementations encountering `"unknown"` in a receipt's `chain.status` field MUST reject the receipt as schema-invalid.

#### 7.3.4 Chain identifier binding (automatic)

All receipts within a chain MUST share the same `chain.chain_id` (per §7.5, a chain is the authoritative log of a single issuer; the `chain_id` is the opaque identifier that groups its receipts). Verifiers MUST reject input in which any receipt R(i) has a `chain.chain_id` different from that of R(0), failing immediately with a clear "chain_id mismatch" error that identifies the offending index and both `chain_id` values. This check is unconditional — no caller parameter can suppress it, and it runs independently of `previous_receipt_hash` linkage so that an attacker who splices in a forged hash link cannot mix receipts from two distinct chains under a single verification call. Verifiers MUST NOT attempt to "stitch" or partition cross-chain input; the only correct response is rejection.

This check parallels §7.3.2: both enforce single-chain integrity invariants that no caller parameter can disable. Verifying receipts from multiple chains requires multiple calls to the chain verifier, one per chain.

#### 7.3.5 Sequence number contiguity and store trust

Verification step 3 (above) mandates strict contiguity: each receipt's `chain.sequence` MUST equal its predecessor's + 1. Any gap (e.g. receipts at sequence 1, 3, 5 missing sequence 2 and 4) is a hard verification failure, not a warning. Verifiers MUST mark the chain invalid and identify the offending index. This applies even when signatures and hash linkage on the surviving receipts are otherwise valid — a partial chain with gaps cannot be silently accepted.

**Store trust model.** Chain verification proves the integrity of the receipts the verifier is *given*; it cannot, on its own, prove that the verifier was given every receipt the issuer wrote. If an attacker can both delete receipts from the store AND re-sign every downstream receipt with an updated `previous_receipt_hash` (which requires the agent's signing key), they can erase mid-chain history undetectably from chain verification alone. The receipt store is therefore a trusted component for completeness claims.

Operators who require detection of store-level tampering SHOULD layer at least one of the following on top of chain verification:

- **Append-only storage backend** — S3 Object Lock, immutable WORM volumes, or an equivalent that prevents in-place mutation and rejects deletes.
- **External chain-state witnesses** — `ExpectedLength` and/or `ExpectedFinalHash` (per §7.3.1) supplied from an out-of-band record the attacker cannot also rewrite (separate audit log, transparency log, signed checkpoint).
- **Periodic chain-head anchoring** — publish chain-head hashes to an append-only public log at regular intervals; gaps relative to the anchored state are evidence of store-level rewriting.

These are operational controls outside the protocol; the verifier cannot synthesize them and the spec does not mandate any specific backend. They are listed here so that compliance reviewers can match the protocol's verification contract to their operational threat model.

#### 7.3.6 Idempotency key and retry deduplication

When an agent retries a tool call (e.g. on timeout), the wrapping proxy or SDK may emit more than one `tool_call` receipt for the same logical operation. Without a shared identifier, an auditor cannot distinguish a legitimate retry from a duplicated emission. `action.idempotency_key` (§4.3.2) carries a stable identifier for the logical operation so that all receipts arising from one operation share a value. The SDK and MCP proxy SHOULD populate it automatically where a stable source exists (e.g. the MCP proxy derives it from the wrapped JSON-RPC request `id`).

Duplicate `idempotency_key` values are **not** a verification failure. Retries are a normal, legitimate occurrence and the protocol does not attempt to suppress duplicate receipts. Verifiers MUST treat two or more receipts sharing a non-empty `idempotency_key` as a **warning** surfaced alongside the verification result, leaving `valid` unchanged. The warning lets auditors review whether the duplicates represent expected retries or unexpected double-counting. Receipts that omit `idempotency_key` never contribute to duplicate warnings.

#### 7.3.7 Key-rotation traversal

A chain MAY change its signing key mid-stream. The transition is recorded as a **key-rotation event**: a receipt carrying `credentialSubject.keyRotation` (§4.3.2), signed with the **outgoing** key, that carries the **incoming** public key inline in `new_public_key`. This lets a verifier chain through arbitrary rotations using only the chain and the genesis key — no external key registry is consulted on the traversal path (ADR-0015).

A verifier maintains an *active key*, initialised to the genesis key supplied by the caller, and processes receipts in order. For each receipt:

1. **Verify the signature under the active key.** A key-rotation receipt is signed with the outgoing key (`signed_with: "old"`), so it verifies under the *current* active key like any other receipt — the active key does not change until *after* this receipt is processed.
2. **If `keyRotation` is present, validate the rotation event:**
   a. `event_type` MUST equal `"key_rotated"` and `signed_with` MUST equal `"old"`.
   b. `old_algorithm` and `new_algorithm` MUST name a supported algorithm. This version supports only `"ed25519"` (ADR-0001); a verifier that cannot verify under the named algorithm MUST fail.
   c. The SHA-256 of the active key's raw bytes MUST equal `old_key_fingerprint` (consistency index — a mismatch is a hard error).
   d. Decode `new_public_key` (multibase `u` → raw bytes). Its SHA-256 MUST equal `new_key_fingerprint` (a mismatch is a hard error).
3. **Adopt the incoming key.** Once a key-rotation receipt has both a valid signature under the outgoing key and valid rotation fields, the active key becomes the decoded `new_public_key` for every subsequent receipt, until the next rotation. A rotation receipt whose own signature is invalid MUST NOT hand the key over — the binding of `new_public_key` to the prior chain segment is only as trustworthy as the outgoing key's signature over it.

The genesis (first) signing key is still registered out of band — there is no rotation event that introduces it — and that registration is what the first receipt's `proof.verificationMethod` resolves against. `proof.verificationMethod` identifies the *issuer*, not a specific key, and remains stable across rotations; verifiers MUST NOT treat it as a per-key identifier.

Hash linkage and sequence contiguity (§7.3) are unaffected by rotation: a key-rotation receipt is hash-linked and sequenced exactly like any other receipt. Rotation only changes which key validates the signature.

### 7.4 Reversal receipts

Receipts are immutable once issued. To record that an action was reversed, issue a new receipt appended to the same chain with:

- The same `action.type` as the original receipt
- `outcome.status`: `"success"` if the reversal succeeded, `"failure"` if it did not
- `outcome.reversal_of` set to the `id` of the original receipt

The chain is always append-only; the original receipt is never mutated or removed.

### 7.5 Chain issuer model

A receipt chain MUST have a single issuer. All receipts within a chain MUST have the same `issuer.id`. Delegated agents MUST create a new chain and link it to the parent chain via the `delegation` field (see §4.3.2). This ensures that each chain is an authoritative log from a single agent, and cross-agent workflows are represented as linked chains rather than mixed-issuer sequences.

### 7.6 Delegation verification

When a receipt chain includes a `delegation` field (see §4.3.2):

1. Resolve `delegation.parent_chain_id` and retrieve the parent chain.
2. Locate the receipt with `id` matching `delegation.parent_receipt_id` in the parent chain.
3. Confirm `delegation.delegator.id` matches the `issuer.id` of the parent chain's receipts.
4. Confirm the `principal` in the delegated chain matches the `principal` in the parent chain (the human on whose behalf actions are taken does not change across delegation).

If any step fails, the delegation link is unverifiable. The delegated chain's receipts are still individually valid but cannot be traced back to the parent chain.

### 7.7 Trusted timestamp verification

When `action.trusted_timestamp` is present and non-null:

1. Base64-decode the value to obtain the DER-encoded RFC 3161 `TimeStampToken`.
2. Verify the TSA's signature on the `TimeStampToken` against the TSA's certificate.
3. Extract the `MessageImprint` hash from the `TimeStampToken`.
4. Confirm the `MessageImprint` hash matches the SHA-256 digest of the receipt's canonical form (proof field removed) — the same digest used for signing (§7.2).
5. Confirm the TSA timestamp falls within a reasonable window of `action.timestamp` (implementation-defined tolerance).

Trusted timestamps are OPTIONAL. When present, they provide independent evidence of when the receipt was created, which cannot be backdated by the issuer.

### 7.8 End-to-end receipt verification

To verify a single Agent Receipt:

1. **Schema validation.** Validate the receipt against the JSON Schema (§4.4). If validation fails, verification fails with `MALFORMED_RECEIPT`.
2. **DID resolution.** Resolve the DID URL in `proof.verificationMethod` to obtain the issuer's public key. The resolution mechanism depends on the DID method used (see §9.6). If the DID cannot be resolved, verification fails with `UNRESOLVABLE_DID`.
3. **Signature verification.** Compute the RFC 8785 canonical serialization (UTF-8 bytes) of the receipt with the `proof` field removed. Verify the Ed25519 signature in `proof.proofValue` (decoded from multibase `u`-prefixed base64url) directly over these canonical bytes using the resolved public key. If verification fails, the receipt is `INVALID_SIGNATURE`.
4. **Timestamp validation.** If `action.trusted_timestamp` is present, verify it per §7.7. If the trusted timestamp is invalid, the receipt is `INVALID_TIMESTAMP`. If no trusted timestamp is present, the receipt relies on `issuanceDate` and `action.timestamp` which are issuer-asserted and not independently verifiable.
5. **Chain context.** If verifying as part of a chain, perform chain integrity checks per §7.3. If verifying a standalone receipt, chain fields indicate the issuer-asserted position in a chain. A verifier MAY perform local consistency checks (e.g., that `sequence` is a positive integer and `previous_receipt_hash` is well-formed), but the receipt's actual chain position cannot be confirmed without at least the preceding receipt.
6. **Delegation context.** If the receipt includes a `delegation` field, verify per §7.6.

A receipt that passes steps 1–4 is individually valid. Steps 5–6 provide chain and delegation context but require additional receipts to verify fully.

> **Note:** This algorithm depends on DID resolution (step 2), which is not fully specified in this version. Implementations MUST document their DID resolution strategy. See §9.6.

---

## 8. Relationship to Existing Work

| Project | Relationship |
|---|---|
| **C2PA / Content Credentials** | Inspiration for the approach (signed provenance manifests, hash-chained). The Agent Receipt Protocol extends the concept from media assets to agent actions. Could potentially be formalized as a C2PA extension. |
| **W3C Verifiable Credentials** | Agent Receipts are W3C VCs. The VC Data Model 2.0 is used as the envelope format. |
| **Grantex** | Complementary. Grantex handles authorization (should this agent be allowed to act?). The Agent Receipt Protocol handles receipts (what did this agent do?). An Agent Receipt may reference a Grantex grant token in `authorization.grant_ref`. |
| **AgentStamp** | Overlapping in audit trail and agent identity. AgentStamp's hash-chained audit is similar but narrower (trust verification events only). |
| **MolTrust** | Complementary. Agent registry and reputation. Could serve as the identity layer issuing the agent DIDs referenced in receipts. |
| **W3C DIDs** | Agent and principal identities are expressed as DIDs. No specific DID method is required. |

---

## 9. Open Questions

1. ~~**Multi-agent delegation.**~~ **Resolved.** See `delegation` field in §4.3.2 and verification in §7.6.

2. **Reversal receipt schema.** The field for linking a reversal receipt back to the original receipt (`reversal_of`) needs to be defined and placed within `credentialSubject` or as a top-level field.

3. **Privacy granularity.** How much control does the principal have over what appears in receipts? Action types reveal what was done even without parameters. Needs a user consent model.

4. **Offline / batched receipts.** If the agent cannot sign in real-time (e.g., high-frequency or offline scenarios), can receipts be batched and signed later? This weakens chain integrity guarantees and needs explicit handling.

5. ~~**Multiple issuers per chain.**~~ **Resolved.** A chain MUST have a single issuer (§7.5). Multi-agent scenarios use separate chains linked via `delegation` (§7.6).

6. **DID method requirements and key lifecycle.** The spec requires a DID for the issuer but does not mandate a DID method. Should conformance require resolvable DIDs, or are opaque identifiers acceptable for early implementations? Additionally, the spec does not address agent key lifecycle: how Ed25519 key pairs are generated, where private keys are stored, how keys are rotated (and how rotation interacts with chain verification), or how compromised keys are revoked. The `did:agent:` identifier used in examples has no defined resolution mechanism — a verifier cannot resolve it to a public key without out-of-band knowledge. A companion specification (e.g., MolTrust for agent registry and reputation) may address key management, but the boundary between this spec and any such companion is undefined.

7. **Sequence gaps.** If a receipt is created but never persisted (e.g., crash during write), the chain will have a gap in `chain.sequence`. The verification algorithm (§7.3) treats this as a chain break. Whether verifiers should distinguish "gap" from "tamper" is undefined.

8. **Concurrent action streams.** The chain model is strictly linear: each receipt references exactly one predecessor via `chain.previous_receipt_hash`, and `chain.sequence` is monotonically increasing. Modern agent patterns — fan-out tool calls, sub-agent hierarchies, orchestrator/worker topologies — produce concurrent action streams that cannot be represented as a single linear chain. Possible approaches include: (a) allowing `chain.previous_receipt_hash` to be an array for DAG-structured chains, (b) defining explicit fork/join receipt types, or (c) requiring separate chains per concurrent branch with a linking mechanism. The delegation model (§7.5) partially addresses multi-agent scenarios but does not cover intra-agent concurrency (e.g., an agent dispatching multiple tool calls in parallel within a single session).

9. **Per-action-type parameter schemas.** The `parameters_hash` field enables privacy-preserving proof of action parameters. Given disclosed parameters as a JSON value, a verifier can independently reconstruct the RFC 8785 canonical form and recompute `parameters_hash`. What is missing without parameter schemas per taxonomy entry is the ability to validate the disclosed parameters against an expected structure for that `action.type` and to standardize parameter layouts across implementations. Defining per-action-type parameter schemas would provide this validation and interoperability. This is deferred to a future version.

10. **Intent field content boundaries.** The `conversation_hash` and `reasoning_hash` fields lack normative definitions of what content should be hashed. Cross-agent interoperability requires either normative content boundaries or a mechanism for implementations to declare their hashing inputs. See §4.3.2.1 for non-normative guidance.

11. **Verification error taxonomy.** The end-to-end verification algorithm (§7.8) references verification error conditions (`MALFORMED_RECEIPT`, `UNRESOLVABLE_DID`, `INVALID_SIGNATURE`, `INVALID_TIMESTAMP`) but does not define a formal error taxonomy. A future version should define machine-readable codes covering both malformed receipts and verification results to enable consistent error reporting across implementations.

---

## 10. Design Decisions

1. **W3C VC envelope.** Receipts conform to the VC Data Model 2.0 JSON shape. No VC library dependency is required — receipts MAY be constructed with plain JSON serialization. The VC envelope is used for interoperability with existing VC tooling, not as a binding requirement on implementations. The top-level `version` field is a protocol extension not defined by the VC Data Model; VC tooling that validates strictly against the VC schema SHOULD ignore unrecognized top-level fields.

2. **Ed25519 signing.** Single proof type for this version. The `proof.type` value `Ed25519Signature2020` is borrowed from the W3C Data Integrity family for ecosystem recognition, but the signing input is intentionally simplified: the signer MUST compute the Ed25519 signature over the RFC 8785 canonical JSON of the receipt with the `proof` field removed. This differs from the full W3C Data Integrity signing algorithm (which constructs a separate verification hash from document and proof options). Implementations that need full Data Integrity compatibility SHOULD use the complete algorithm and note this in their conformance documentation. Multi-proof-type support (e.g., X.509 for C2PA alignment) is deferred.

3. **Trusted timestamps.** Local timestamps are the minimum requirement. RFC 3161 TSA tokens are OPTIONAL but RECOMMENDED for compliance-grade deployments. When present, the TSA timestamps the same canonical JSON used for signing, providing independent non-repudiation of receipt creation time. See §7.7 for verification.

4. **Chain scope.** Chains group receipts by a logical unit (typically a session or conversation). The definition of chain boundaries is left to implementations.

5. **Storage agnostic.** The spec defines the receipt format and chain verification algorithm. It does not prescribe a storage backend.

6. **Receipts as a separate log.** Receipts are stored in a separate log, not attached to action outputs. Attachment (C2PA-style embedding) is deferred.

7. **Revocation is append-only.** Reversal is recorded by issuing a new receipt, not by mutating the original. The chain is always append-only.

8. **Key lifecycle is out of scope for this version.** Agent key generation, secure storage, rotation, and revocation are not specified by this version of the protocol. Implementers SHOULD treat key management as a critical security concern: a compromised agent key allows production of validly-signed but fraudulent receipts that are indistinguishable from legitimate ones. MolTrust (listed in §8) or a dedicated key management specification may address this in future. At minimum, implementations SHOULD document their key generation and storage practices.

9. **base64url for `proofValue`.** The `proofValue` field uses multibase `u`-prefixed base64url (no padding) rather than the W3C Data Integrity default of base58btc (`z`). base64url avoids the need for a base58 library, is natively supported in all target runtimes, and is slightly more compact. This is an intentional deviation from the W3C default.
