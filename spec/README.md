<div align="center">

# Agent Receipt Protocol

### An open protocol for cryptographically signed, tamper-evident records of AI agent actions

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status: Draft](https://img.shields.io/badge/Status-Draft_v0.4.0-orange.svg)](v0.4.0/spec.md)

---

**AI agents act on your behalf. This protocol proves what they did.**

</div>

---

## The problem

AI agents send emails, modify documents, execute commands, and make purchases — but every vendor logs differently (if they log at all), in proprietary formats, with no way to verify the records haven't been tampered with. There's no unified view across tools. No chain of custody. No receipt.

The EU AI Act mandates traceability for high-risk AI systems. The regulation exists. The standard for how to comply doesn't.

## What Agent Receipts are

An Agent Receipt is a [W3C Verifiable Credential](https://www.w3.org/TR/vc-data-model-2.0/) signed with Ed25519, recording a single action taken by an AI agent:

| Field | What it captures |
|:---|:---|
| **Action** | What happened, classified by a standardized taxonomy |
| **Principal** | Who authorized it (human or organization) |
| **Issuer** | Which agent performed it |
| **Outcome** | Success/failure, reversibility, undo method |
| **Chain** | SHA-256 hash link to the previous receipt (tamper-evident) |
| **Privacy** | Parameters are hashed, never stored in plaintext |

Receipts are hash-chained — if anyone modifies or deletes one, the chain breaks and you'll know.

## Design principles

1. **Privacy-preserving by default.** Parameters are hashed, not stored in plaintext. The human principal controls what is disclosed.
2. **Built on existing standards.** W3C Verifiable Credentials, Ed25519, SHA-256, RFC 8785, RFC 3161. No novel cryptographic primitives.
3. **Hash-chained for integrity.** Each receipt includes the hash of the previous, forming a tamper-evident chain.
4. **Agent-agnostic.** Not tied to MCP, OpenAI function calling, or any specific framework. Any agent that can produce JSON and sign it can emit receipts.
5. **Minimal by default, extensible by design.** The core schema is small. Domain-specific extensions can be layered on via additional `@context` URIs.

## Why receipts?

**Post-incident review.** An agent ran overnight and something broke. The receipt chain shows exactly which actions it took, in what order, and whether each succeeded or failed — with cryptographic proof the log hasn't been altered after the fact.

**Compliance and audit.** Regulated environments require evidence of what systems did and why. Receipts are W3C Verifiable Credentials with Ed25519 signatures, giving auditors a tamper-evident trail they can independently verify.

**Safer autonomous agents.** Agents can query their own audit trail mid-session. Before taking a high-risk action, they can check what they've already done and whether previous steps succeeded, enabling self-correcting workflows.

**Multi-agent trust.** When agents collaborate, receipts serve as proof of prior actions. Agent B can verify that Agent A actually completed step 1 before proceeding to step 2, without trusting a shared log.

**Usage tracking.** Every action is classified by type and risk level, giving you a structured breakdown of what agents spent their time on.

### Beyond local storage

The protocol is designed for receipts to travel — publishing to a shared ledger, forwarding to a compliance system, or exchanging between agents as proof of prior actions. Receipts are portable W3C Verifiable Credentials, but where they go is always under the user's control.

## Specification

| Document | Description |
|:---|:---|
| [v0.4.0/spec.md](v0.4.0/spec.md) | Protocol specification (Draft v0.4.0; latest) |
| [schema/agent-receipt.schema.json](schema/agent-receipt.schema.json) | JSON Schema for receipts (Draft 2020-12) |
| [spec/taxonomy/action-types.json](spec/taxonomy/action-types.json) | Canonical action type definitions |
| [schema/taxonomy.schema.json](schema/taxonomy.schema.json) | JSON Schema for the taxonomy |

**Status:** Draft — see [GOVERNANCE.md](GOVERNANCE.md) for the spec lifecycle.

## Action Taxonomy

The protocol defines a hierarchical vocabulary of action types organized by domain, each with a default risk level:

| Domain | Examples | Risk levels |
|:---|:---|:---|
| **Filesystem** | `filesystem.file.read`, `filesystem.file.delete` | low — high |
| **System** | `system.command.execute`, `system.browser.navigate` | low — high |
| **Communication** | `communication.email.send` (planned) | medium — critical |
| **Financial** | `financial.payment.initiate` (planned) | high — critical |

The canonical definitions live in [`spec/taxonomy/action-types.json`](spec/taxonomy/action-types.json). The taxonomy is extensible — implementations can add domain-specific types and override default risk levels.

## Example receipt

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://agentreceipts.ai/context/v1"
  ],
  "id": "urn:receipt:550e8400-e29b-41d4-a716-446655440000",
  "type": ["VerifiableCredential", "AgentReceipt"],
  "version": "0.1.0",
  "issuer": { "id": "did:agent:claude-instance-abc123", "type": "AIAgent" },
  "issuanceDate": "2026-03-31T14:30:00Z",
  "credentialSubject": {
    "principal": { "id": "did:user:alice", "type": "HumanPrincipal" },
    "action": {
      "id": "act_7f3a1b2c-d4e5-46f7-a8b9-c0d1e2f3a4b5",
      "type": "filesystem.file.delete",
      "risk_level": "high",
      "target": { "system": "local", "resource": "/tmp/old-report.pdf" },
      "parameters_hash": "sha256:a3f1c2d4e5b6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1d6",
      "timestamp": "2026-03-31T14:30:00Z"
    },
    "outcome": {
      "status": "success",
      "reversible": false
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
    "verificationMethod": "did:agent:claude-instance-abc123#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "ul_wFLgGWlzFaYt2ckT4wZfoeRa7ZqL0tt3y10dgr7FdsVMivs5tc9ZrUYBJ_FKEE4aFApeAzPH6jp57irtgDCw"
  }
}
```

## Implementations

| Repository | Language | Description |
|:---|:---|:---|
| [@obsigna/sdk-ts](https://github.com/agent-receipts/obsigna/tree/main/sdk/ts) | TypeScript | SDK — receipt creation, signing, hashing, storage, taxonomy ([npm](https://www.npmjs.com/package/@obsigna/sdk-ts)) |
| [ojongerius/attest](https://github.com/ojongerius/attest) | TypeScript | MCP proxy + CLI — reference implementation |
| [agent-receipts/sdk-py](https://github.com/agent-receipts/obsigna/tree/main/sdk/py) | Python | SDK — receipt creation, signing, hashing, chain verification ([PyPI](https://pypi.org/project/obsigna/)) |

## Contributing

The most valuable contributions right now aren't code — they're domain expertise. If you work in a regulated industry deploying AI agents, [open an issue](https://github.com/agent-receipts/spec/issues) or comment on the [spec](v0.4.0/spec.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT — see [LICENSE](LICENSE).
