# CONTEXT — Agent Receipts

> Shared language for this repo. Read this before doing anything.
> If you find yourself coining a new term, stop and check this file first.
> If the term doesn't exist here and you need one, propose adding it before using it.

## What this project is

**Agent Receipts** is an open protocol for producing tamper-evident audit trails of AI agent activity.
It is a **protocol first, library second**. Wire-format decisions outrank ergonomic API decisions.
Implementations exist in three languages (TypeScript, Python, Go) and must agree byte-for-byte on the wire.

The canonical home is `agentreceipts.ai`. The reference monorepo is `github.com/agent-receipts/obsigna`.

## Core domain terms

These terms have specific meanings in this project. Use them consistently. Do **not** introduce synonyms.

- **Receipt** — A single signed attestation of one agent action (a tool call, a model call, a decision point).
  Always Ed25519-signed. Always a W3C Verifiable Credential. Never called a "log", "event", "trace", or "record".
- **Receipt chain** — An ordered sequence of receipts where each one's hash references the previous.
  Tamper-evident; not tamper-proof. Never called a "ledger" or "log".
- **Link** — The hash pointer from one receipt to its predecessor. Not "parent_hash", not "prev_id".
- **Envelope** — The outer VC structure wrapping a receipt's payload. Distinct from the payload itself.
- **Issuer** — The entity (an agent, an MCP proxy, a plugin) producing receipts. Has a key pair.
- **Subject** — The entity the receipt is *about* (often a tool call, a model response).
- **Verifier** — Any consumer that checks a chain's integrity. Verification is offline-capable by design.
- **Anchor** — A point at which a chain's state is committed externally (e.g. to a content-addressed store).
  Optional. Anchors do not exist in the base protocol; they're an extension point.

## Surface map

- `/spec` — the wire-format normative reference. **Source of truth.** Changes here cascade.
- `/sdk/ts` — TypeScript SDK.
- `/sdk/py` — Python SDK.
- `/sdk/go` — Go SDK.
- `/mcp-proxy` — MCP proxy that wraps tool calls and emits receipts. Pure dogfood.
- `/docs/adr` — Architecture Decision Records. See ADR index there.

Related external repos (not in this tree):

- `agent-receipts/openclaw` — OpenClaw plugin. Same idea, different host.

## Invariants (do not violate without an ADR)

1. **Three-SDK consistency.** Any change to the wire format, envelope, or canonical JSON serialization in `/sdk/ts` requires equivalent changes proposed in `/sdk/py` and `/sdk/go` in the same PR or a tracking issue linked from it.
2. **Spec-first.** Wire-format changes start in `/spec` and propagate to SDKs, not the reverse.
3. **Offline verification.** No verifier should require network access to validate a chain's structural integrity.
4. **No silent breakage.** Backward-incompatible changes to the wire format require a version bump and an ADR.
5. **Storage is pluggable.** SQLite is the default backend; the protocol does not depend on it. See ADR-0004.

## Tone & conventions

- Code comments explain *why*, not *what*. The protocol's surface is small; the rationale is the hard part.
- Errors thrown by SDKs should converge on a shared taxonomy across languages. A formal verification error taxonomy is not yet defined; see spec v0.1 §9 item 11 ("Verification error taxonomy") for the open question.
- Examples in docs always use realistic agent scenarios, never `foo`/`bar`.

## Known sharp edges

- `agentreceipts.ai` is the canonical entity. A similarly named GitHub repo exists in the wild; JSON-LD and `<link rel="me">` are in place to disambiguate. Don't reintroduce ambiguity in new docs.
- `0tt0.net` has a known CSS issue from the GitHub Pages single-domain limitation; do not treat it as a styling reference.

## What this file is for

This file exists so that:
- The agent uses the same words you use, not synonyms it invents per session.
- Decisions made once stay made (link to ADRs rather than re-litigating).
- Cross-SDK invariants are visible before someone makes a one-SDK change.

If a session keeps re-explaining the same concept, that concept belongs here.
If a new term emerges from a grilling session, add it here before closing the session.
