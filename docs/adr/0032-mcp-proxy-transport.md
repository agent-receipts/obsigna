# ADR-0032: mcp-proxy Transport — stdio, HTTP Deferred

## Status

Accepted (2026-06-12).

## Context

The mcp-proxy runs on a user's laptop or a small single-tenant VM. A multi-tenant,
shared-service offering would be architected and deployed differently — different identity
plumbing, different isolation, different failure model — and that case is explicitly *not*
what this proxy serves.

Choosing a transport for the proxy looks like a plumbing decision but is really a decision
about **where principal identity comes from**. That is the root of the `did:user:unknown`
problem: when a transport multiplexes many principals over one long-lived process, the
proxy has to resolve "who is this?" per request, and the codepath that resolves it is
exactly the codepath that, on any gap, falls back to a placeholder principal. An
unattributed action then gets stamped with a guessed identity and signed into the chain.

## Decision

**The mcp-proxy transport is stdio. HTTP is deferred.**

### Rationale

- stdio means **one spawn per MCP session — one principal per process**. The principal DID
  is injected **at spawn**, from the spawning session's context. There is no per-request
  identity resolution, so the codepath that produced `did:user:unknown` ceases to exist.
  The bug is made unrepresentable, not merely fixed.
- One-principal-per-process keeps the trust boundary **structural rather than enforced in
  code** — the same argument that earned the daemon its own binary in ADR-0031 (Daemon
  Binary Topology). The process boundary *is* the principal boundary.
- It matches how MCP clients invoke servers today: spawned per session over stdio.

### Commitments this ADR locks in

- **Binding is an interface; transport is an adapter.** Identity flows through a single
  seam — `Principal(ctx) DID`. Only the stdio adapter ships now, and it fills that seam
  from spawn context. An HTTP adapter later is *additive* — a second implementation of the
  same seam — not a rewrite of the proxy.
- **Resolution precedence** for the injected principal DID is defined and ordered:
  **launch argument (`--principal`) > environment variable > config file.** The first
  source that supplies a DID wins; later sources are not consulted.
- **Absent principal fails closed.** If no principal DID is provided by any source in the
  precedence chain, the proxy refuses to emit a receipt. It never falls back to
  `did:user:unknown`, and never substitutes a default or guessed principal. A receipt
  carrying a guessed principal is *worse* than no receipt: it launders an unattributed
  action into something that looks attributed. This fail-closed rule is the actual fix —
  the stdio transport choice is what makes the rule cheap to enforce, because there is
  exactly one principal to check, once, at spawn.

## Consequences

- Unblocks the mcp-proxy build (tracked separately — see *Non-goals*).
- Resolves the `did:user:unknown` issue **by design**: with one principal injected per
  process and a fail-closed rule for its absence, there is no execution path that can emit
  a placeholder principal.
- HTTP transport is deferred until a standing or shared-service requirement actually
  exists. Revisiting that need re-opens this ADR; the `Principal(ctx)` seam is the
  designated extension point, so the revisit adds an adapter rather than reworking the
  proxy.
- The trust boundary is the process boundary. Operators reason about "who can this proxy
  speak for?" by looking at how it was spawned, not by auditing per-request resolution
  logic.

## Non-goals

- HTTP / multi-tenant transport. Out of scope until a shared-service requirement exists.
- The mcp-proxy implementation itself — covered by a separate change.
