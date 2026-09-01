# MCP gateway — design ported from AGT's Python `mcp_gateway.py`

Zero dependencies. `mcpGateway.ts` doesn't import AGT, doesn't import an
MCP SDK, doesn't import anything — it's the interception-point *design*
from `microsoft/agent-governance-toolkit`'s
`agent-governance-python/agent-os/src/agent_os/mcp_gateway.py`
(commit `359a2332f57d9000924baba269ed24e4e15ad8b0`), ported to TypeScript
with no source copied and no runtime dependency on the toolkit. Background
on why this exists — TypeScript's `agent-governance-typescript/src/mcp.ts`
only scans static tool *definitions*, it has no runtime interception point
at all — is in `workshop-stack-research.md` at the repo root, §2.

## What was carried over

- Two gates, not one — `interceptToolCall` (request) and
  `interceptToolResponse` (response), independently.
- A staged pipeline where every decision carries the stage that produced
  it (`deny_list`, `builtin_pattern`, `runtime`, `approval_pending`,
  `rate_limit`, ...), not just a bare allow/deny.
- Fail-closed at each pluggable call site — the policy runtime, the
  approval callback, and the response scanner each get their own
  try/catch, rather than one blanket catch at the top.
- A policy "transform" (rewritten arguments) is refused rather than
  silently collapsed into allow/deny, because this gate's return type has
  nowhere to put a rewrite.
- Redaction happens at the point of persisting an audit entry, not at the
  point of deciding — policy evaluation always sees raw params.
- Sanitization doesn't trust itself: after `sanitize()` runs, the gateway
  re-scans its own output and fails closed if anything is still there.
- Audit sink and rate-limit store are injected interfaces
  (`AuditSink`, `RateLimitStore`), so the gateway doesn't care whether
  they're in-memory, a file, or something real.
- Per-agent state, keyed by agent id, not one global counter.

## Running the demo

```bash
npx tsx demo.ts
```

`demo.ts` wires up a toy `PolicyRuntime` and `ResponseScanner` — stand-ins
for whatever a real implementation would plug in (Cedar, OPA, an obsigna
daemon call, ...) — and walks through the request-side gates (deny-list,
dangerous-parameter pattern, policy denial, transform refusal, rate limit)
and the response-side ones (clean response, a hard-blocked PII leak, a
credential leak that the toy sanitizer fails to actually remove — caught
by the rescan-after-sanitize check, not by trusting the sanitizer's own
report — and a genuinely sanitizable prompt-injection tag).

## Wiring it to a real MCP server

`McpGateway` doesn't know about transports. Call `interceptToolCall`
before dispatching a `tools/call` request to your MCP server implementation
and `interceptToolResponse` on whatever comes back, before it reaches the
model. Replace the toy `PolicyRuntime` with a real one — a Cedar
`isAuthorized` call (see the working example in `workshop-stack-research.md`
§3) is a natural fit, since `PolicyRuntime.evaluatePreToolCall` and Cedar's
`AuthorizationCall` shape are both "principal/action/resource/context in,
allow/deny out."
