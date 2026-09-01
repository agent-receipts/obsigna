# Workshop stack research: instrumentation stack for "Instrument your MCP server"

Research only — no recommendation of a candidate shape (A/B/C) outside the
Observations section. Prepared for the 21 October 2026 Agentic Engineering Day
NZ workshop. All work below is against the four externally named repos/packages;
`agent-receipts/*` was not cloned or inspected per the task's non-goals.

**Repos/packages inspected, with commit SHA and inspection date:**

| Source | Commit / version | Date recorded in source | Inspected on |
|---|---|---|---|
| `microsoft/agent-governance-toolkit` | `359a2332f57d9000924baba269ed24e4e15ad8b0` (shallow clone, default branch) | latest commit dated 2026-08-31 | 2026-09-01 |
| `open-telemetry/semantic-conventions-genai` | `5ca9052bc796ef1e497200b1d558fd87a201f335` (shallow clone, default branch) | latest commit dated 2026-09-01 | 2026-09-01 |
| `@cedar-policy/cedar-wasm` (npm) | `4.12.0` | published 2026-07-28 | 2026-09-01 |
| `@opentelemetry/semantic-conventions` (npm) | `1.43.0` | published 2026-07-09 | 2026-09-01 |

---

## 1. Summary table: candidate dependencies × hard constraints

Tested with `npm pack` + a real `npm ci --offline` run against committed
`vendor/*.tgz` tarballs (transitive deps also vendored, cache emptied first —
see method note below the table). ✅ = verified pass, ⚠️ = pass with a caveat,
❓ = could not verify from source alone.

| Package | 1. Pure JS / no native modules | 2. Vendorable offline | 3. Version-pinnable (still installs in 7 wks) | 4. Small transitive tree |
|---|---|---|---|---|
| `@microsoft/agent-governance-sdk` (AGT TS SDK) | ✅ 5 runtime deps, all pure JS/TS (`@noble/*`, `js-yaml`); no `node-gyp`/`binding.gyp` in the published tarball | ✅ `npm ci --offline` succeeded from vendored tarballs (see below) | ⚠️ Pinnable, but the project has shipped a breaking (SemVer-major) release roughly every 3–5 weeks since March 2026, and `CHANGELOG.md`'s `[Unreleased]` section already queues another breaking change (see §1) | ✅ Real transitive tree is 6 packages (`@noble/ciphers`, `@noble/curves→@noble/hashes`, `@noble/ed25519`, `js-yaml→argparse`) — small. (A monorepo-wide `package-lock.json` in the repo shows 417 packages, but that covers the whole monorepo incl. the VS Code extension's devDependencies, not what `npm install @microsoft/agent-governance-sdk` alone pulls.) |
| `@cedar-policy/cedar-wasm` (Cedar WASM) | ✅ WASM only, `wasm-bindgen`-generated, platform-agnostic (one `.wasm` per build target — esm/nodejs/web — not per-OS); `deps: none` | ✅ `npm ci --offline` succeeded from a vendored tarball | ✅ Zero dependencies to drift; actively released (created 2024-05-21, `4.12.0` published 2026-07-28, prior tag history back to `3.4.x`) | ✅ Zero npm dependencies |
| `@opentelemetry/semantic-conventions` | ✅ Zero dependencies, pure JS/TS constants | ✅ `npm ci --offline` succeeded from a vendored tarball | ✅ Zero dependencies; official OTel JS release cadence | ✅ Zero dependencies |
| `@opentelemetry/api` | ✅ Zero dependencies | ✅ `npm ci --offline` succeeded from a vendored tarball | ✅ Zero dependencies | ✅ Zero dependencies |
| `@opentelemetry/sdk-trace-node` + `sdk-trace-base` + `resources` (needed for a console-exporter demo) | ✅ First-party `@opentelemetry/*` packages only, no third-party or native deps in their declared `dependencies` (checked via `npm view … dependencies`, not vendor-tested end-to-end) | ❓ Not vendor-tested in this pass (same shape as the packages above; no reason to expect it fails, but not verified with an offline `npm ci`) | ✅ Same OTel JS release train as the packages above | ✅ ~6 first-party packages total for basic tracing + console export |

**Method note (constraint 2):** built a scratch project, ran `npm pack` for
`@microsoft/agent-governance-sdk@5.0.0`, `@cedar-policy/cedar-wasm@4.12.0`,
`@opentelemetry/semantic-conventions@1.43.0`, `@opentelemetry/api@1.9.0`, and
AGT's five transitive deps (`@noble/ciphers`, `@noble/curves`, `@noble/ed25519`,
`@noble/hashes`, `js-yaml`, `argparse`) into a `vendor/` directory; wrote a
`package.json` with `file:./vendor/*.tgz` references for all of the above
(direct **and** transitive — `npm.overrides` was needed to stop npm resolving
the transitive `@noble/*`/`js-yaml` deps from the live registry even though
they were also listed as `dependencies`); then ran `npm ci --offline --cache
<empty-dir>`. It succeeded (`added 10 packages … found 0 vulnerabilities`) with
no network access. **Caveat:** simply dropping the top-level tarball in
`vendor/` is not sufficient — every transitive dependency's tarball must be
vendored and pinned too, or `npm ci --offline` fails trying to reach the
registry for the un-vendored ones. For Cedar and the OTel packages this is
moot (zero deps); for AGT it means vendoring 6 tarballs, not 1.

Also ran a functional smoke test (not just an install test) confirming both
`@cedar-policy/cedar-wasm` and `@microsoft/agent-governance-sdk` actually load
and evaluate under Node from the vendored install — see §2 for the Cedar
example, which is the literal code that was run.

---

## 2. Microsoft Agent Governance Toolkit — TypeScript SDK maturity

**Source:** `microsoft/agent-governance-toolkit` @ `359a2332f57d9000924baba269ed24e4e15ad8b0`.

### Which of the four core legs are actually implemented in TypeScript

The top-level `README.md` states (README claim, not verified against source at
that point): *"All five language SDKs implement core governance (policy,
identity, trust, audit)... Python has the full stack."* `docs/PACKAGE-FEATURE-MATRIX.md`
(last reviewed 2026-05-21) makes the same claim in a "Quick Comparison" table
showing ✅ for Policy/Identity/Trust/Audit/MCP Security/etc. across all five
languages.

Checked against the actual TypeScript source
(`agent-governance-typescript/src/`):

- **Policy** — `src/policy.ts` exports `PolicyEngine`. Real, in-process
  rule evaluation (allow/deny by action string, YAML loading). ✅ implemented.
- **Identity** — `src/identity.ts` exports `AgentIdentity`, `IdentityRegistry`.
  Ed25519-based, real. ✅ implemented.
- **Trust** — `src/trust.ts` exports `TrustManager`. Real, in-process scoring.
  ✅ implemented.
- **Audit** — `src/audit.ts` exports `AuditLogger`. Real, in-process
  hash-chained log (SHA-256, Node's built-in `crypto`). ✅ implemented — but
  see "where the audit chain is written from" below for what this does and
  doesn't cover.

So the four-leg claim holds for what those four primitives mean narrowly
(policy/identity/trust/audit *exist and run* in TS). What the matrix's ✅
grid does **not** surface, and which only shows up by reading source, is
**parity of the surrounding surface**:

- **MCP gateway / interception** — TypeScript does **not** have one. See next
  section.
- **Unified CLI (`agt`)** — `PACKAGE-FEATURE-MATRIX.md` itself marks this "—
  Not yet available" for TS (Python only), which is consistent with source
  (no CLI package under `agent-governance-typescript/`).
- **Cedar policy backend** — TypeScript's `CedarBackend`
  (`src/policy-backends/cedar.ts`) is a thin HTTP client: it POSTs
  `{action, entities}` to a caller-supplied `endpoint` and expects
  `{decision: "allow"|"deny"|"review"}` or `{allow: boolean}` back. There is
  **no embedded Cedar evaluator** (no WASM, no native binding) in the
  TypeScript SDK — "Cedar support" here means "call out to something else
  that speaks Cedar over HTTP." Confirmed by the SDK's own test suite
  (`tests/policy-backends.test.ts`), which only exercises `CedarBackend` via a
  mocked `fetch` against a fake `https://cedar.example.com/evaluate` URL —
  there is no local-evaluation code path to test. This matters for the SSRF
  guard also present in that file (`isBlockedEndpoint`, blocking cloud
  metadata IPs and private ranges) — it's there because the endpoint is a
  live HTTP call, not a local library.
- The Rust `policy-engine/` core mentioned in the top-level README ("Agent
  Control Specification... Rust core") is **not** delivered to TypeScript
  as WASM or a native binding; it isn't in the TS dependency tree at all
  (`agent-governance-typescript/package.json` has no reference to it). The
  only route from TS into anything Cedar- or Rust-core-related is the
  out-of-process HTTP call above.

### What the MCP gateway does in TypeScript

It doesn't exist. `agent-governance-typescript/src/mcp.ts` exports
`McpSecurityScanner`, which does **static analysis of MCP tool
*definitions*** — pattern-matching tool `name`/`description` strings for
prompt-injection phrasing, typosquatting (Levenshtein distance to a
hardcoded list of well-known tool names), zero-width/homoglyph characters,
and "rug pull" (long descriptions with instruction-like phrasing). It takes
a `McpToolDefinition { name, description, parameters? }` and returns a
`McpScanResult` — there is no request/response interception, no session or
transport handling, and no dependency on any MCP SDK
(`@modelcontextprotocol/sdk` does not appear anywhere in
`agent-governance-typescript/`).

By contrast, the spec the README references —
`docs/specs/MCP-SECURITY-GATEWAY-1.0.md` — describes a much bigger surface
("tool call interception, response scanning, message signing, session
authentication, rate limiting, auth enforcement, CVE feed integration,
trust-gated servers, schema drift detection... All SDK implementations MUST
conform to this specification"). The actual runtime interceptor that
matches that spec exists only in Python:
`agent-governance-python/agent-os/src/agent_os/mcp_gateway.py`, exercised
by `agent-governance-python/agent-os/tests/test_mcp_gateway.py` and
`test_mcp_pii_and_response_gateway.py`. The `.NET` package
(`Microsoft.AgentGovernance.Extensions.ModelContextProtocol`) also has a
gateway-shaped integration per the README's `.NET` code sample
(`builder.Services.AddMcpServer().WithGovernance(...)`), which was not
independently verified against source (out of scope — `.NET` wasn't asked
for) but is consistent with what the matrix implies.

**Is it usable standalone?** `McpSecurityScanner` itself is a plain,
dependency-free class — you can `new McpSecurityScanner().scan(tool)`
without any broader AGT runtime. But it answers a narrower question ("does
this tool definition look malicious?") than "gateway," and does nothing at
the point a tool call is actually made.

### npm package(s), version, clean install

- Package: `@microsoft/agent-governance-sdk` (single TS package; the VS Code
  extension `agent-os-vscode/` is unpublished/bundled separately and not on
  npm under its own name in what was checked).
- Current published version: `5.0.0` (`npm view … dist-tags` → `latest:
  5.0.0`), published **2026-08-03** per the npm registry's `time` field.
- Repo's own `CHANGELOG.md` records `[5.0.0]` as dated **2026-06-25** — a
  ~6-week gap between the changelog date and the actual npm publish date.
  This is a source-vs-registry discrepancy worth knowing about if timing a
  workshop against "what's on npm right now."
- Installs cleanly: `npm pack @microsoft/agent-governance-sdk` succeeds;
  the published tarball contains a built `dist/` (126 files, compiled `.js`
  + `.d.ts`, no source `.ts`). Declared runtime `dependencies` on the
  **published** package.json: `@noble/ciphers@2.2.0`, `@noble/curves@2.2.0`,
  `@noble/ed25519@3.1.0`, `@noble/hashes@2.2.0`, `js-yaml@5.2.1` — note these
  pinned versions are *older* than what's in the repo's own
  `agent-governance-typescript/package.json` at the inspected commit
  (`@noble/curves@2.3.0`, `@noble/hashes@2.3.0`, `js-yaml@5.2.3`), i.e. the
  repo tip has already moved past the last npm publish.
- Ran a functional smoke test after a vendored offline install (§1):
  `new PolicyEngine([{action:'data.read', effect:'allow'}]).evaluate('data.read')`
  → `"allow"`. Works.

### Native modules in the tree

None in the published npm package's own runtime dependency tree (see above —
5 deps, all pure JS/TS, verified via `npm view <pkg> dependencies` on each:
`@noble/ciphers` 0 deps, `@noble/curves` → `@noble/hashes` only, `@noble/ed25519`
0 deps, `@noble/hashes` 0 deps, `js-yaml` → `argparse` only, `argparse` 0
deps). The repo-root `package-lock.json` (which covers the whole monorepo,
including the `agent-os-vscode/` extension's dev tooling) does list
`fsevents` and `unrs-resolver` as packages with install scripts, but these
are devDependency-side tooling (macOS filesystem watcher, ESLint/webpack
resolver), not part of what installing the published SDK package pulls in —
confirmed by the clean offline install in §1 pulling none of them in.

### Release cadence and breaking-change history (last 3 months, i.e. since ~June 2026)

From `CHANGELOG.md` (dates as recorded in the file) and the npm registry's
`time` field (actual publish dates) — these disagree in places, both are
reported:

| Version | CHANGELOG date | npm publish date (registry) |
|---|---|---|
| `5.0.0` | 2026-06-25 | 2026-08-03 |
| `4.1.0` | (not separately dated in changelog head; consolidation release) | — |
| `4.0.0` | 2026-06-01 | 2026-05-29 |
| `3.7.0` | — | 2026-05-19 |
| `3.6.0` | — | 2026-05-12 |
| `3.5.0` | — | 2026-05-08 |
| `3.4.0` | — | 2026-05-05 |
| `3.3.0` | — | 2026-04-27 |
| `3.2.2` | — | 2026-04-22 |
| `3.2.1` | 2026-04-22 | — |
| `3.2.0` | 2026-04-22 | — |

By npm publish timestamps, **8 releases landed in the ~3.5 months from
2026-04-22 to 2026-08-03** — roughly one every 1–2 weeks in April–May,
slowing to monthly for `4.0.0`→`5.0.0`. Both `4.0.0` and `5.0.0` are
explicitly marked `BREAKING` in `CHANGELOG.md` ("BREAKING: Python package
consolidation," "BREAKING: Monorepo-wide v4/v5 alignment" — the v5 bump
also widened internal cross-package version caps). As of the inspected
commit, no release has landed since `5.0.0` on 2026-08-03 (about 4 weeks
quiet as of 2026-09-01), **but** `CHANGELOG.md`'s `[Unreleased]` section
already contains a queued breaking change ("BREAKING: `acs-generator` is
CLI-only in `0.4.0b0`") and `BREAKING_CHANGES.md` lists several more
breaking changes dated `TBD` (not yet released) affecting
`TrustMiddleware`, `HostSession`, and `agt.policies` — all Python-side, but
indicative of an actively-churning monorepo that bumps TypeScript's version
number in lockstep with Python on every major ("Bumped all first-party
Python, TypeScript, .NET, and Rust packages from 4.1.0 to 5.0.0").

**Assessment (factual, not a recommendation):** given ~monthly major-version
releases with breaking changes each time from March through August 2026,
and breaking changes already queued in `[Unreleased]`, the probability of
another breaking npm release landing in the 7 weeks between now
(2026-09-01) and the workshop (2026-10-21) is high based on this cadence
history. A pin to `5.0.0` in workshop material would not automatically
break attendees' installs (pinned, not `^5.0.0` or `latest`), but "install
whatever's current" instructions given verbally or in a README without
pinning would be exposed to this risk.

### Where the audit chain is written from

Same process as the agent — there is no separate daemon or IPC boundary.
`src/audit.ts`'s `AuditLogger` is an in-memory JS class: `log()` computes
`sha256(JSON.stringify({timestamp, agentId, action, decision, previousHash,
skillAuditMetadata}))` and appends to a private in-memory array
(`this.entries: AuditEntry[]`); `verify()` walks that array checking the
hash chain with `timingSafeEqual`. There is no file/disk persistence, no
subprocess, and no network call in this file — `exportJSON()` just
serializes the current in-memory array. The `AuditEntry` shape
(`src/types.ts:470-478`) is `{timestamp, agentId, action, decision, hash,
previousHash, skillAuditMetadata?}` — no request ID, no session ID, no
argument hash field (see §4 for why this matters for correlation with
telemetry).

---

## 3. Cedar JavaScript/WASM bindings

**Canonical binding:** `@cedar-policy/cedar-wasm`, npm, currently `4.12.0`
(published 2026-07-28; package first published 2024-05-21). **Official** —
published from `cedar-policy/cedar` (the upstream Cedar monorepo, subpath
`cedar-wasm/`), maintained by `szegheon-aws`, `morevct`, `kevhak`,
`cedar-wasm-team` (all `@amazon.com` addresses per npm registry metadata).
License Apache-2.0. `npm view` reports `deps: none`. A community fork
(`tempire/cedar-wasm-js`, `tj-noor/cedar-wasm-js`) and a wrapper
(`@auto-nomos/cedar`, "wraps the official AWS Rust SDK as WASM") also turned
up in search but are not the canonical package.

### API surface, minimal case

Three build targets ship in one npm package: `esm` (default), `nodejs`
(CommonJS, uses `fs`), and `web` (manual `initSync(wasmBuffer)` — needed for
some bundler/Jest setups). Extracted from
`nodejs/cedar_wasm.d.ts` in the published `4.12.0` tarball:

```ts
export interface AuthorizationCall {
  principal: EntityUid;
  action: EntityUid;
  resource: EntityUid;
  context: Context;
  schema?: Schema;              // OPTIONAL — schema is not mandatory
  validateRequest?: boolean;
  policies: PolicySet;
  entities: Entities;
}
export type PolicySet = { staticPolicies?: StaticPolicySet; templates?: ...; templateLinks?: ... };
export type StaticPolicySet = string | Policy[] | Record<PolicyId, Policy>; // raw Cedar text is valid
export interface EntityJson { uid: EntityUidJson; attrs: Record<string, CedarValueJson>; parents: EntityUidJson[]; tags?: ...; }
export type Entities = Array<EntityJson>;                 // plain JSON array, no separate "hydration" API
export interface Response { decision: "allow" | "deny"; diagnostics: Diagnostics; }
export function isAuthorized(call: AuthorizationCall): AuthorizationAnswer;
```

**Working minimal example** (this is the literal code run as a smoke test
under the offline-vendored install from §1, on Node, via the `nodejs`
subpackage):

```js
const cedar = require('@cedar-policy/cedar-wasm/nodejs');

const policyText = `
permit(
  principal == User::"alice",
  action == Action::"view",
  resource == Photo::"vacation.jpg"
);
`;

const result = cedar.isAuthorized({
  principal: { type: 'User', id: 'alice' },
  action: { type: 'Action', id: 'view' },
  resource: { type: 'Photo', id: 'vacation.jpg' },
  context: {},
  policies: { staticPolicies: policyText },
  entities: [],
});

console.log(result);
// { type: 'success',
//   response: { decision: 'allow', diagnostics: { reason: ['policy0'], errors: [] } },
//   warnings: [] }
```

This ran successfully with no schema and no entity records at all (empty
`entities: []`), because the policy only referenced UIDs directly and
didn't need entity attributes or hierarchy.

### Does the WASM artefact vendor cleanly? (constraint 2)

Yes — see §1's method note. `npm pack` produces a 4.3 MB gzipped tarball
(13.1 MB unpacked: three copies of a 4.2 MB `.wasm`, one per build target —
`esm/`, `nodejs/`, `web/`). It is a single universal `wasm-bindgen`-built
binary per target, not per-OS prebuilds, so "platform-agnostic" per the
task's WASM carve-out holds. `npm ci --offline` from a vendored tarball
succeeded with an empty npm cache, and a subsequent `require()` +
`isAuthorized()` call worked (above).

### Boilerplate before the first policy evaluates

- **Schema:** optional (`schema?: Schema` in `AuthorizationCall`). Not
  mandatory for evaluation — confirmed by the working example above, which
  omits it entirely. A schema is only needed if you want `validateRequest`-style
  checking or schema-aware entity/attribute validation.
- **Entities:** `Entities = Array<EntityJson>`, i.e. a plain array of
  `{uid, attrs, parents}` objects — no builder API, no separate "hydration"
  step or entity-store object to construct. An empty array (`[]`) is valid
  when policies don't need entity attributes/hierarchy, as in the example.
- **Policies:** `StaticPolicySet = string | Policy[] | Record<PolicyId,
  Policy>` — a single raw Cedar policy-language string is accepted directly
  (`{ staticPolicies: policyText }`), no need to pre-parse or convert to
  JSON policy representation for the simple case.

**Assessment of the "pre-write schema/entities, attendees write only
policy" split (factual, not a recommendation):** the API supports this
split cleanly for the entity/policy boundary — `entities` and `policies`
are independent fields on one call object, so pre-populated entity JSON and
attendee-authored policy text compose without friction. Schema is a third,
fully separable, optional field; if used for validation it would be
pre-written alongside entities and would not require attendees to touch it.
The unknown here (see §5/Unknowns) is authoring ergonomics of raw Cedar
policy text itself for MCP-tool-call-shaped `context` payloads (arbitrary
JSON tool arguments as Cedar `context` attributes) — not evaluated, would
need a worked MCP-shaped example beyond this minimal case.

---

## 4. OpenTelemetry GenAI semantic conventions — MCP coverage

**Source:** `open-telemetry/semantic-conventions-genai` @
`5ca9052bc796ef1e497200b1d558fd87a201f335`.

### MCP-related span and attribute definitions (from `model/`)

Dedicated directory: `model/mcp/` (`common.yaml`, `spans.yaml`,
`registry.yaml`, `metrics.yaml`). Two spans are defined,
`model/mcp/spans.yaml`:

- **`mcp.client`** (span kind `CLIENT`) — "the MCP call from the client
  side," reported when the client initiates a request/notification, or by
  the server when it initiates an operation. Covers request→response/ack.
- **`mcp.server`** (span kind `SERVER`) — "processing of the MCP request or
  notification initiated by the peer."

Both note explicitly: *"MCP tool call execution spans are compatible with
GenAI [execute_tool spans]... If the MCP instrumentation can reliably
detect that outer GenAI instrumentation is already tracing the tool
execution, it SHOULD NOT create a separate span. Instead, it SHOULD add
MCP-specific attributes to the existing tool execution span."* — i.e. a
`tools/call` MCP request is expected to correlate with (or merge into) a
`gen_ai.execute_tool.internal` span (`model/gen-ai/spans.yaml:573-612`),
which itself carries `gen_ai.tool.call.arguments`/`gen_ai.tool.call.result`
(both `opt_in`) and `gen_ai.tool.call.id`.

**Verbatim attribute names** (from `model/mcp/registry.yaml` and
`model/mcp/common.yaml`, not paraphrased):

- `mcp.method.name` — enum of MCP JSON-RPC methods (`initialize`,
  `tools/call`, `tools/list`, `resources/read`, `prompts/get`,
  `sampling/createMessage`, `notifications/cancelled`, etc. — 24 members
  total). `requirement_level: required` on both spans.
- `mcp.session.id` — string, recommended when the request/notification is
  part of a session.
- `mcp.resource.uri` — string, conditionally required for resource-URI
  request types.
- `mcp.protocol.version` — string, e.g. `"2025-06-18"`.
- `jsonrpc.request.id` — string representation of the JSON-RPC `id`;
  conditionally required when the client executes a request. (Defined in
  the core `open-telemetry/semantic-conventions` registry, not this repo —
  this repo depends on it, see `model/manifest.yaml`.)
- `jsonrpc.protocol.version` — recommended when not `"2.0"`.
- `rpc.response.status_code` — the JSON-RPC error code as a string;
  conditionally required if the response has an error code.
- `gen_ai.operation.name`, `gen_ai.tool.name`, `gen_ai.prompt.name`,
  `gen_ai.prompt.variable` — recommended/conditionally-required, shared
  with the general GenAI conventions, populated so MCP tool-call spans
  read consistently with non-MCP tool-call spans.
- `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result` — `opt_in` on
  both MCP spans (type `any`, JSON-schema-constrained via
  `model/gen-ai/gen-ai-tool-call-arguments.json` /
  `gen-ai-tool-call-result.json`; flagged sensitive).
- `network.transport`, `network.protocol.name`, `network.protocol.version`,
  `server.address`/`server.port` (client span), `client.address`/`client.port`
  (server span) — standard network attributes, all reused from core semconv
  (all `stable`).
- `error.type` — conditionally required if the operation fails (`stable`).

### Stability level of each relevant attribute

Every MCP-specific attribute (`mcp.method.name`, `mcp.session.id`,
`mcp.resource.uri`, `mcp.protocol.version`) and every `gen_ai.*` attribute
referenced on these spans is marked `stability: development` in the model
YAML, rendered as a blue "Development" badge in the generated docs
(`docs/gen-ai/mcp.md`). The **spans themselves** (`mcp.client`, `mcp.server`)
are also `stability: development`. A handful of attributes reused from
*core* OTel semconv are stable or release-candidate:
`error.type` (stable), `network.transport`/`network.protocol.*`/`server.*`/`client.*`
(stable), `jsonrpc.*` (development), `rpc.response.status_code`
(release-candidate). No MCP-specific attribute has graduated past
`development`.

### Schema URL — is the README's "TODO" still accurate?

**No, it's stale.** The top-level `README.md` (§"Schema URL") still
literally says:
```
## Schema URL

TODO
```
But `model/manifest.yaml` (the file OTel's `weaver` tooling actually reads)
defines a concrete one:
```yaml
schema_url: https://opentelemetry.io/schemas/gen-ai-dev/1.42.0-dev
stability: development
dependencies:
  - schema_url: https://opentelemetry.io/schemas/1.44.0
    registry_path: https://github.com/open-telemetry/semantic-conventions.git@v1.44.0[model]
```
So the schema URL exists and is wired up in the machine-readable manifest;
the human-facing README prose documenting it simply hasn't been updated.
This is exactly the kind of README-vs-source drift the task asked to flag.

### npm package(s) implementing these conventions; console-exporter-only usable?

`@opentelemetry/semantic-conventions` (official, `open-telemetry/opentelemetry-js`
monorepo — a different repo from the two cloned for this task, so not
independently commit-pinned here; installed via npm at `1.43.0`, published
2026-07-09). Constants live behind an `/incubating` (a.k.a. "experimental")
entry point, since none of the `gen_ai.*`/`mcp.*` names are stable. Verified
present in the published `1.43.0` tarball
(`build/src/experimental_attributes.d.ts`):
```ts
export declare const ATTR_MCP_METHOD_NAME: "mcp.method.name";
export declare const ATTR_MCP_PROTOCOL_VERSION: "mcp.protocol.version";
export declare const ATTR_MCP_RESOURCE_URI: "mcp.resource.uri";
export declare const ATTR_MCP_SESSION_ID: "mcp.session.id";
export declare const ATTR_JSONRPC_REQUEST_ID: "jsonrpc.request.id";
export declare const ATTR_JSONRPC_PROTOCOL_VERSION: "jsonrpc.protocol.version";
```
These are just typed string constants — actual span creation/export is
handled by `@opentelemetry/api` + `@opentelemetry/sdk-trace-node` (or
`sdk-trace-base` in a browser) + `@opentelemetry/sdk-trace-base`'s
`ConsoleSpanExporter`. **Yes, usable with a console exporter only** — this
is standard OTel JS SDK behavior and requires no collector or Docker;
`ConsoleSpanExporter` is part of `@opentelemetry/sdk-trace-base` and prints
spans to stdout directly. (The semconv constant package's own `dependencies`
were checked at `deps: none`; the SDK packages' first-party-only dependency
trees were checked via `npm view … dependencies`, not independently
vendor-tested end-to-end — see the ❓ in §1's table.)

---

## 5. Join key between telemetry and signed records

Factual inventory of available identifiers, not a design proposal.

**On the OTel MCP side** (from §4), fields that could serve as a
correlation key between an `mcp.client`/`mcp.server` span (or the
associated `gen_ai.execute_tool.internal` span) and an external signed
record of the same tool call:

- `jsonrpc.request.id` — the JSON-RPC request `id`, present when the call
  is a request (not a notification). Scoped to one request/response pair
  within a session; not globally unique on its own.
- `mcp.session.id` — identifies the MCP session the call happened in.
  Combined with `jsonrpc.request.id`, gives session+request granularity.
- `gen_ai.tool.call.id` (from `model/gen-ai/registry.yaml`, referenced on
  the `execute_tool` span, not the MCP spans directly) — a tool-call-specific
  ID, `recommended: If available`.
- The OTel trace/span ID itself (not GenAI/MCP-specific — standard W3C
  Trace Context `traceparent`) is always present and is the conventional
  correlation handle in OTel-based systems generally.
- `gen_ai.tool.call.arguments` / `gen_ai.tool.call.result` — if captured
  (both `opt_in`, flagged sensitive), these carry the actual argument/result
  payload, which could be hashed and compared against a canonicalized
  signed record's hash — but OTel does not itself define or require a
  canonical serialization for this comparison to be exact-match reliable
  (see §6, issue #386 for a closely related open discussion).

**Community-recognized gap:** an open, unmerged proposal in this same repo
— issue **#132**, "Proposal: `gen_ai.threat.detection.*` attributes for
runtime threat detection on agent spans" — proposes an explicit
`agent.threat.detection.correlation_id`, described as an *"opaque
producer-defined join key for audit context held outside telemetry,"*
deliberately excluded from metric labels (unbounded cardinality). This is
independent confirmation from within the OTel GenAI community that no
existing MCP/GenAI attribute is designed to be *the* join key to an
external audit/evidence record — one would need to be minted and threaded
through explicitly (e.g. into `params._meta` per the MCP context-propagation
convention in `docs/gen-ai/mcp.md`, or as a custom span attribute).

**On the AGT audit-chain side** (from §2's reading of
`agent-governance-typescript/src/types.ts:470-478`): the TypeScript
`AuditEntry` shape is `{timestamp, agentId, action, decision, hash,
previousHash, skillAuditMetadata?}`. **None of these fields is a
request ID, session ID, or tool-call ID that would line up with
`jsonrpc.request.id` or `mcp.session.id`.** `action` is a policy-rule
action string (e.g. `"data.read"`), not a canonicalized representation of
the underlying tool call, and there is no `arguments_hash`-style field in
this TS type (the top-level `CHANGELOG.md` for `[4.0.0]` does mention
`arguments_hash`, `approver_did`, `policy_version`, `issued_at`,
`completed_at` as "expanded audit fields," but that entry is under the
general v4.0.0 "Added" section without a language qualifier, and grepping
`agent-governance-typescript/src/types.ts` for these names found nothing —
they were not confirmed present in the TypeScript `AuditEntry` type at the
inspected commit). So: no built-in join key exists between AGT's TS audit
log and OTel MCP telemetry; correlating the two would require custom
wiring on both sides.

---

## 6. OTel GenAI issue tracker search

Searched `open-telemetry/semantic-conventions-genai` issues (via web search,
not the GitHub API — this repo isn't in this session's authenticated GitHub
tool scope, and the task's own method notes prefer avoiding unauthenticated
API rate limits) for: tamper-evidence, integrity, non-repudiation, audit,
compliance, signing. No issues were opened, commented on, or filed — read
only. Three relevant hits, verified by fetching each issue page directly:

- **#386 — "Evidence origin for governance-consumed GenAI telemetry
  (self-reported vs externally attested)"** (open, filed 2026-07-19). The
  most directly relevant hit: proposes a `gen_ai.evidence.origin =
  self_reported | externally_observed` attribute so consumers can tell
  whether a span's claims are the producer's own say-so or independently
  attested. Explicitly separates **"who attests"** (an audit/vantage
  question) from **"who signs"** (an accountability question) as distinct
  concerns, and deliberately leaves the attribute unset by default rather
  than defaulting to `self_reported`, on the reasoning that "nobody said"
  differs from an explicit self-report. Does not attempt to standardize
  external-attestation formats or signing mechanisms — scoped to
  span-level metadata only. This is the closest the tracker comes to
  discussing whether spans alone are sufficient as audit evidence, and its
  answer (implicitly) is "not without an origin/provenance marker, and
  self-reporting your own span isn't attestation."
- **#132 — "Proposal: `gen_ai.threat.detection.*` attributes for runtime
  threat detection on agent spans"** (open). See §5 — proposes a
  `correlation_id` attribute as a join key to audit context held outside
  telemetry, which is itself an acknowledgment that telemetry spans are
  not treated as self-sufficient audit records within this proposal.
  Does not discuss tamper-evidence, signing, or non-repudiation directly.
- **#302 — "Enhancing OTel GenAI Semantic Conventions with a User-Centric
  Entry Span"** (open). Not actually about audit/compliance — proposes a
  user-facing "entry span" for conversation/session analytics (TTFT,
  session reconstruction). Surfaced by the search terms but contains no
  audit/integrity/signing discussion; included here for completeness/to
  show a negative result.

No issue found using these terms is specifically about tamper-evidence,
non-repudiation, or cryptographic signing of spans — #386 is adjacent
(provenance/attestation) but scoped away from signing mechanisms by its
own text. This is consistent with what §4 found in the model itself: all
MCP/GenAI attributes are `development`-stability, and the two spans
carry no attribute resembling a signature or hash-chain field.

---

## Unknowns

- **AGT `.NET` MCP gateway internals** — the README's `.NET` code sample
  (`AddMcpServer().WithGovernance(...)`) suggests a real gateway exists
  there, and `PACKAGE-FEATURE-MATRIX.md` marks `.NET` MCP Security as ✅,
  but this was not independently verified against `.NET` source (out of
  scope — the task asked about TypeScript specifically). If a workshop
  shape ever needed to compare "does any non-Python AGT language have a
  real MCP interceptor," `.NET` would need the same source-level check
  given to TypeScript here.
- **Cedar authoring ergonomics for MCP-tool-call-shaped policies** — the
  minimal `isAuthorized` example in §3 is deliberately minimal (no schema,
  no entities). Not evaluated: how clean the pre-written
  schema/entity-hydration split stays once `context` needs to carry
  arbitrary JSON tool arguments and `entities` needs to represent, say, an
  agent identity with attributes/parents — that would need a second,
  MCP-shaped worked example beyond what this pass covered.
- **Exact npm dependency count/vendor test for the full OTel tracing
  stack** (`sdk-trace-node`, `sdk-trace-base`, `resources`,
  `context-async-hooks`, `core`) — checked via `npm view … dependencies`
  only (all first-party `@opentelemetry/*`, no third-party/native deps
  visible), not run through the same offline-`npm ci` test as AGT/Cedar/
  the two packages that were vendor-tested. No reason from the dependency
  listing to expect a different result, but not independently confirmed.
- **Whether AGT's `arguments_hash`/`approver_did`/`policy_version`/
  `issued_at`/`completed_at` audit fields (mentioned in `CHANGELOG.md`
  `[4.0.0]`) exist in any language's SDK today, and if so which** — the
  changelog entry doesn't name a language, and a grep of the TypeScript
  `AuditEntry` type came up empty at the inspected commit. Not checked
  against Python/Go/Rust/`.NET` source (out of scope for this pass, but
  relevant if audit-field parity across languages ever matters).
- **`@opentelemetry/semantic-conventions`'s own commit/release
  provenance** — pinned by npm version (`1.43.0`) rather than a cloned
  commit SHA, since only two repos were cloned per the task's four named
  sources (AGT and the semconv-genai spec repo); the JS SDK implementing
  these conventions lives in a third repo
  (`open-telemetry/opentelemetry-js`) that wasn't cloned. If exact commit
  provenance for that package matters, it would need its own clone.

---

## Observations

*(Brief, separate from findings above; not a recommendation of a candidate shape.)*

- The single biggest asymmetry uncovered: AGT's TypeScript SDK is real for
  policy/identity/trust/audit-as-primitives, but has **no MCP-call
  interception** and **no embedded Cedar evaluator** — both of those only
  exist in the toolkit's Python leg (or, for interception, arguably .NET,
  unverified). A workshop built "on AGT" for MCP tool-call instrumentation
  in TypeScript would be building on the toolkit's least-covered corner
  language-wise for exactly the two capabilities (MCP interception, Cedar
  evaluation) most central to the workshop's stated topic.
- Every MCP/GenAI OTel attribute relevant to this workshop is
  `stability: development` — none has graduated. That's not necessarily
  disqualifying for a workshop (development conventions are still usable
  and are what most current instrumentation targets), but it does mean
  attribute names are subject to change without the same guarantees a
  `stable` convention would carry, and it's worth saying so explicitly to
  attendees if they're expected to build on these names afterward.
- AGT's release cadence (roughly monthly breaking major-version bumps
  through mid-2026, with more queued in `[Unreleased]`) is the more
  concrete near-term risk of the two "moving target" concerns in this
  report — more concrete than the OTel development-stability concern,
  because it's an install-time break, not just a semantic one, and the
  7-week runway to 21 October sits inside AGT's observed release interval.
