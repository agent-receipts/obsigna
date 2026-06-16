# ADR-0027: opensandbox_execd Emission Channel

## Status

Proposed — design note only. No implementation is in scope for this ADR.

## Context

### OpenSandbox as an AR integration surface

OpenSandbox (alibaba/OpenSandbox, CNCF Landscape) is a general-purpose agent
execution substrate. Agents run inside an isolated sandbox container; all
agent-initiated actions within the sandbox flow through a single in-sandbox
daemon: `execd`, a Gin HTTP service. This chokepoint property makes execd an
ideal AR instrumentation surface — full coverage, no per-tool integration work.

execd already exports OTLP metrics outside the sandbox boundary, tagged with
`OPENSANDBOX_ID`. There is no tamper-evident record of what the agent did.
Agent Receipts fills that gap.

### execd action surface

| Endpoint | Action surface | Long-lived? |
|----------|----------------|-------------|
| `POST /command` | Shell command execution | No |
| `POST /code` (SSE) | Code execution; streams stdout/stderr until close | Yes (stream) |
| `GET/POST/PUT/DELETE /files` | File read, create, write, delete | No |
| `GET/POST /directories` | Directory list, create | No |
| `POST /pty` | PTY session (interactive, long-running) | Yes (session) |

Every observable agent action inside the sandbox passes through one of these
five endpoints.

### OTLP is not sufficient

execd already emits OTLP metrics from an internal post-action hook. OTLP covers
the same actions — but OTLP is sampled, lossy, and produces metric aggregates,
not a complete ordered record of each individual action. Agent Receipts requires:

- **Completeness.** Every action, not a sampled subset.
- **Ordering.** Hash-chained receipts with monotonic sequence numbers.
- **Tamper-evidence.** Ed25519 signature over the canonical receipt.

The AR emission path uses a separate transport from OTLP. OTLP observes actions
through execd's internal hook; AR observes the same actions by intercepting the
HTTP traffic at the proxy layer (see §In-sandbox AR proxy). They share no
state, transport, or delivery contract.

### Signing-key boundary

The Ed25519 signing key MUST NOT reside inside the sandbox. The sandbox is an
arbitrary-code environment for the agent; a key-in-sandbox is the CI-guide
colocation antipattern — signing from within the environment being audited.
The in-sandbox side is a keyless thin emitter: it serializes an unsigned event
frame and delivers it outbound to the host-side AR daemon. The daemon holds the
Ed25519 key, canonicalizes, signs, chains, and persists. This extends the
ADR-0010 daemon/emitter split across the sandbox/host boundary.

## Locked decisions

The following are fixed for this design note and must not be relitigated in
implementation issues:

1. **Key stays host-side.** The in-sandbox proxy is keyless. The AR daemon on
   the host holds the Ed25519 key and produces all signatures.
2. **Two placement points, threat-model-mapped.** See §Placement table.
   Both are defined; deployments select based on their threat model.
3. **No new receipt format.** `opensandbox_execd` uses HttpEmitter as the
   outbound transport. The W3C VC envelope is unchanged.
4. **Separate transport from OTLP.** AR events use their own delivery path to
   the host daemon and share nothing with the OTLP exporter or its delivery
   contract.
5. **`OPENSANDBOX_ID` is the subject/binding field.** It appears in the
   receipt's `credentialSubject.binding.sandbox_id`, establishing the
   per-sandbox sub-chain. The `credentialSubject.binding` object is a proposed
   schema extension not yet present in the current spec; formalising it is
   follow-up item 3 (see §Spawned follow-up work).
6. **`/code` SSE receipts emit at stream close.** The event is canonicalized
   over `(code_hash, language, result_hash, logs_hash)` once the stream
   finishes, within execd's graceful-shutdown tail-drain window.

## Decision

### Channel value

`channel: "opensandbox_execd"`

The channel discriminator carries the trust statement: "this receipt was
observed by the AR proxy inside an OpenSandbox sandbox; signing, chaining, and
storage happen host-side in the AR daemon." Verifiers reading the channel value
can look up this ADR's coverage envelope and apply the appropriate trust
calculus.

### Placement table

Two placement points are defined. They are complementary, not alternatives.
Placement A is the default and provides maximum action coverage under
honest-operator assumptions. Placement B is an optional add-on that provides
adversary-resistant coverage for boundary-crossing traffic.

| Property | Placement A — execd-side | Placement B — ingress/egress |
|---|---|---|
| **Where** | Inside the sandbox: a thin AR proxy binary interposes between the agent and execd, requiring no execd source changes | Host-side network boundary (iptables/nftables hook, veth intercept, or CNI plugin) |
| **Covers** | All five execd endpoints | Boundary-crossing network actions only (outbound HTTP/S, DNS) initiated from `/command`, `/code`, and PTY sessions |
| **Recommended for** | Default; Wedge-C deployments proving to downstream consumers | High-assurance deployments where the agent may be adversarial; supplements Placement A |

**Threat-model mapping:**

| Threat | Placement A | Placement B |
|---|---|---|
| Agent lies about action parameters passed to execd | Not defended | Not defended |
| Operator modifies a receipt after signing | Defended | Defended |
| Legitimate operator suppresses receipts before the host daemon receives them | Not defended | Defended for network-crossing actions |
| Fully-compromised sandbox (sandbox root) suppresses emit | Not defended | Defended for network-crossing actions |
| Agent exfiltrates data over the network via execd | Defended — /command `curl` etc. produce a receipt | Defended |
| Agent reads the AR signing key | Defended — key never enters the sandbox | Defended |

The primary adversary Placement A defends against is an operator who controls
the host and sandbox configuration but cannot alter the receipt chain after it
is signed by the host daemon. Placement B adds adversary-resistant coverage for
network-crossing actions where even a compromised sandbox cannot suppress the
host network stack's observation.

### Action type mapping

execd endpoints map to existing AR taxonomy types where a match exists; new
types are proposed where none does. New types follow the established three-part
dotted pattern (`domain.subdomain.action`). Proposed new types require a
taxonomy amendment in the implementation PR.

#### `/command` → `system.command.execute`

Existing type. Risk: `high`.

| Receipt field | Content |
|---|---|
| `action.type` | `system.command.execute` |
| `parameters_hash` | SHA-256 of canonical `{"command":<string>,"env":<map>?}` |
| `response_hash` | SHA-256 of canonical `{"exit_code":<int>}` |
| `drop_count` | Accumulated drop count (omitted when zero; see §Drop-counter handling) |
| `binding.sandbox_id` | `OPENSANDBOX_ID` env var |
| `binding.endpoint` | `"/command"` |

#### `/code` → `system.code.execute` *(new type, risk: `high`)*

SSE endpoint. The proxy emits one receipt after the stream closes (or after
execd's graceful-shutdown tail-drain window expires). If the sandbox is
force-terminated before the window expires, the receipt is lost; verifiers
treat the resulting gap as a missing single receipt, not as a tool-call/result
pair — see ADR-0020 §"At-least-once delivery and the WAL" for the authoritative
gap-classification guidance.

| Receipt field | Content |
|---|---|
| `action.type` | `system.code.execute` |
| `parameters_hash` | SHA-256 of canonical `{"code_hash":<sha256>,"language":<string>}` |
| `response_hash` | SHA-256 of canonical `{"result_hash":<sha256>,"logs_hash":<sha256>}` |
| `drop_count` | Accumulated drop count (omitted when zero) |
| `binding.sandbox_id` | `OPENSANDBOX_ID` |
| `binding.endpoint` | `"/code"` |

`code_hash` is SHA-256 of the submitted code text. `result_hash` and
`logs_hash` are SHA-256 of the accumulated SSE result and log streams
respectively. Raw code and outputs never appear in the receipt.

#### `/files` → `filesystem.file.*`

HTTP method determines the subtype. All four subtypes are existing taxonomy
types.

| HTTP method | `action.type` | Risk |
|---|---|---|
| `GET` | `filesystem.file.read` | `low` |
| `POST` | `filesystem.file.create` | `low` |
| `PUT` | `filesystem.file.modify` | `medium` |
| `DELETE` | `filesystem.file.delete` | `high` |

| Receipt field | Content |
|---|---|
| `parameters_hash` | SHA-256 of canonical `{"path":<string>}` (read/delete) or `{"path":<string>,"content_hash":<sha256>}` (create/modify) |
| `response_hash` | SHA-256 of canonical `{"content_hash":<sha256>}` (read) or `{"bytes_written":<int>}` (create/modify) or `{}` (delete) |
| `drop_count` | Accumulated drop count (omitted when zero) |
| `binding.sandbox_id` | `OPENSANDBOX_ID` |
| `binding.endpoint` | `"/files"` |

#### `/directories` → `filesystem.directory.*`

`filesystem.directory.create` exists. `filesystem.directory.list` is new
(risk: `low`).

| HTTP method | `action.type` | Risk |
|---|---|---|
| `GET` | `filesystem.directory.list` *(new)* | `low` |
| `POST` | `filesystem.directory.create` | `low` |

| Receipt field | Content |
|---|---|
| `parameters_hash` | SHA-256 of canonical `{"path":<string>}` |
| `response_hash` | SHA-256 of canonical `{"entries_hash":<sha256>}` (list) or `{}` (create) |
| `drop_count` | Accumulated drop count (omitted when zero) |
| `binding.sandbox_id` | `OPENSANDBOX_ID` |
| `binding.endpoint` | `"/directories"` |

#### `/pty` → `system.pty.open` / `system.pty.close` *(both new, risk: `critical`)*

PTY sessions are long-running and have no predictable end time. A single receipt
at session end would suppress evidence of a session running for hours. Two
receipts are emitted per PTY session:

1. **`system.pty.open`** — emitted when the PTY is established.
2. **`system.pty.close`** — emitted when the PTY closes (SIGHUP, client
   disconnect, or timeout). Linked to the open receipt via a `correlator` field.

**Correlator naming:** The field is named `tool_use_id` in ADR-0013 and
ADR-0014 because it links tool-invocation Pre/Post pairs. PTY open/close are
session-scope events, not tool invocations — using `tool_use_id` here would be
a misnomer. The more generic name `correlator` is used instead. The semantics
are identical: a per-session UUID generated on open, repeated on close, used by
the daemon and verifiers to pair the two receipts.

**Schema status:** `correlator` is not present in the current receipt schema or
daemon IPC frame (the only similar existing field, `action.idempotency_key`, has
retry semantics and is unsuitable here). Adding `correlator` requires a spec
schema update, SDK changes, and a daemon IPC frame amendment; this is captured
as follow-up item 6 (implementation PR).

A `pty.open` without a corresponding `pty.close` (abnormal termination, OOM
kill, sandbox force-stop) is classified as **`incomplete_session`**: a verifier
classification for session-scope open/close pairs where the close receipt is
absent. `incomplete_session` is to PTY pairs what `incomplete_tool_roundtrip`
(ADR-0020) is to tool-call pairs — it signals an attested start with no
attested end, not a hash-chain corruption. This classification does not yet
exist in the verifier framework; formalizing it is follow-up item 4.

| Receipt field | `system.pty.open` | `system.pty.close` |
|---|---|---|
| `parameters_hash` | SHA-256 of canonical `{"command":<string>,"env":<map>?}` | SHA-256 of canonical `{"exit_code":<int>,"signal":<string>?}` |
| `response_hash` | SHA-256 of canonical `{"pty_id":<string>}` | SHA-256 of canonical `{"io_hash":<sha256>}` |
| `correlator` | Generated per-session UUID | Same UUID |
| `drop_count` | Accumulated drop count (omitted when zero) | Accumulated drop count (omitted when zero) |
| `binding.sandbox_id` | `OPENSANDBOX_ID` | `OPENSANDBOX_ID` |
| `binding.endpoint` | `"/pty"` | `"/pty"` |

`io_hash` is SHA-256 of the accumulated PTY I/O stream. Raw I/O is not
persisted. The `exit_code` and optional `signal` in `pty.close` describe why
the session ended; these are the action's meaningful close parameters.

#### Placement B — `network.egress.observed` *(new type, risk: `medium`)*

Placement B receipts are emitted by the host-side network interceptor, not by
the in-sandbox proxy. They cover outbound network connections crossing the
sandbox boundary. Because the interceptor operates below the HTTP application
layer, it observes connection-level metadata rather than execd endpoint
semantics.

| Receipt field | Content |
|---|---|
| `action.type` | `network.egress.observed` *(new)* |
| `parameters_hash` | SHA-256 of canonical `{"dst_addr":<string>,"dst_port":<int>,"protocol":<string>}` |
| `response_hash` | SHA-256 of canonical `{"bytes_out":<int>,"verdict":<string>}` where `verdict` is `"allowed"` or `"blocked"` |
| `drop_count` | Accumulated drop count (omitted when zero) |
| `binding.sandbox_id` | `OPENSANDBOX_ID` |
| `binding.placement` | `"ingress_egress"` |

The `dst_addr` is the resolved IP; `protocol` is `tcp` or `udp`. The emitter
is the host interceptor, not the sandbox proxy. `OPENSANDBOX_ID` is extracted
from the network namespace or cgroup label attached to the connection by the
orchestrator at sandbox creation time.

### `OPENSANDBOX_ID` as sub-chain scope

`OPENSANDBOX_ID` is injected by the sandbox orchestrator into the execd process
environment before execd starts. The agent cannot set or alter it.

In receipts, it appears as `credentialSubject.binding.sandbox_id`. It
establishes the sub-chain scope: all receipts from within a single sandbox
instance share the same `sandbox_id` and are sequenced together into a
sub-chain.

### Per-sandbox sub-chain anchored to the global chain

Receipts from within a single sandbox form a **sub-chain**: each receipt links
to its predecessor within that sandbox via `previousReceiptHash`. The sub-chain
is independently verifiable — its internal hash linkage and signatures are
self-contained.

The sub-chain's first receipt SHOULD carry a `parentChainRef` field pointing to
the current tip of the host daemon's global chain at the moment the sub-chain is
initialized (i.e., when the first event for a new `OPENSANDBOX_ID` arrives at
the daemon). This anchoring provides:

1. **Global temporal ordering.** Sandbox `sid-abc` started "after global receipt
   N." Multiple concurrent sandboxes are ordered relative to each other via
   their anchor points in the global chain.
2. **Sub-chain completeness.** All events within `sid-abc` form a contiguous
   hash-linked sequence; a sequence gap within the sub-chain is a verification
   failure (per ADR-0019 P5).
3. **Cross-sandbox correlation.** Verifiers can locate a sandbox's sub-chain in
   the global sequence, enabling session-level audit scoping without scanning
   the entire chain.

Sub-chains without `parentChainRef` lose the temporal ordering property across
sandboxes. Anchoring is strongly preferred; it becomes required once
`parentChainRef` is defined in the daemon IPC contract (follow-up item 3). Until
then, sub-chains remain independently verifiable and the global ordering
property is aspirational.

**Replication note.** In a replicated daemon deployment (future work per
ADR-0022), `parentChainRef` MUST be resolved against the current primary
replica at sub-chain initialization time to avoid anchor ambiguity. This is a
daemon-side concern not resolved in this ADR.

### In-sandbox AR proxy

Placement A's emit hook is implemented as a **thin in-sandbox AR proxy** — a
small long-lived Go binary that interposes between the agent and execd. No execd
source changes are required.

**Deployment:** The orchestrator starts the AR proxy alongside execd in the
sandbox. The agent is directed to the AR proxy's port; the proxy forwards each
request verbatim to execd's port. On receiving execd's response, the proxy
returns it to the agent and emits an unsigned AR event frame to the host relay
in a non-blocking goroutine before or after the response flush (depending on
whether the response is streaming — see §SSE and PTY handling below).

**Relation to OTLP:** The AR proxy intercepts at the HTTP transport layer;
OTLP is emitted from an internal execd callback. They observe the same actions
at different instrumentation points and use separate transports.

**SSE and PTY handling:**
- `/code` (SSE): the proxy streams the response through to the agent, accumulates
  output hashes, and fires the AR emit after the stream closes or execd's
  graceful-shutdown tail-drain window expires.
- `/pty`: the proxy emits `system.pty.open` when the connection is established
  and `system.pty.close` when it terminates, accumulating the I/O hash during
  the session.

### Drop-counter handling

The in-sandbox AR proxy is a long-lived process. It uses the in-memory drop
counter specified in ADR-0010: on every transport failure (connection refused,
TLS handshake failure, write deadline exceeded), the proxy increments an
in-memory counter rather than silently swallowing the failure. On the next
successful send, the counter is included as `drop_count` in the IPC frame;
the daemon synthesizes an `events_dropped` receipt into the chain exactly as
ADR-0010 specifies.

Per ADR-0025, the transport failure MUST be surfaced through the proxy's Go
error channel (a non-nil error return from the emit goroutine). The error is
recorded by incrementing the drop counter. The agent's action response is not
withheld — the action completed before the emit goroutine fires. This is the
`fire-and-forget` delivery strategy from ADR-0020: the proxy does not wait for
downstream acknowledgement, but a failed `connect()` or write is known
synchronously and is counted, not swallowed. The drop counter is the ADR-0010
surface mechanism for this channel; it makes every gap visible in the chain
once connectivity is restored.

### Transport: in-sandbox proxy → host relay → daemon

The in-sandbox AR proxy cannot reach the AR daemon's Unix socket directly (the
socket is on the host, not inside the sandbox). The outbound path uses a
two-hop design that requires no changes to the existing daemon:

1. **In-sandbox proxy → host relay (HTTPS, mTLS).** The proxy POSTs unsigned
   AR event frames to a designated host address over mTLS. The sandbox network
   namespace permits outbound connectivity to this address. The proxy presents a
   per-sandbox-instance TLS client certificate provisioned by the orchestrator.

2. **Host relay → AR daemon (AF_UNIX).** The host relay is a small new binary
   that validates the mTLS client certificate, extracts the `OPENSANDBOX_ID`
   from the certificate subject or SAN, and forwards the unsigned frame to the
   AR daemon's existing Unix socket — the same IPC path all other emitters use.
   The daemon performs `SO_PEERCRED` peer-attestation on the relay binary, not
   on the in-sandbox proxy.

The relay is a new host-side component; its detailed design (certificate
validation policy, AF_UNIX socket wiring, process identity) is follow-up
item 5. The daemon requires no modifications: it receives unsigned frames on
its Unix socket as it does today.

**On failure.** If the proxy cannot reach the host relay, the transport failure
is captured by the proxy's Go error channel (non-nil error return) and
increments the drop counter (see §Drop-counter handling). The agent's action
response is not affected.

### Trust model

This channel uses a two-hop attestation chain distinct from the Unix-socket
peer-credential model of other channels:

1. **Sandbox identity.** The mTLS client certificate presented by the in-sandbox
   proxy asserts the sandbox's identity (`OPENSANDBOX_ID` in the subject or SAN).
   The certificate is provisioned by the orchestrator before the sandbox starts;
   the agent cannot alter it.

2. **Host relay identity.** The AR daemon peer-attests the host relay binary via
   `SO_PEERCRED` on the Unix socket. The receipt's `peer` object records the
   relay's PID, UID, and executable path — not the in-sandbox proxy's identity.

3. **Sandbox binding.** The relay extracts `OPENSANDBOX_ID` from the validated
   client certificate and includes it in the forwarded frame. The daemon records
   it as `binding.sandbox_id` in the signed receipt. An attacker who forges the
   mTLS certificate could impersonate a different sandbox, but cannot impersonate
   the relay binary's process identity or reach the daemon without going through
   the relay.

**Implication for certificate provisioning:** If multiple sandboxes share a
single mTLS certificate, `binding.sandbox_id` cannot be trusted to
discriminate between them. Certificate provisioning MUST be per-sandbox-instance
(follow-up item 1).

### Sequence diagram

```
Agent (inside sandbox)
  │
  │  HTTP action request
  ▼
AR proxy (inside sandbox, thin Go binary)
  │  Forward request to execd
  ▼
execd (inside sandbox, Gin HTTP daemon)
  │
  ├─► [OTLP hook] ──────────────► OTLP collector
  │      (existing, internal)        sampled, aggregated, lossy
  │
  │  HTTP response
  ▼
AR proxy (captures request + response, hashes payloads)
  │
  │  Serialize unsigned AR event frame
  │  (OPENSANDBOX_ID bound; no key material)
  │
  │  POST /ingest (mTLS outbound)
  ▼
Host relay (host-side, validates mTLS cert)
  │
  │  Forward unsigned frame (AF_UNIX)
  ▼
AR daemon (host-side)
  │
  ├─ Peer-attest relay binary (SO_PEERCRED)
  ├─ Canonicalize (RFC 8785, ADR-0002)
  ├─ Hash parameters + response (ADR-0008)
  ├─ Sign (Ed25519, ADR-0001)
  ├─ Chain (prev_hash, sub-chain scoped by sandbox_id)
  ├─ Persist (SQLite, ADR-0004)
  │
  └─► External anchor (ADR-0015, optional)
           rotation events + checkpoint hashes
```

The agent never communicates with the AR daemon or the host relay. The signing
key is unreachable from inside the sandbox.

### Machine-readable coverage metadata

Each `opensandbox_execd` receipt carries a `coverage` block in the signed event
body. The daemon canonicalizes and signs it alongside the rest of the event, so
the coverage claim is attested.

This channel's coverage block intentionally diverges from ADR-0014's schema
on three fields. ADR-0014 introduced `enforcement` (advisory/primary, mapping
Codex's hook-vs-kernel distinction) and `sandbox` (seatbelt/landlock_seccomp,
mapping Codex's OS-level sandbox type). Neither concept applies here: the AR
proxy observes all execd traffic uniformly, and OpenSandbox's sandbox type is
not relevant to the AR coverage claim. The `placement` field is new and specific
to this channel, distinguishing the two complementary interception points.

| Field | Type | Placement A | Placement B |
|---|---|---|---|
| `covers` | array of strings | `["command","code","files","directories","pty"]` | `["network_egress"]` |
| `excludes` | array of strings | `[]` | `["command","code","files","directories","pty"]` |
| `placement` | string | `"execd"` | `"ingress_egress"` |
| `opensandbox_version` | string | running version | running version |

The `coverage` block is emitter-asserted and not validated against ground truth
by the daemon. The daemon attests who sent the claim and that it has not been
tampered with post-signing, but cannot verify whether the proxy actually covered
the stated surface on this host. Trust in the coverage claim is bounded by trust
in the binary that produced it — the same caveat as ADR-0014.

### Non-goals confirmed

- No execd fork. The AR proxy is a separate binary placed in front of execd;
  execd's source is not modified.
- No OpenClaw-specific implementation. OpenClaw is the test bed; this design is
  substrate-agnostic.
- No OSEP authoring. If upstreaming a native emit hook point proves valuable, a
  separate OSEP follow-up may be warranted; this ADR makes no upstream claim.
- No production deployment.
- No dependency on #487, #480, or #533.

## Consequences

### Easier

- OpenSandbox deployments gain a tamper-evident record of all in-sandbox agent
  actions at the single chokepoint without forking execd or modifying any
  existing AR component.
- The existing AR daemon, its Unix socket interface, HttpEmitter (`mtls`
  strategy), and VC envelope are reused unchanged. No new receipt format, no new
  signing algorithm.
- Per-sandbox sub-chains scope audit evidence to individual sandbox runs;
  auditors reconstruct what happened in `sid-abc` without parsing the entire
  global chain.
- Placement B provides adversary-resistant receipts for boundary-crossing
  traffic — a property no existing channel offers.

### More difficult / costs

- **Placement A trust is honest-operator only.** A fully-compromised sandbox
  (sandbox root) can suppress or manipulate the AR proxy before events reach
  the host relay. This is the same "lying client" threat as `mcp_proxy` and
  `claude_code_hook`.
- **New host relay component required.** The relay binary (host-side, bridges
  mTLS to the daemon's Unix socket) does not exist yet. Its design is follow-up
  item 5; the channel cannot be implemented without it.
- **mTLS certificate lifecycle.** Each sandbox instance needs its own client
  certificate. Provisioning, rotation, and revocation for ephemeral sandboxes
  is deferred to follow-up item 1. Shared certificates weaken the sandbox-level
  trust property.
- **`/code` tail-drain timing.** If the sandbox is force-terminated before
  execd's graceful-shutdown window completes, the `/code` receipt is lost. The
  AR proxy's SIGTERM handler must cooperate with execd's drain window.
- **PTY open-without-close.** Abnormally terminated PTY sessions leave a
  `system.pty.open` receipt without a corresponding `system.pty.close`.
  Verifiers MUST classify this as `incomplete_session` once follow-up item 4
  formalizes the classification.
- **Taxonomy extensions required.** Four new action types
  (`system.code.execute`, `system.pty.open`, `system.pty.close`,
  `network.egress.observed`) and one new filesystem type
  (`filesystem.directory.list`) must be added to the taxonomy in the
  implementation PR.
- **`parentChainRef` field** is not yet defined in the daemon IPC contract.
  Sub-chain global anchoring (SHOULD) is aspirational until follow-up item 3
  lands.

### Spawned follow-up work

1. [ ] Certificate provisioning strategy for per-sandbox-instance mTLS — separate
       design note; required before Placement A can be deployed securely.
2. [ ] Add `filesystem.directory.list`, `system.code.execute`,
       `system.pty.open`, `system.pty.close`, `network.egress.observed` to the
       taxonomy (`sdk/go/taxonomy/taxonomy.go` and the embedded taxonomy JSON in
       mcp-proxy).
3. [ ] Define `parentChainRef` in the daemon IPC contract; amend ADR-0010 or
       issue a targeted daemon-IPC ADR to formalize sub-chain anchoring.
4. [ ] Verifier: define and implement `incomplete_session` classification for
       `pty.open` without `pty.close`; update verifier docs to reference this
       ADR as the defining source.
5. [ ] Design and implement the host relay binary: mTLS inbound, AF_UNIX
       outbound to the AR daemon socket, `OPENSANDBOX_ID` extraction from the
       client certificate.
6. [ ] Implementation: in-sandbox AR proxy (Go, intercepts agent→execd traffic,
       wires HttpEmitter `mtls` strategy for outbound to host relay).
7. [ ] Consider upstreaming a native emit hook point to OpenSandbox if adoption
       warrants it — separate OSEP follow-up.

## Related ADRs

- [ADR-0010 (Daemon Process Separation)](./0010-daemon-process-separation.md) —
  defines the thin-emitter/daemon split, drop-counter mechanism, and Unix socket
  IPC contract the host relay bridges into for this channel.
- [ADR-0013 (`claude_code_hook`)](./0013-claude-code-hook-channel.md) — peer
  channel; establishes the `tool_use_id` correlator pattern from which PTY
  pairing's `correlator` field draws its semantics.
- [ADR-0014 (`codex_hook`)](./0014-codex-hook-channel.md) — peer channel;
  originator of the per-receipt `coverage` block concept; this ADR's schema
  intentionally diverges on three fields (see §Machine-readable coverage metadata).
- [ADR-0019 (Protocol Integrity Gaps)](./0019-protocol-integrity-gaps-and-mitigations.md) —
  P5 sequence-gap enforcement applies to sub-chain completeness.
- [ADR-0020 (Emitter Abstraction)](./0020-emitter-abstraction-and-remote-receipt-delivery.md) —
  HttpEmitter with `mtls` auth strategy is the proxy's outbound transport;
  `fire-and-forget` strategy semantics govern emit-failure handling; gap
  classification guidance for missing single receipts.
- [ADR-0025 (Emit Failure Contract)](./0025-emit-failure-contract.md) — emit
  failures MUST be surfaced through the proxy's Go error channel and tracked via
  the drop counter; this ADR inherits that requirement.
