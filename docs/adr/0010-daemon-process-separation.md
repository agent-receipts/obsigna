# ADR-0010: Daemon Process Separation for Signing and Storage

## Status

Accepted (2026-05-03), amended 2026-05-05 and 2026-05-06 (see *Amendments*)

## Implementation status

Phase 1 lands the standalone daemon, peer-credential capture, the file-backed `KeySource`, and the `GetChainTail` store primitive. Emitter refactor (mcp-proxy, OpenClaw, three SDKs), packaging (Homebrew / launchd / systemd), and the Windows port follow in subsequent phases tracked under [issue #236](https://github.com/agent-receipts/obsigna/issues/236).

## Context

The current architecture runs the agent-receipts plugin/SDK in-process with the agent. This means the agent process owns the Ed25519 signing keys and has read/write access to the SQLite receipts database. An agent auditing itself is not a meaningful audit: a compromised or misbehaving agent can forge, suppress, or tamper with its own receipts. This undermines the core value proposition of tamper-evident receipts.

A secondary problem: every emitter (each MCP proxy instance, each OpenClaw-using agent, each SDK consumer) currently carries its own copy of the keypair in memory, its own SQLite connection and WAL, its own RFC 8785 canonicalizer, and its own hash-chain state. Running multiple MCP proxies plus an agent session means N independent crypto/storage stacks doing the same job, with N separate chains that share no sequence space — making cross-channel correlation a query-time problem rather than a structural property.

## Decision

Split every integration into two roles:

1. **Thin emitter** — the plugin, proxy, or SDK fires an event describing the tool call. No signing, no storage, no crypto. Fire-and-forget over a local IPC socket. The agent must never block waiting for the audit layer. Two failure modes are distinguished, with deliberately different visibility properties:
   - **Daemon not running** (connect fails or is refused): events truly drop silently. There is no daemon to record the gap, by definition. Operators detect this via the absence of fresh receipts and via service-manager status, not via in-chain signal.
   - **Daemon running but backpressured** (`EAGAIN` on a non-blocking send): drops are tracked and surface in the chain via the `events_dropped` mechanism described under *Permissions and trust* below.

2. **agent-receipts daemon** — a separate process running as its own OS user, sole owner of the signing keys and the SQLite database. Receives events, captures peer credentials, canonicalizes (RFC 8785), hash-chains, signs (Ed25519), and persists.

### IPC transport

- Linux: Unix domain socket (`SOCK_STREAM` with 4-byte big-endian length-prefix framing). Default `$XDG_RUNTIME_DIR/agentreceipts/events.sock` (per-user, when the variable is set), falling back to `/run/agentreceipts/events.sock` (system-wide; requires privileged directory setup).
- macOS: Unix domain socket (`SOCK_STREAM` with 4-byte big-endian length-prefix framing). Default `$XDG_DATA_HOME/agent-receipts/events.sock` (per-user; `XDG_DATA_HOME` defaults to `~/.local/share`). HOME-based instead of the launchd per-user temp dir: TMPDIR is not inherited by every spawn context — GUI-launched MCP servers typically see no TMPDIR and drift to `/tmp` while the daemon keeps the per-user path, causing a silent receipt-loss mismatch (issue #545). The launchd-managed system install will select an alternative path explicitly via `AGENTRECEIPTS_SOCKET` once packaging lands.
- Windows: named pipe via Node's `net` module (`\\.\pipe\agentreceipts-events`) with equivalent ACL semantics.
- Socket and pipe locations are configurable via the `AGENTRECEIPTS_SOCKET` environment variable (Linux/macOS) or the equivalent on Windows.
- TCP loopback is explicitly rejected — it dissolves the filesystem permission model and would require a bespoke local auth scheme.
- `SOCK_STREAM` with length-prefix framing is chosen over `SOCK_DGRAM` because peer credentials on datagram sockets either lack a defined OS-level mechanism or require per-message ancillary data with platform-specific gaps. `SOCK_SEQPACKET` would have been the natural choice — discrete messages without explicit framing — but macOS `AF_UNIX` does not implement `SOCK_SEQPACKET`, and macOS is in MVP scope. Peer-credential capture (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` + `LOCAL_PEEREPID` on macOS) is tied to the connected socket rather than to message boundaries, so it works identically on stream sockets — the trust-model properties described under *Permissions and trust* hold unchanged.

### Permissions and trust

- Daemon is the sole writer to the database and key store.
- Emitters cannot read the database or keys.
- Daemon captures peer credentials at connection-accept time, using the connected-socket primitive native to each platform:
  - Linux: `SO_PEERCRED` for `uid`, `gid`, `pid`.
  - macOS: `LOCAL_PEERCRED` for `uid` and `gid`; `LOCAL_PEEREPID` for `pid`.
  - Windows: `GetNamedPipeClientProcessId` for `pid`; `OpenProcessToken` to extract the user SID and integrity level.
  The executable path is read from `/proc/<pid>/exe` (Linux), `proc_pidpath` (macOS), or `QueryFullProcessImageName` (Windows). The agent's self-asserted identity is untrusted; peer attestation is what makes the audit meaningful.
- Connection is non-blocking. When the daemon's per-connection receive buffer is full, the emitter's send returns `EAGAIN`; the emitter increments a local drop counter rather than blocking, and flushes the counter alongside its next successful event. The daemon records the gap as a synthesised `events_dropped` receipt in the chain so dropped events are never invisible. (One narrow loss window remains — the emitter crashing after dropping but before flushing — and is documented as such.)

### Schema split

Emitter sends the minimum faithful representation:

- `v` (schema version)
- `ts_emit` (RFC 3339, advisory)
- `session_id` (opaque string; UUID v4 recommended when emitter-generated; persists for emitter-instance lifetime; detailed allocation rule in the *Amendments* section, OQ4)
- `channel` (`openclaw` | `mcp_proxy` | `sdk` | ...)
- `tool` (`{ server, name }` for MCP; equivalent shape for other channels)
- `input`, `output`, `error` (raw, no normalisation)
- `decision` (`allowed` | `denied` | `pending`)

Daemon adds before signing:

- `seq`, `prev_hash`, `ts_recv` (authoritative)
- `peer` — platform-tagged identity object. Common across all platforms: `platform` (`linux` | `darwin` | `windows`), `pid`, `exe_path`. POSIX (`linux`, `darwin`) additionally carries `uid`, `gid`. Windows additionally carries `user_sid` and `integrity_level`. The `platform` discriminator is authoritative for which identity fields are present; verifiers MUST NOT collapse Windows SIDs into numeric uids.
- `id` (receipt UUID)

Canonicalization happens only in the daemon. Pre-canonicalizing in N emitters in N languages would silently break verification.

### Read interface

Filesystem-first, journald-style. The daemon owns writes and keys exclusively; reads happen via direct SQLite access with filesystem permissions:

- DB: `0640`, owner `agentreceipts`, group `agentreceipts-read`
- Public key: `0644`, world-readable
- The `agent-receipts verify` CLI reads the DB and public key directly and works when the daemon is down. The daemon is the only thing that can write, never the only thing that can read — independent verifiability is the property signing exists to provide.

A future read socket for live-tail (`agent-receipts tail -f`) is in scope but not part of this ADR.

## Consequences

### Positive

- Restores the audit property: an agent cannot forge, suppress, or tamper with its own receipts.
- Single chain across all channels (OpenClaw, MCP proxy, SDK) with monotonic `seq` and `session_id` grouping — directly addresses the unified cross-channel audit gap identified in the agent security landscape.
- Memory footprint per emitter drops to near-nothing (no keypair, no SQLite, no canonicalizer in-process). Multiple MCP proxies plus an agent session share one daemon.
- Faster emitter startup, especially for short-lived SDK consumers that currently pay the SQLite-open cost per run.
- Single canonicalizer eliminates a class of cross-language verification bugs.
- Simpler verification: one DB, one chain, one public key.
- Capability separation matches the trust model that mature projects in this space (e.g. Pipelock) use as a selling point.

### Negative / tradeoffs

- Adds an installable system service. Packaging story required: Homebrew formula, `.deb`/`.rpm` with systemd unit, launchd plist, Windows Service installer. This is friction the current `npm install` story does not have.
- Hard cutover for emitters. v1 in-process behaviour is deprecated and removed rather than left available, because shipping the "agent signs its own receipts" footgun under the agent-receipts name is worse than a major version bump. `@agnt-rcpt/openclaw` and the MCP proxy each become v2 with the daemon as a runtime requirement.
- The MCP proxy gains a two-layer attestation model (proxy attests in the event body to the connecting agent's PID/UID; daemon attests via peer creds to the proxy itself). Both are recorded; verifiers see both.
- Operators must run and supervise the daemon. Mitigated by standard service-manager integration on each platform.

## Related ADRs

- [ADR-0001 (Ed25519 signing)](./0001-ed25519-for-receipt-signing.md) — unchanged, but the key now lives only in the daemon.
- [ADR-0002 (RFC 8785 canonicalization)](./0002-rfc8785-json-canonicalization.md) — moves exclusively to the daemon.
- [ADR-0004 (SQLite storage)](./0004-sqlite-for-local-receipt-storage.md) — daemon is sole writer; readers use filesystem permissions.

## Amendments

### 2026-05-05: IPC framing — `SOCK_STREAM` with length-prefix framing instead of `SOCK_SEQPACKET`

Phase 1 (#322) implemented `SOCK_STREAM` with a 4-byte big-endian length-prefix frame in place of the originally-specified `SOCK_SEQPACKET`, because macOS `AF_UNIX` does not implement `SOCK_SEQPACKET`. The *IPC transport* section above describes the current wire format and reasoning; this entry records the deviation history.

### 2026-05-05: Default socket paths — per-user defaults instead of system paths

Phase 1 (#322) defaults to per-user socket paths because MVP has no launchd- or systemd-managed system install yet. macOS originally used `$TMPDIR/agentreceipts/events.sock` (the originally-specified `/var/run/agentreceipts/events.sock` is not produced by `daemon.DefaultSocketPath()`, only by explicit configuration) — **superseded on 2026-05-23 by the HOME-based default; see the 2026-05-23 amendment below for the current macOS resolution**. Linux uses `$XDG_RUNTIME_DIR/agentreceipts/events.sock` when that variable is set, falling back to `/run/agentreceipts/events.sock` only when it is not. Both originally-specified system paths can still be selected explicitly via `AGENTRECEIPTS_SOCKET` (or `--socket`) and will become the packaging-managed defaults once launchd / systemd integration lands. The *IPC transport* section above describes the current resolution.

### 2026-05-23: macOS default moved off TMPDIR (issue #545)

The macOS default originally lived under `$TMPDIR/agentreceipts/events.sock`, matching launchd's per-user temp dir. In practice TMPDIR is not inherited by every spawn context — MCP servers launched by Claude Desktop (or any other GUI host) commonly see no TMPDIR and silently land on `/tmp`, while a daemon launched from a shell keeps the launchd-assigned per-user temp dir. The two ends could not find each other, no error surfaced, and zero receipts landed.

The macOS default now resolves against `$HOME` via `$XDG_DATA_HOME/agent-receipts/events.sock` (defaulting to `~/.local/share/agent-receipts/events.sock`). HOME is preserved across every spawn context the daemon supports, so the daemon and any emitter that share a user resolve to the same path regardless of how they were started. The new directory matches the per-user directory already used for `receipts.db` and the Ed25519 signing key, so operators continue to back up a single path to capture every piece of daemon state.

Linux is unchanged: `$XDG_RUNTIME_DIR` is set per-user by systemd-logind across desktop and service sessions, so the divergence pattern that breaks the macOS default does not manifest there in practice. Users running the daemon on a headless box without systemd-logind should pin the socket path explicitly via `AGENTRECEIPTS_SOCKET`, same as before.

Operators upgrading from v0.11.0 or earlier on macOS must restart both the daemon and any emitter (mcp-proxy, hook) so the new default takes effect on both ends. Anyone relying on TMPDIR redirection should switch to `AGENTRECEIPTS_SOCKET` — that override has always taken precedence and is unaffected.

### 2026-05-06: OQ2 — Existing chain migration policy — abandon old chains

**Decision:** v1 users have per-emitter SQLite databases. Phase 2 (Section 3, thin-emitter refactor) will abandon existing v1 chains and start a fresh daemon-managed chain at `seq=1`. No in-place migration or `import-chain` script. The daemon and emitters use new default DB/key paths (separate from v1) to ensure accidental resume does not happen; operators who want to preserve v1 chains for verification must keep v1 and v2 DBs in separate directories.

**Rationale:** agent-receipts is pre-1.0 with early-stage adoption (solo dev and lab usage). No production audit dependencies exist that would prohibit a clean break, and the cost of migration logic (either in-process DB surgery during daemon startup or a separate import tool) compounds the already-substantial emitter refactor burden of Section 3.

**Consequences:**
- Auditors must preserve v1 SQLite databases and matching public keys offline if they require long-term audit of pre-Phase-2 events. V1 receipts remain cryptographically verifiable with those artifacts; v2 daemon does not automatically resume or import v1 chains (separate DB/key paths prevent accidental coexistence).
- v1 chains are not resumed on v2 daemon startup (separate DB/key paths prevent accidental coexistence).
- On daemon startup with a fresh database, the chain starts at `seq=1` with no previous-receipt hash.

**Spec/code changes:**
- No migration logic in daemon startup.
- No v1→v2 chain migration or data import tooling in `sdk/go/store` (schema migrations for other purposes are unaffected).
- Documentation MUST include a deprecation notice: "v1 in-process receipts are not migrated; preserve offline copies if long-term verification is required."

### 2026-05-06: OQ3 — SDK cutover sequencing — single-shot release

**Decision:** All three SDKs (Go, TS, Py), mcp-proxy, and OpenClaw ship in a single PR/release. No phased rollout per channel.

**Rationale:** Phased cutover introduces a mixed-state window where v1 emitters (in-process signing/storage) and v2 emitters (daemon socket, fire-and-forget) write to two separate chains — breaking the core property of daemon-process-separation: a single unified chain. Single-shot release on day one ensures all emitters speak the same schema. The large PR is one cohesive unit; reviewability is not materially worse than five parallel reviews, and readers see the full story at once.

**What mixed-state means for chain integrity (the scenario we avoid by choosing single-shot):**
- During a phased cutover, v1 emitters create receipts in their own per-process SQLite DBs (one per process, no shared `seq` space) while v2 emitters send to the daemon socket (one shared chain, monotonic `seq`).
- Auditors query two independent chains: the daemon chain (v2, authoritative for post-cutover) and N orphaned v1 chains (v1, final state at the moment each module upgraded).
- Cross-channel correlation (e.g., "all receipts for this agent session") requires application logic to coalesce results from both chains, violating the single-chain guarantee.
- Phased rollout would surface this as a gap in audit coverage; single-shot eliminates the window.

**Consequences:**
- Section 3 (thin-emitter refactor) produces one large, multi-module PR (likely 1500+ lines). Structured as one commit per module for clarity, each with test coverage.
- v1 is the final in-process release; v2 is the first daemon-backed release. No intermediate release or beta channel for the cutover itself.

### 2026-05-06: OQ4 — session_id allocation rule — UUID at startup, persistent across reconnects

**Decision:** Each emitter process MUST provide a stable `session_id` (opaque string) for its logical session. If the host provides a session identifier, forward it unchanged. Otherwise, generate a new UUID v4 at startup (recommended form for generated IDs). The `session_id` remains constant across daemon reconnects and is instance-local (lifetime of the emitter instance). The daemon records `session_id` faithfully; verifiers MUST treat it as an advisory grouping hint, not a cryptographic boundary.

**Rationale:**
- **At startup (not per-tool-call):** Agents invoke multiple tool calls within a single logical session. Generating a new `session_id` per tool call would fragment a logical agent session into N receipts with N identifiers. Grouping by emitter-instance lifetime (one session_id for all tool calls within the instance's lifetime) naturally clusters them.
- **Persistent across daemon reconnect:** The emitter holds the session_id in memory. If the daemon restarts or the network drops and reconnects, the emitter retransmits with the same `session_id`, keeping receipts logically grouped. No persist-to-disk is required (the session_id dies with the emitter instance).
- **Uniform across SDKs:** All three SDK emitters (Go, TS, Py) and integration points (mcp-proxy, OpenClaw) initialize `session_id` once at construction time; never generate a new one per emit(). If multiple SDK instances exist in the same process, they should share or coordinate on a single session_id.

**Cardinality and indexing:**
- **Expected cardinality:** Few long-lived sessions per deployment. An agent run typically has one emitter instance (hence one session_id), lasting minutes to hours. Database sees ~1–10 unique `session_id` values per day in typical usage.
- **Indexing strategy:** Phase 2 will extract `session_id` into a dedicated (or generated) column and add a non-unique index to support efficient queries like `SELECT * FROM receipts WHERE session_id = ?`. For now, session_id is only in the receipt JSON; extraction is deferred to the Section 3 schema evolution.

**Normative spec line:**
> "Each emitter process MUST provide a stable `session_id` (opaque string) for its logical session. If the host or parent process provides a session identifier (e.g., Claude Code's session ID, an agent-loop context ID), forward it unchanged. Otherwise, generate a new UUID v4 at emitter startup (recommended form for generated IDs). The `session_id` remains constant across daemon reconnects, instance-local (survives only the lifetime of the emitter instance). The daemon makes no guarantee that `session_id` values are unique across deployments or across time, only that it records the value faithfully."

**SDK author guideline:**
> "Initialize `session_id` once per emitter/SDK instance at construction time. If the host provides a session identifier, use it unchanged; otherwise generate a new UUID v4. Do not generate a new session_id on each emit(). Reuse the same session_id across all tool calls and daemon reconnects within the instance lifetime. No persistence to disk is required."

**Spec/code changes:**
- All three SDKs emit the same `session_id` for their process lifetime; no SDK-specific logic.
- Daemon: no new logic (session_id is already captured in `receipt.Issuer.SessionID`). Schema extraction and indexing deferred to Section 3 (Phase 2).
- Agent-receipts verify CLI can filter by session_id (e.g., `--session <UUID>`) once the schema extraction lands.
