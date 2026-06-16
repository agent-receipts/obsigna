# obsigna-daemon

Single OS-user process that owns the Ed25519 signing key and the SQLite
receipt store. Emitters (mcp-proxy, OpenClaw, SDK consumers) connect over a
local Unix-domain socket and send fire-and-forget event frames; the daemon
captures the connecting peer's OS-attested credentials, canonicalises the
receipt (RFC 8785), signs it (Ed25519), and persists it.

See [ADR-0010](../docs/adr/0010-daemon-process-separation.md) for design
rationale and [issue #236](https://github.com/agent-receipts/obsigna/issues/236)
for the work breakdown.

This is **Phase 1** of the daemon roll-out — the foundation slice. It ships
the standalone daemon binary, peer-cred capture, chain-tail resumption, the
file-backed `KeySource`, and the `obsigna receipt verify` read CLI (which
works whether the daemon is up or down). Emitter refactor for mcp-proxy /
OpenClaw / SDK ships in later phases.

## Build

```sh
go build ./cmd/obsigna-daemon
go test ./...                     # unit tests
go test -tags=integration ./...   # integration tests (real socket, real DB)
```

Build from a clone of the monorepo: the repo-root `go.work` wires the in-tree
`sdk/go` so `go build` from `daemon/` picks up `ReceiptStore.GetChainTail`.

`go install github.com/agent-receipts/ar/daemon/cmd/obsigna-daemon@latest`
is **not yet supported**: the daemon depends on `sdk/go.GetChainTail`, which
is not in the latest published `sdk/go` tag (`v0.6.0`). Standalone install
becomes possible once the next `sdk/go` tag is released and a follow-up bumps
the require in `daemon/go.mod`.

### CI coverage

`.github/workflows/daemon.yml` runs `go vet`, builds `./cmd/...`, and
runs the unit + integration test suite with `-race` and
`-tags=integration` on pushes to `main` and on pull requests targeting
`main` whose diff touches `daemon/**` or `sdk/go/**`. The `sdk/go/**`
trigger mirrors `mcp-proxy.yml` so that `sdk/go` changes which break
the daemon are caught in the same PR that introduces them.

## Run

The daemon takes config from a TOML config file, environment variables, or
flags, in **precedence order file < env < flags** (lowest to highest): a key
omitted from the file leaves the env/flag/default value untouched, and any
matching env var or explicit flag overrides a file value. All fields have
sensible per-OS defaults. The config file defaults to
`$XDG_DATA_HOME/agent-receipts/daemon.toml` (falling back to
`~/.local/share/agent-receipts/daemon.toml`) — a missing default-path file is
fine; override the path with `--config` or `AGENTRECEIPTS_CONFIG`, where a
missing file, malformed TOML, or an unknown key is an error. `--print-config`
prints the fully resolved config (paths only — never key material) in the same
shape, so it doubles as a starting `daemon.toml`.

```sh
obsigna-daemon \
  --socket /run/agentreceipts/events.sock \
  --db    /var/lib/agentreceipts/receipts.db \
  --key   /etc/agentreceipts/signing.key \
  \
  --issuer-id "did:agent-receipts-daemon:$(hostname)" \
  --verification-method "did:agent-receipts-daemon:$(hostname)#k1"
```

| Flag | Env | Default |
|---|---|---|
| `--socket` | `AGENTRECEIPTS_SOCKET` | Linux: `$XDG_RUNTIME_DIR/agentreceipts/events.sock` (falls back to `/run/agentreceipts/events.sock`). macOS: `$XDG_DATA_HOME/agent-receipts/events.sock` (defaults to `~/.local/share/agent-receipts/events.sock`). |
| `--unsafe-socket-path` | — | `false` — permit a `--socket` outside the per-platform safe set (see [Socket-path safety](#socket-path-safety)). |
| `--db` | `AGENTRECEIPTS_DB` | `$XDG_DATA_HOME/agent-receipts/receipts.db` (defaults to `~/.local/share/agent-receipts/receipts.db`) |
| `--key` | `AGENTRECEIPTS_KEY` | `$XDG_DATA_HOME/agent-receipts/signing.key` (defaults to `~/.local/share/agent-receipts/signing.key`) |
| `--chain-id` | `AGENTRECEIPTS_CHAIN_ID` | `default` |
| `--issuer-id` | `AGENTRECEIPTS_ISSUER_ID` | `did:agent-receipts-daemon:local` |
| `--public-key` | `AGENTRECEIPTS_PUBLIC_KEY` | `<--key>.pub` |
| `--verification-method` | `AGENTRECEIPTS_VERIFICATION_METHOD` | `did:agent-receipts-daemon:local#k1` |
| `--shutdown-deadline` | — | `200ms` — time budget for emitting interrupted-chain terminators on SIGTERM/SIGINT (see [Graceful shutdown](#graceful-shutdown)). |
| `--config` | `AGENTRECEIPTS_CONFIG` | `$XDG_DATA_HOME/agent-receipts/daemon.toml` (falls back to `~/.local/share/agent-receipts/daemon.toml`) — TOML config file; a missing default-path file is fine, but a missing `--config`/`AGENTRECEIPTS_CONFIG` path, malformed TOML, or an unknown key is an error. |
| `--print-config` | — | `false` — print the fully resolved config (paths only — never key material) and exit; the output doubles as a starting `daemon.toml`. |

The signing key file must be a PKCS#8-encoded Ed25519 private key (the format
`receipt.GenerateKeyPair()` in `sdk/go` produces) with permissions no looser
than owner-only — the daemon rejects any group or world bit (read, write, or
execute), so `0600`, `0400`, etc. are accepted; `0640` and `0644` are not.
The daemon also refuses to start on a non-Ed25519 key, a symlink, or a
non-regular file at this path.

The socket directory is created with mode `0750` if missing; the socket
itself is `0660`. Phase 1 unprivileged installs use the per-user defaults
(`$XDG_DATA_HOME` on macOS, `$XDG_RUNTIME_DIR` on Linux when set).

### Socket-path safety

The per-user runtime/data directory is what makes peer-credential capture and
the trust boundary meaningful (ADR-0010 § IPC transport). A socket in a shared,
world-traversable, periodically-swept directory (e.g. `/tmp`) keeps peer creds
working but loses location privacy, and the socket file may disappear under
load. To stop a safe default being silently abandoned by an override, the
daemon refuses to start when `--socket` / `AGENTRECEIPTS_SOCKET` resolves
outside the per-platform safe set:

- **Linux:** under `$XDG_RUNTIME_DIR` (when set), `/run`, or `/var/run`.
- **macOS:** under `$TMPDIR` (when set), `/var/run`, or
  `$XDG_DATA_HOME/agent-receipts` (where the per-user default lives, alongside
  `receipts.db` and the signing key).

The path is canonicalized with `filepath.EvalSymlinks` before the check, so a
symlink pointing out of the safe set is judged by its real target. The default
socket path always resolves inside the safe set, so defaults are never
rejected. TCP addresses (e.g. `127.0.0.1:9000`) are rejected unconditionally —
the daemon speaks Unix-domain sockets only.

To deliberately run on a path outside the safe set — containers with unusual
mounts, dev experiments, the short `/tmp` path the integration tests need to
stay within the macOS `sun_path` limit — pass `--unsafe-socket-path`. The
daemon then starts, logs a `level=warn` line naming the path, and re-emits the
warning every 60 seconds. The flag unblocks legitimate edge cases; it does not
suppress the warning, and it does not override the TCP rejection.

On every startup the daemon publishes the matching SPKI public key to
`--public-key` (default `<KeyPath>.pub`, tracking any `--key` override) with
mode `0644`, so independent verifiers — `obsigna receipt verify`, audit
scripts, CI checks — can load it without access to the private key path. If
the file already exists with the same contents the publish is a no-op; if
the contents differ the daemon refuses to start (a mismatch means either
the signing key was rotated / restored from backup, or the published file
was tampered with — operator must remove the stale file deliberately). The
daemon also refuses if the path is a symlink, FIFO, device, etc.

The published key file is `0644`, but its parent directory is created at
`0750` to match the receipt-store directory's access policy — non-owners
must be in the daemon user's group to traverse it and reach the public key.
Per-user installs (the MVP path: `$XDG_DATA_HOME/agent-receipts/`, defaulting
to `~/.local/share/agent-receipts/`) are unaffected since the operator who
runs the verify CLI owns the directory. System installs
(`/etc/agentreceipts/`, `/var/lib/agentreceipts/`) are expected to give the
daemon a dedicated `agentreceipts` user and the read-side an
`agentreceipts-read` group whose members traverse the directory; that
ownership/grouping is a packaging concern (Homebrew / launchd / systemd) and
not something the daemon assigns at runtime. If the directory already exists
the daemon does not modify its mode, so operator-managed permissions are
preserved.

## Graceful shutdown

On SIGTERM or SIGINT the daemon performs a three-phase shutdown:

1. **Stop accepting** — the IPC socket listener closes immediately. New emitter connections are refused from this point.
2. **Drain** — Active handler goroutines that have already started reading their frame run to completion; connections not yet fully accepted or partially read are closed. No new receipts can enter the chain after this step.
3. **Terminate** — if the configured chain (`--chain-id`) has at least one receipt and no terminal receipt yet, the daemon emits a terminal receipt with `chain.terminal: true` and `chain.status: "interrupted"`. This receipt is signed with the daemon's key and persisted to the store before the process exits, so verifiers can later classify the chain as `interrupted` rather than `unknown`. (The daemon owns one chain per process; multi-chain support is future work.)

The total deadline for step 3 is `--shutdown-deadline` (default `200ms`). The deadline is **best-effort**: it gates entry into the signing and store operations, but cannot preempt an already-in-progress SQLite call (the store does not yet use context-aware `QueryRowContext`/`ExecContext`). Under normal conditions (single-writer process, local disk) this is not a practical concern. If the deadline expires before the terminator is written, the daemon logs a `level=warn` line (`terminator: deadline expired, chain … will be classified as 'unknown' by verifier`) and exits cleanly — the verifier's `unknown` classification (spec §7.3.3) is the documented fallback for chains whose terminator could not be written in time. Store I/O or signing failures during terminator emission are surfaced as a non-zero exit code.

Once a terminal receipt has been written, the daemon will refuse to start again against the same `--chain-id` and `--db`; use a new `--chain-id` or a fresh `--db` for subsequent runs.

**Crash case (SIGKILL / OOM kill):** the daemon cannot write anything. Chains left without a terminal receipt are classified as `unknown` by the verifier. This is by design — spec §7.3.3 documents `unknown` as the recourse for chains the daemon never sees again.

**TTL semantics (v1):** there is no idle-chain TTL in v1. The daemon emits `interrupted` for every open chain at shutdown time, regardless of how long ago the last receipt was written. Over-emitting `interrupted` for a long-idle chain is the lesser failure mode compared to designing TTL semantics under shutdown pressure. Follow-up issue tracked separately.

## Read interface: `obsigna receipt verify`

```sh
obsigna receipt verify
# or, with explicit paths:
obsigna receipt verify \
  --db /var/lib/agentreceipts/receipts.db \
  --public-key /etc/agentreceipts/signing.key.pub \
 
```

Defaults match the daemon's: a verify run without flags works after
`obsigna-daemon` has run at least once with the same per-user paths.

`verify` opens the SQLite store **read-only** via `sdk/go/store.OpenReadOnly`
so it is safe to run while the daemon is the active writer, and it does not
require the daemon socket to be reachable. Independent verifiability is not
gated on daemon availability (issue #236, Section 4).

**Rotated chains verify with no extra flags.** After an offline
`obsigna-daemon --rotate`, the published `--public-key` holds the *new*
key, but a chain is anchored to the key that signed its first receipt. `verify`
resolves that genesis key automatically from the superseded keys `--rotate`
archives beside the live one (`<public-key>.rotated-<fingerprint>`), then traverses each
`key_rotated` receipt forward (spec §7.3.7) — so a rotated chain reports `VALID`
against the published key path. If those archives are missing, the chain reports
`BROKEN` at the first receipt rather than silently passing.

Resolution stays pinned to the operator's key: a chain reached through an
archive must end its rotation lineage at the `--public-key` it was verified
against. A cryptographically self-consistent chain that rotates to some *other*
key — e.g. an attacker who planted a `<public-key>.rotated-*` archive and a
chain signed under their own key — reports `BROKEN` (the published key is not
the chain's current key), so a forged archive cannot turn into a `VALID` result.

Exit codes are stable for scripting:

| Code | Meaning |
|---|---|
| `0` | Chain verified |
| `1` | Chain failed verification (output lists per-receipt status) |
| `2` | Usage error (bad flags, missing key file, unreadable DB) |

## Read interface: `obsigna receipt show <seq>`

```sh
obsigna receipt show 42
# or, against a multi-chain store / explicit DB:
obsigna receipt show 42 --db /var/lib/agentreceipts/receipts.db
# pretty-printed JSON:
obsigna receipt show 42 --json
```

Prints the full fields of the receipt at chain sequence `<seq>` (1-indexed):
issuer, chain id, action type / tool, parameters hash, outcome, signature, and
any action-specific payload (e.g. the drop count on an `events_dropped`
receipt). Like `verify`, it opens the store **read-only** so it is safe to run
while the daemon writes.

`--chain-id` is required only when the store holds more than one chain; with a
single chain it is auto-detected. Without it on a multi-chain store, the
command lists the available chain ids and exits with a usage error.

Exit codes are stable for scripting:

| Code | Meaning |
|---|---|
| `0` | Receipt found and printed |
| `1` | No receipt at the requested sequence (or empty store) |
| `2` | Usage error (bad flags, ambiguous chain, unreadable DB) |

## Read interface: `obsigna receipt verify-event`

`verify` answers "is this chain internally consistent?". `verify-event` answers
the narrower question that turns out to matter most for trust: **was this
specific receipt produced by the documented `emitter → daemon → chain`
pipeline, or written to the store by some other path?** It composes the chain
checks (signature, hash linkage, sequence contiguity) with the daemon-captured
`peer_credential` (ADR-0010 § Permissions and trust) that makes the audit
meaningful — the agent's self-asserted identity is untrusted; peer attestation
is what is load-bearing.

```sh
# A single receipt by id:
obsigna receipt verify-event --id urn:receipt:...

# The most recent receipt in the chain:
obsigna receipt verify-event --chain-head

# Every receipt issued in a trailing window (e.g. post-incident triage):
obsigna receipt verify-event --since 10m --json

# Pin the expected emitter(s) — mismatches warn, they do not fail:
obsigna receipt verify-event --chain-head \
  --emitter-allowlist /usr/bin/mcp-proxy,/usr/bin/openclaw
```

Exactly one selector (`--id`, `--chain-head`, `--since`) is required. Like the
other read commands it opens the store **read-only**, so it is safe to run
against a live daemon's database or a forensic snapshot, and it never emits —
unlike `doctor`'s synthetic round-trip, this is a cheap historical read.

It runs six checks per receipt, each reported with a structured pass / fail /
warn / n/a status:

1. **Signature** — the Ed25519 signature verifies under the supplied public key.
2. **Hash linkage** — the receipt chains back to the daemon's startup baseline
   and is reachable from the chain head (any break anywhere taints it).
3. **Peer credential present** — the daemon-captured `peer_credential` is
   present and well-formed. Receipts predating peer-credential capture are
   flagged `n/a` ("predates peer-credential evidence"), **not failed**.
4. **Emitter identity** — the captured `exe_path` matches the operator
   `--emitter-allowlist`. This is operator policy, not protocol: a mismatch
   **warns**, it never fails. With no allowlist configured the observed path is
   surfaced informationally.
5. **Schema version** — the receipt's schema version is one this verifier
   understands (compatible by major version).
6. **Chain context** — the receipt's sequence position is contiguous with its
   neighbours (no gap immediately before or after).

The verdict distinguishes the two cases operators currently cannot tell apart:

- **VERIFIED — pipeline-provenance confirmed**: crypto holds *and* the
  peer-credential evidence shows the documented pipeline produced it.
- **VERIFIED (cryptographically) — no pipeline-provenance evidence**: crypto
  holds but there is no peer credential. This is the state a receipt written
  directly to SQLite (or emitted before peer-credential capture) produces.

What it deliberately does **not** check: whether the audited action actually
happened in the world (no protocol can attest to that), and whether the emitter
binary is trustworthy beyond its `exe_path` matching the allowlist (binary
integrity attestation is a separate, ADR-grade decision).

Use cases: forensic snapshot review, post-incident triage (`--since`), and a CI
gate on a known-good receipt — gate on exit `0` to require provenance, or
accept `0` and `3` alike to require only cryptographic validity.

Exit codes are stable for scripting:

| Code | Meaning |
|---|---|
| `0` | Verified **and** pipeline-provenance confirmed |
| `1` | A check failed — the receipt is suspect, investigate |
| `2` | Usage error (bad flags, no/ambiguous selector, unreadable DB or key) |
| `3` | Verifies cryptographically but lacks peer-credential evidence |

When a selector resolves to multiple receipts (`--since`), the process exit code
is the worst case across them (`1` outranks `3`, which outranks `0`).

## Health check: `obsigna doctor`

```sh
obsigna doctor
# structured output for CI / healthchecks:
obsigna doctor --json
# treat warnings as failures (stricter CI gate):
obsigna doctor --json --warn-as-error
# skip the synthetic round-trip (writes no event to the chain):
obsigna doctor --no-roundtrip
```

`doctor` diagnoses the whole pipeline ADR-0010 describes — emitter → socket →
daemon → SQLite → `verify` — and reports an actionable per-step result. It
exists because the pipeline's failure modes are subtle: tool calls succeed at
the application layer and individual signatures verify, yet the documented path
can be silently broken (wrong socket path, world-readable DB, version skew,
missing peer-credential capture). `doctor` makes "agent-receipts is working on
this host" mean **`doctor` exits 0**, not "a row exists in SQLite" (issue #539).

It resolves paths and the chain id exactly like `verify`/`list` (`--socket`,
`--db`, `--public-key`, `--chain-id`, or the matching `AGENTRECEIPTS_*` env
vars), so a no-flag run works after the daemon has run once with the same
per-user paths.

Checks, in pipeline order:

| Check | What it asserts | `fail` means |
|---|---|---|
| `daemon process` | A daemon is reachable on the resolved socket. | No daemon is listening — start it with `obsigna daemon run`. |
| `socket` | The socket file exists, is a socket, and is not world-accessible (daemon binds `0660`). | Missing/usurped path, or a non-socket file at the path. |
| `emitter dial path` | The path an emitter on this host would dial matches the daemon's. | (warns) Emitter and daemon disagree — events would never arrive. |
| `db permissions` | The receipt DB is no looser than `0640` (ADR-0010 § Read interface). | World-readable receipts leak peer attestation / disclosures. |
| `schema/version` | The store is readable and the published public key parses; reports the key fingerprint and receipt count. | Unreadable DB or malformed/absent public key. |
| `peer credentials` | The OS peer-credential primitive (`SO_PEERCRED` / `LOCAL_PEERCRED`) is available. | Unsupported platform — peer-cred capture, and thus the trust model, is unavailable. |
| `chain head` | The stored chain verifies via the `verify` code path. An `unknown` head (never cleanly terminated) is surfaced as a `warn` (issue #475). | The chain fails verification (BROKEN). |
| `round-trip` | **Load-bearing.** A synthetic event fired through the real socket lands in the DB with a *fresh* peer credential matching doctor's PID/UID. | The event never landed, or its peer credential was not freshly attested for this process. |

The round-trip is the check the Max-incident postmortem motivated: an
`INSERT`-then-`SELECT` on the DB file "works" while bypassing the socket, the daemon's
peer-cred capture, and the chain head. The synthetic event is **deliberately
visible** in the chain — channel `doctor`, tool `agent-receipts-doctor.roundtrip`,
which the daemon records as `action.type` **`doctor.agent-receipts-doctor.roundtrip`**
(a low-risk diagnostic self-check). That is the value to filter on when querying
the chain. A "test mode" that bypassed the
chain would defeat the property being tested: that *real* events make the full
traversal. Use `--no-roundtrip` to skip it (e.g. a forensic-mode daemon that
must not receive synthetic events); the round-trip check then reports `warn`.

On macOS the daemon's accept-time `LOCAL_PEEREPID` lookup can race a fast peer
detach and record `pid=0` (see `peercred_darwin.go`); when the synthetic event
lands with a matching UID but `pid=0`, the round-trip reports `warn` (pipeline
intact, fresh PID unconfirmed) rather than a misleading credential-mismatch
`fail`.

`chain head` verifies the **full** stored chain rather than only a tail window:
hash-link verification is meaningless without the prefix, so a partial-tail
check could not establish integrity.

Exit codes are stable for CI:

| Code | Meaning |
|---|---|
| `0` | All checks `ok` (or only `warn` without `--warn-as-error`) |
| `1` | At least one check `fail`ed (or `warn`ed under `--warn-as-error`) |
| `2` | Usage error (bad flags) |

## Wire protocol

SOCK_STREAM Unix-domain socket (uniform across Linux and macOS — see
*Transport choice* below). Each emitter message is a 4-byte big-endian length
prefix followed by a JSON payload of that many bytes. Maximum payload is
1 MiB; larger frames are dropped with the connection.

The JSON payload is the ADR-0010 emitter schema:

```json
{
  "v": "1",
  "ts_emit": "2026-05-03T00:00:00.000Z",
  "session_id": "uuid-v4",
  "channel": "mcp_proxy",
  "tool": { "server": "github", "name": "list_repos" },
  "input": { "owner": "agent-receipts" },
  "output": [ { "name": "ar" } ],
  "error": "",
  "decision": "allowed"
}
```

`decision` is one of `allowed` / `denied` / `pending`. `input` and `output`
accept any JSON value (object, array, primitive) or `null` / omitted for
events with no payload; the daemon canonicalises (RFC 8785) and stores only
the SHA-256 digest in `action.parameters_hash` and `outcome.response_hash`,
never the raw bytes. The daemon adds `seq`, `prev_hash`, `ts_recv`, peer
attestation, and the receipt id before signing, so emitters never see those
fields and cannot forge them.

## Phase 1 scope and deviations

The following are deliberate Phase 1 choices, all callable out for follow-up:

- **Transport choice.** ADR-0010 specifies `SOCK_SEQPACKET`. macOS does not
  support SEQPACKET on AF_UNIX, so the daemon uses `SOCK_STREAM` uniformly
  on both Linux and macOS with explicit length-prefix framing. Peer-credential
  retrieval works identically on stream sockets, so the trust model is
  unchanged. A follow-up issue should amend ADR-0010 to record the per-OS
  socket type.
- **Peer attestation placement.** ADR-0010 called for a top-level peer
  field; spec v0.3.0 (PR #496) added a dedicated `action.peer_credential`
  object on the receipt. The daemon writes that typed field directly
  (`platform`, `pid`, `uid`, `gid`, `exe_path`) and the synthetic
  events_dropped receipt's drop counter rides on the sibling
  `action.emitter_metadata.drop_count` field. The values are still
  signature-protected. The Phase-1 flat-map shape (`peer.platform`,
  `peer.pid`, etc. inside `parameters_disclosure`) has been retired.
- **macOS `peer_credential.exe_path`.** Linux populates this from `/proc/<pid>/exe`;
  macOS uses the `SYS_PROC_INFO(PROC_PIDPATHINFO)` syscall directly
  (the call libproc's `proc_pidpath()` wraps), so the daemon stays
  CGO-free. Failure is non-fatal — `exe_path` is left empty and pid /
  uid / gid are still recorded.
- **Single chain id.** The daemon owns one chain id per process. Multi-chain
  support can grow `chain.State` into a chainID-keyed map without breaking
  callers.
- **No emitter refactor.** mcp-proxy, OpenClaw, and the three SDKs continue
  to sign in-process. They will be migrated to thin emitters in Phase 2+.
- **No drop-counter / `events_dropped` synthetic receipts.** That mechanism
  belongs with the emitter side (`EAGAIN` handling) and ships with the
  emitter refactor.
- **No Homebrew / launchd / systemd packaging.** Operators run the binary
  directly in Phase 1.
- **No Windows port.** Tracked as a separate issue per #236.

## Layout

```
daemon.go                                  # Run() entrypoint and Config; publishes the public key on startup
cmd/obsigna-daemon/main.go                 # daemon CLI: flag/env parsing, signal handling
cmd/agent-receipts/main.go                 # read CLI: thin shim over internal/{listcli,showcli,verifycli,doctorcli}
internal/
  chain/state.go                           # in-memory (seq, prev_hash) owner; sole writer
  keysource/keysource.go                   # KeySource interface (ADR-0015 shape)
  keysource/file.go                        # PEM-on-disk adapter
  socket/listener.go                       # Unix-domain socket + length-prefix framing
  socket/peercred_{linux,darwin,other}.go  # OS-specific peer-credential capture
  pipeline/build.go                        # frame + peer -> AgentReceipt -> sign -> store
  listcli/list.go                          # `obsigna receipt list` subcommand
  showcli/show.go                          # `obsigna receipt show <seq>` subcommand
  verifycli/verify.go                      # `obsigna receipt verify` subcommand
  doctorcli/doctor.go                      # `obsigna doctor` pipeline health check
integration_test.go                        # tags: integration. End-to-end concurrency, peer-cred, and verify-CLI fixtures.
tests_doctor_test.go                       # tags: integration. `obsigna doctor` round-trip against a live daemon.
```
