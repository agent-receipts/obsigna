# Demo: truncation goes red

**The claim:** a tail-truncated receipt chain still verifies `VALID`. Dropping
the last few receipts leaves the rest internally consistent, so plain
`obsigna verify` can't see the gap ([ADR-0008 §2](../../docs/adr/0008-response-hashing-and-chain-completeness.md)).
The fix is an **out-of-band, signed checkpoint anchor** the agent's UID cannot
rewrite — and `verify --against-anchor` turns that gap **red**.

**This demo proves it end to end through the real path**, not a hand-written
script:

```
 OpenCode (real binary, real session)
    │  tool.execute.after            ← native bash tool calls
    ▼
 @obsigna/opencode-plugin            ← emitter only, holds no key (this checkout)
    │  Unix socket (emit)
    ▼
 obsigna-daemon                      ← signs (Ed25519), chains, AND…
    │                                  …signs a checkpoint per receipt
    ▼
 git checkpoint anchor               ← commits to a dir the AGENT UID cannot write
    ▲
 obsigna verify --against-anchor     ← head vs latest signed checkpoint → green/red
```

Everything in that diagram is the shipped code, built from this checkout. The
**only** stub is the LLM: a local, offline [mock model](./mock-model.mjs) drives
OpenCode through a handful of `bash` calls so the run is deterministic and free.
The model sits *outside* the integrity boundary — whoever decides the tool
calls, the receipt-and-checkpoint path is identical. (Run it against a real
model below.)

## Why two OS users

The checkpoint anchor only beats an attacker if it lives in a **different
fate-sharing domain** than the agent. So the demo runs the daemon and the agent
as **two different OS users**:

| Principal | User | Owns / can do |
|---|---|---|
| **daemon** | `obsigna-daemon` | owns the anchor dir (`git`, mode `0700`), the key, the store; signs receipts + checkpoints |
| **agent** | `obsigna-agent` | runs OpenCode; *emits* over the socket — and nothing else |

They share a group so the agent can reach the daemon's socket (`0660`, group
member can connect). The anchor dir is `0700` — owner-only — so the same agent
that just emitted receipts **cannot** rewrite the witness. `start.sh` proves
this with a live `echo >> anchor.ndjson` that gets `Permission denied`.

This is why the demo needs `root` (to create the two users); the security
property *is* the OS boundary.

## Prerequisites

- **Linux** — the demo creates OS users (`useradd`) and a setgid socket dir under
  `/run`; the UID boundary it proves is an OS construct
- `go` 1.26+, `node` 20+, `pnpm`, `git` — to build this checkout
- `root` / `sudo` — to create the two demo users and the `/run` socket dir
- `opencode` — auto-installed via `npm install -g opencode-ai` if missing
- Network on first run (npm/opencode/provider install). Behind a TLS-intercepting
  proxy the scripts point Node at the OS trust store automatically; run with
  `sudo -E` to preserve any `NODE_EXTRA_CA_CERTS` you already have.

## Run it

```bash
cd demo/opencode-anchor

sudo -E ./start.sh     # build → real OpenCode session → boundary proof → GREEN verify
sudo -E ./verify.sh    # re-run the green verification any time
sudo -E ./attack.sh    # drop the store tail → RED verify (saved to artifacts/red-verify.txt)
sudo ./clean.sh        # tear down state  (add --users to delete the demo users too)
```

`start.sh` leaves the signed store and anchor under `/tmp/obsigna-anchor-demo`
(override with `DEMO_HOME=...`), so `verify.sh` and `attack.sh` run against real,
persisted output.

### What you'll see

`start.sh` ends green:

```
Chain demo-chain: VALID (6 receipts)
Anchor …/anchor.ndjson: PASS (6 checkpoint(s); head seq 6 anchored)
```

`attack.sh` ends red — the captured artifact ([`artifacts/red-verify.txt`](./artifacts/red-verify.txt)):

```
Chain demo-chain: VALID (3 receipts)
Anchor …/anchor.ndjson: FAIL (truncation) — anchor records head at seq 6 (…)
  but store head is seq 3: receipts 4..6 truncated
```

Same store, two verdicts: plain verify can't see the dropped tail; the anchor
can.

## Run it against a real model

The mock only chooses the tool calls. To prove the path with a real agent,
authenticate a provider and swap the model — nothing else changes:

```bash
opencode auth login                         # e.g. Anthropic
# edit start.sh's `opencode run -m …` to e.g.  -m anthropic/claude-sonnet-4-6
# and ask it to run a few shell commands / edit a file
```

The receipts, checkpoints, boundary, and verify behave identically; only the
chain length and tool mix become non-deterministic.

## The checkpoint sinks (this demo runs `git`)

`--checkpoint-anchor` is a fan-out list; one checkpoint goes to every sink:

- **`git:<dir>`** — *used here.* The commit chain is the tamper-evident
  structure; the daemon commits to a dir the agent UID cannot write.
- **`file:<path>`** — append-only NDJSON; immutability is only as strong as the
  filesystem perms around it.
- **`syslog:<tag>`** — local/forwarded syslog: a different host or principal.

For a witness that survives full host compromise, point a sink at an **off-box**
append-only medium — object-lock (WORM) storage, a transparency log, or a
sequence-stamping SIEM ingest. **Named, not run here:** the demo's tier is the
local `git` backend, which already beats the in-box agent.

## Files

| File | Role |
|---|---|
| `start.sh` | build, set up users, run the real session, prove the boundary, green verify |
| `verify.sh` | re-runnable `verify --against-anchor` (green) |
| `attack.sh` | truncate the store tail → red verify → capture the artifact |
| `clean.sh` | tear down state (`--users` also removes the demo users) |
| `lib.sh` | shared paths, principals, helpers |
| `mock-model.mjs` | offline deterministic model that drives the tool calls |
| `workspace/` | the agent's OpenCode project: `opencode.json` + `.opencode/plugin/` |
| `artifacts/red-verify.txt` | the captured red verdict |

## Troubleshooting

- **`missing required tool: pnpm`** — `npm install -g pnpm` or `corepack enable`.
- **npm/opencode TLS errors** — you're behind a proxy; re-run with `sudo -E`, or
  ensure the proxy CA is in `/etc/ssl/certs/ca-certificates.crt`.
- **`opencode session failed`** — see `/tmp/obsigna-anchor-demo/logs/opencode.log`
  and `daemon.log`.
