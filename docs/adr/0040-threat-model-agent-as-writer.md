# ADR-0040: Threat Model — Agent as Writer

## Status

Proposed

## Context

ADR-0010 makes the daemon the sole signer and sole writer of the receipt store, and the [threat model](../threat-model.md) calls the compromised-agent defence "shipped, not aspirational". The Max-incident postmortem showed a gap between that claim and what an agent can actually do. An agent reported "agent-receipts is working — I wrote a receipt and read it back from SQLite". That was technically true and operationally wrong. The `INSERT`-then-`SELECT` bypassed the socket, peer-credential capture, the chain head, and the signature.

The postmortem produced five follow-ups. Three have shipped:

| Follow-up | Status |
|---|---|
| Daemon refuses unsafe socket paths | Shipped — [#538](https://github.com/agent-receipts/obsigna/issues/538), PR [#579](https://github.com/agent-receipts/obsigna/pull/579) |
| `doctor` subcommand (load-bearing round-trip check) | Shipped — [#539](https://github.com/agent-receipts/obsigna/issues/539) |
| `verify-event` subcommand (pipeline-provenance check) | Shipped — [#540](https://github.com/agent-receipts/obsigna/issues/540), PR [#659](https://github.com/agent-receipts/obsigna/pull/659) |
| SDKs must not have direct DB write paths; daemon is exclusive writer | Unfiled — decided here |
| Add a `daemon_attestation` field to receipts | Unfiled — decided here |

The last two cannot be decided one issue at a time. Both depend on which writer this project defends against, and ADR-0010 never named that writer. This ADR names it.

### Write paths available to an agent

An agent is a process with code execution as its own OS user. It can put something that looks like a receipt in front of a reader in four ways:

- **W1 — Raw store write.** The agent opens `receipts.db` and inserts a row directly. The row has no valid signature, or a signature from a key the verifier does not trust.
- **W2 — In-process SDK signing.** The agent uses an SDK's in-process path: its own key, `Store.Insert`, a valid signature under the wrong key. ADR-0022 D2 keeps this path supported for tutorials and tests.
- **W3 — Daemon-key theft.** The agent reads the daemon's signing key and signs forged receipts that verify against the published daemon public key.
- **W4 — Lying through the pipeline.** The agent emits over the real socket but lies in the event body (tool, input, output).

W4 is already defended. The daemon records kernel-attested `action.peer_credential` (pid/uid/gid/exe_path) and the grounded principal (ADR-0038) alongside the claim, inside the signed body. The lie is recorded next to ground truth.

W1 and W2 are **detectable but not preventable** by the protocol. Verification against the daemon's public key rejects them, and `verify-event` exits `3` on a receipt that verifies cryptographically but carries no peer-credential evidence. Neither check helps when the reader never runs a verifier, which is exactly what happened in the incident.

W3 depends on the deployment:

- **System install** (Linux `agent-receipts-daemon.system.service`): the daemon runs as the dedicated `agentreceipts` user, the key is `0400` in `/etc/agentreceipts`, and the DB is `0640`. The agent's uid can read neither the key nor write the DB, so W1 against the daemon's store and W3 are both prevented by the OS.
- **Per-user install** (the default MVP path: `systemctl --user`, launchd agent, `~/.local/share/agent-receipts/`): the daemon runs as **the same uid as the agent**. The key's `0600` mode excludes other users, not the agent. The agent can read the key (W3) and write the DB (W1). Peer-credential capture still works, but the agent can also forge it.

The threat model currently states the compromised-agent defence without this deployment qualifier. The [OpenClaw deep-dive post](../../site/src/content/docs/blog/openclaw-plugin-deep-dive.mdx) already states the qualifier correctly, so the two documents disagree.

## Decision

### D1. The adversary is a compromised agent running as its own uid

The agent-as-writer threat is: **an agent process with arbitrary code execution as its own OS user, trying to make a record of an action exist, disappear, or change, without that being detectable by a verifier.** Root, the daemon user, and supply-chain compromise stay out of scope, as the threat model already states.

### D2. A trustworthy receipt is defined by verification, not by storage

A row in `receipts.db` is **not** evidence. A receipt is evidence only if all of the following hold:

1. its signature verifies against the daemon's published public key;
2. it hash-links into a chain that verifies (and against an external anchor, where one is configured, per ADR-0015);
3. it carries a daemon-attested `action.peer_credential`.

Together these are `obsigna receipt verify-event` exit `0`. For "is the pipeline working", the success criterion is `obsigna doctor` exit `0`, never "a row exists". Every doc surface that explains how to check that receipts are being written points to `doctor` or `verify-event`, not to a SQLite query.

This makes W1 and W2 explicitly **detect-only** threats. The defence is the verifier, and prevention is not claimed.

### D3. W3 is prevented only when the daemon runs as a separate uid

The compromised-agent defence is a property of the **system install**, not of daemon mediation as such. The threat model and the Trust Model page must say this directly.

- **System install:** W1 against the daemon's store and W3 are prevented by the OS. This is the only deployment for which the threat model claims the compromised-agent defence.
- **Per-user install:** it defends against *accidental* bypass (misconfigured emitters, stale socket paths, an agent "checking" the pipeline the wrong way) and keeps the single-canonicalizer and single-chain benefits of ADR-0010. It does **not** defend against a deliberately malicious agent running as the same user. This is a stated limitation, not a bug.

### D4. SDK store write paths stay; they are not a security boundary

The "SDK should not have direct DB write paths" follow-up is **re-scoped, not implemented as filed**:

- Removing `Store.Insert` / `insert()` from the Go, TypeScript, and Python SDKs would break the in-process mode ADR-0022 D2 keeps for tutorials and tests. It would also add no security. An agent with code execution needs no SDK function to write a SQLite file: `sqlite3`, any SQLite binding, or raw file I/O will do. The boundary is filesystem ownership (D3), and detection is the verifier (D2).
- What the incident did expose is a **footgun**: nothing stops an SDK from opening the *daemon's* store for writing and appending rows next to daemon-signed receipts. The re-scoped follow-up is a guard: the daemon marks its store as daemon-owned (for example with a store-level metadata row written at initialisation), and SDK stores refuse to open a daemon-owned store read-write, with an error that points at the emitter path. Read-only opens (`OpenReadOnly`, `verify`, `verify-event`, `doctor`) are unaffected.
- The guard is documented as a correctness guard, not a security control. A hostile agent can remove the marker, and the verifier catches the rows anyway (D2).

### D5. No separate `daemon_attestation` field

The `daemon_attestation` follow-up is **closed as already covered**. The attestation it asks for already exists:

- `action.peer_credential` (spec v0.3.0+) is daemon-attested by definition. The schema says so, and it is present only on receipts produced through a daemon.
- The daemon's Ed25519 signature over the canonical body is the daemon's attestation that it produced the whole receipt, peer credential included.
- `verify-event` already combines these into a pipeline-provenance verdict.

A new field inside the signed body would be written by the same key that signs the body, so it cannot tell "the daemon signed this" apart from "someone holding the daemon's key signed this". That is the W3 case, and only D3 defends against it. Binding a key to "is a daemon key" belongs to issuer/key resolution (ADR-0007, ADR-0015), not to a receipt field. Any future proposal to add daemon identity to receipts (daemon version, instance id, deployment tier) needs its own spec change and explicit approval under `spec/` governance.

## Consequences

- The threat model's compromised-agent claim gains its deployment qualifier. After this ADR it matches the system-install reality and the OpenClaw post.
- Operators get one answer to "is this receipt real?" (`verify-event`) and one answer to "is the pipeline working?" (`doctor`). A SQLite row is explicitly not either.
- The per-user install stays the easy default but is described accurately. Operators who must defend against a malicious agent are pointed to the system install.
- No SDK API is removed, no spec change is made, and no new receipt field is added.
- The daemon-owned-store guard (D4) is a small, cross-SDK change. It needs the same behaviour in Go, TypeScript, and Python, and a cross-SDK test.

## Follow-ups

- Edit `docs/threat-model.md` so that § Compromised agent process and § Current implementation status qualify the defence by deployment tier (D3).
- Edit the Trust Model site page to match D3.
- Add a `doctor` check that warns when the daemon's uid equals the invoking user's uid ("per-user install: compromised-agent defence not in effect"). It should be a warning, never a failure, because per-user is a supported tier.
- File the daemon-owned-store write guard across sdk/go, sdk/ts, and sdk/py with a cross-SDK test (D4).
- Close the `daemon_attestation` follow-up as covered by `action.peer_credential` and `verify-event` (D5).

## Related ADRs

- [ADR-0004 (SQLite storage)](./0004-sqlite-for-local-receipt-storage.md) — the store the agent can reach in the per-user install.
- [ADR-0007 (DID method strategy)](./0007-did-method-strategy.md) — where key-to-daemon binding belongs.
- [ADR-0010 (Daemon process separation)](./0010-daemon-process-separation.md) — sole-writer design; this ADR names the adversary it assumed.
- [ADR-0015 (Key rotation, BYOK, anchoring)](./0015-key-rotation-byok-anchoring.md) — external anchoring bounds post-compromise damage.
- [ADR-0022 (Canonical deployment shape)](./0022-canonical-deployment-shape.md) — keeps in-process SDK signing, which constrains D4.
- [ADR-0038 (Grounded-principal conformance tier)](./0038-grounded-principal-conformance-tier.md) — kernel-attested principal, part of the W4 defence.
