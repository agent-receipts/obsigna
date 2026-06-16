# Threat Model

**Status:** Current. The daemon architecture from [ADR-0010](adr/0010-daemon-process-separation.md) (daemon process separation) is shipped — the MCP proxy and the hook are thin emitters that hold no key, and `obsigna-daemon` is the sole signer. Claims that depend on not-yet-shipped pieces of [ADR-0015](adr/0015-key-rotation-byok-anchoring.md) (production external-anchor adapters, checkpoint anchoring, and HSM/KMS key custody) are flagged inline and summarised under [Current implementation status](#current-implementation-status) below. For the full deployment spectrum behind these boundaries — in-process SDK signing through HSM/KMS custody — see the [Trust Model](https://agentreceipts.ai/specification/trust-model/) page.

**Audience:** Security leads evaluating Agent Receipts for their environment, white-hat reviewers probing the system, and compliance teams writing audit narratives. The intent is that trust assumptions are stated upfront — not discovered.

## Trust boundaries

The trust anchor is the **agent-receipts daemon**. The daemon runs as its own OS user, is sole owner of the signing keys and the SQLite receipts database, and is the only thing that canonicalizes (RFC 8785) and signs receipts. Emitters (the MCP proxy, the OpenClaw plugin, SDK consumers) become thin event producers that fire-and-forget over a local IPC socket.

The **agent process is untrusted with respect to the receipt chain.** It cannot read the signing key, cannot write the database, cannot canonicalize, and cannot construct a signature. The peer credentials of the connecting emitter are captured by the daemon at the OS level (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` / `LOCAL_PEEREPID` on macOS, named-pipe APIs on Windows). The agent's self-asserted identity is not trusted; peer attestation is what makes the audit meaningful.

### Trust still rests on

- **The host OS.** Process isolation, filesystem permissions, and user/group separation are how the daemon's exclusivity over the signing key is enforced.
- **The init system.** systemd, launchd, and the Windows Service Manager are responsible for starting the daemon as the right user with the right permissions and for restarting it on crash.
- **The daemon binary.** Supply-chain integrity of the daemon binary itself is out of scope for this document; tracked separately (see [#151](https://github.com/agent-receipts/obsigna/issues/151)).
- **User/group separation between emitter and daemon.** Emitters run as the agent user; the daemon runs as `agentreceipts`. The DB is `0640` owned `agentreceipts:agentreceipts-read`; the public key is `0644` world-readable. If those modes are violated by misconfiguration, the daemon's exclusivity property collapses.
- **Honest system clock.** Replay detection via timestamps and the temporal ordering of rotation events both assume the host clock is honest. An attacker who controls the clock can backdate events; the chain hash protects ordering relative to other receipts but cannot, on its own, attest to wall-clock truth.
- **The external anchor sink, when configured.** The post-compromise integrity guarantee (see [What we explicitly claim](#what-we-explicitly-claim)) is conditional on an operator-configured external sink that the daemon does not control. Without an anchor, post-compromise integrity remains aspirational.

## What we explicitly claim

> Receipts are cryptographically tamper-evident. Mid-chain modifications, deletions, reorderings, and replays are detected by signature verification and hash-chain checks. The chain's historical integrity survives daemon-key compromise **if and only if rotation events and periodic checkpoints are anchored to a sink the daemon does not control.** Without that anchor, an attacker who compromises the daemon can forge a clean tail or a clean rotation history that is indistinguishable from a real one. With it, history is fixed and the worst the attacker can do is forge *future* receipts under the compromised key — which the next anchored rotation or checkpoint will surface.

The conditional is load-bearing. ADR-0015 specifies the [`KeySource` interface](adr/0015-key-rotation-byok-anchoring.md), the rotation event schema, and the external anchor write contract that this guarantee depends on.

## In-scope threats — what receipts protect against

### Tampered receipts

A receipt whose canonical bytes are modified after signing fails Ed25519 verification. RFC 8785 canonicalization (ADR-0002) ensures bit-stable inputs to the signature, so re-serialisation does not produce false positives. Verifiers reject modified receipts.

### Missing receipts (gap detection)

Receipts carry a monotonic `seq` field. Verifiers check for sequence-number gaps. Two emitter-side failure modes are distinguished by ADR-0010:

- **Daemon not running.** Events drop silently — by definition there is no daemon to record the gap. Operators detect this via service-manager status and the absence of fresh receipts.
- **Daemon backpressured.** Emitters track local drop counts and flush them with the next successful event. The daemon synthesises an `events_dropped` receipt into the chain so backpressure drops are visible.

### Reordered receipts

The hash chain (`prev_hash` linking each receipt to its predecessor) makes any reordering detectable. A verifier replaying the chain will fail to recompute the expected hash if receipts are reordered.

### Replayed receipts

Sequence numbers and `ts_recv` timestamps catch replay. The daemon assigns `ts_recv` authoritatively (the emitter's `ts_emit` is advisory only), so an attacker cannot replay an old receipt with a fresh timestamp without breaking the signature.

Replay detection assumes an honest host clock — see [Trust still rests on](#trust-still-rests-on).

### Compromised agent process

A compromised agent process is now a defended threat, not an admitted gap. The agent cannot read the signing key (it lives in the daemon's address space, owned by a different OS user), cannot write the database (filesystem permissions deny it), and cannot canonicalize or sign. The worst a compromised agent can do is **lie about its own actions in the events it sends** — but the daemon attests the agent's PID/UID/exe path independently, so the lie is recorded alongside ground truth.

### Tail truncation

An attacker who compromises the daemon can drop the most recent N receipts and present a clean prefix. Chain verification alone cannot detect this — the truncated chain is internally consistent.

**Mitigation: external anchor checkpoints (ADR-0015 Phase B).** The daemon writes `(seq, tip_hash, public_key_fingerprint)` triples to an operator-configured external sink at configurable intervals (default: hourly). `tip_hash` commits to the most recently appended receipt itself, so a verifier comparing the local chain against the most recent anchored checkpoint detects truncation as a mismatch on either `seq` or `tip_hash`. ADR-0015 Phase A ships rotation anchoring; Phase B adds checkpoint anchoring. Tail-truncation defence is **partial until Phase B lands**; tracked at [#171](https://github.com/agent-receipts/obsigna/issues/171).

### Forged rotation history

An attacker who compromises the daemon could rewrite the chain's rotation events to retire the legitimate signing key in favour of an attacker-controlled one, then forge subsequent history. Chain verification cannot detect this if the rotation events themselves are forged — the chain is internally consistent and the new key signs everything after the (forged) rotation.

**Mitigation: external anchor for rotation events (ADR-0015 Phase A).** Every `key_rotated` receipt is mirrored to the external sink immediately after it is appended to the local chain. A rotation history that the anchor does not corroborate is rejected. This is the load-bearing reason the conditional in [What we explicitly claim](#what-we-explicitly-claim) names rotation anchoring explicitly.

### Sensitive data in storage

Action parameters are committed via `parameters_hash` by default (privacy-preserving, tamper-evident). Operators who need on-demand forensic recovery enable [ADR-0012](adr/0012-payload-disclosure-policy.md) parameter disclosure: the daemon encrypts elected parameters into a separately-keyed HPKE envelope (`action.parameters_disclosure`) inside the signed receipt body, and an offline responder recovers them with the matching private key (SDK `DecryptDisclosure`). **Both the daemon-side sealing and the responder-side decryption are shipped.** The forensic decryption key lives with the responder, not the daemon — so the daemon (and therefore a compromised daemon) cannot decrypt past disclosures.

Tool **output/response is committed via `response_hash` only** — there is no response-disclosure envelope yet, so responses (which often carry the sensitive payload: file contents, query results) cannot be forensically recovered. This input/output asymmetry is tracked in [#819](https://github.com/agent-receipts/obsigna/issues/819).

Plaintext secrets in receipts are forbidden by policy (see [AGENTS.md security section](../AGENTS.md)).

## Out-of-scope threats

### Compromised daemon process / daemon-user filesystem access

**Refined as bounded, not total.** An attacker who gains code execution as the daemon user, or who reads the daemon's filesystem (signing key, DB), can:

- Forge **future** receipts under the current signing key.
- Force a key rotation to an attacker-controlled key.

What they cannot do, **provided rotation events and checkpoints are anchored externally** (ADR-0015):

- Rewrite the chain's history without that rewrite being inconsistent with the external anchor.
- Forge a rotation history that the anchor did not see.
- Truncate the tail without the next checkpoint catching the regression.

Without an external anchor, daemon compromise is total — chain history can be rewritten freely. The anchor is what bounds the blast radius.

### Compromised root

If the attacker is `root`, all OS-level isolation properties are off the table. The daemon's user/group separation, file permissions, and peer-credential capture all assume the kernel is honest and the root user is not the adversary. Out of scope.

### Colluding MCP client that bypasses the proxy

If the MCP client is compromised in a way that lets it talk to the upstream MCP server *without going through the proxy at all*, there is no event emitted and no receipt to sign. The audit trail can only witness traffic that passes through the proxy. Out of scope; addressed structurally by deployments where the operator controls the client configuration and the network path.

### Lying MCP client / TOCTOU between model and proxy

A compromised MCP client that *does* relay through the proxy but constructs **different payloads for the model versus the proxy** is outside the trust boundary. The receipt witnesses what the client sent through the proxy; if the client showed the model a different prompt or different tool arguments before sending a sanitised version on to the proxy, the receipt records the sanitised version, not what the model actually saw.

This is distinct from the colluding-client case above. A colluding client bypasses the proxy entirely (no receipt at all). A lying client emits receipts that look correct but do not reflect what the model received. Detecting this requires attestation on the model-facing side of the client, which is out of scope for the proxy/daemon and tracked elsewhere as a transparency / model-input-attestation problem.

### Network-level attacks on localhost

The IPC transport between emitter and daemon is a Unix domain socket (Linux/macOS) or a named pipe (Windows). TCP loopback is explicitly rejected by ADR-0010. Network-level attacks (ARP spoofing, localhost MITM via raw sockets) require kernel-level access and reduce to the compromised-root case.

### Supply-chain compromise of the daemon binary

A malicious daemon binary can do anything. Out of scope here; tracked separately at [#151](https://github.com/agent-receipts/obsigna/issues/151) (binary signing, reproducible builds, distribution channel hardening).

## Current implementation status

The daemon architecture is shipped. The MCP proxy and the PostToolUse hook are thin emitters: they hold no Ed25519 key, generate none, and contain no signing path at all — they send event frames over a Unix socket to `obsigna-daemon`, which is the sole signer and the sole writer of the store. Peer credentials are captured via `SO_PEERCRED` / `LOCAL_PEERCRED` at `accept()` (before any frame is read) and recorded in the signed `action.peer_credential`. The daemon refuses to load a signing key whose file mode grants any group or world access and opens it `O_NOFOLLOW`. So the **compromised-agent defence above is shipped, not aspirational**, for the daemon-mediated deployment.

In-process SDK signing still exists — but as a deliberate deployment model, not a footgun. An operator who trusts the agent host and only needs tamper-evidence against downstream parties may choose it for its portability, accepting that code execution in the agent can forge receipts in that model. The daemon deployment is the default precisely for operators who must defend against a compromised agent. The full spectrum is documented on the [Trust Model](https://agentreceipts.ai/specification/trust-model/) page; this threat model describes the daemon deployment unless stated otherwise.

What remains partial — and therefore bounds the claims above:

- **External anchoring is partially shipped.** Key rotation and anchor-first rotation writes are implemented, with a dependency-free file-log *reference* adapter (a plain file is only as append-only as the filesystem around it). Production-grade anchor adapters (S3 object-lock, transparency log, SIEM ingest) and checkpoint anchoring for tail-truncation detection (ADR-0015 Phase B) are **not yet shipped**. So the post-compromise integrity guarantee in [What we explicitly claim](#what-we-explicitly-claim) remains conditional on configuring a qualifying external sink, and that adapter ecosystem is still landing.
- **HSM / cloud-KMS key custody is not yet shipped.** The `KeySource` interface is in place and the file-backed adapter is the default; PKCS#11 and KMS backends (ADR-0015 Phase C) are designed but unimplemented. Against a host-level compromise, the file-backed key is readable by the daemon user — see [Compromised daemon process](#compromised-daemon-process--daemon-user-filesystem-access).
- **Forensic parameter disclosure (ADR-0012) is wired in the daemon.** When a forensic public key is configured, the daemon pipeline encrypts elected parameters into an HPKE envelope addressed to that key; the matching private key lives with the offline responder, not the daemon. This is no longer an open gap.

## Mitigations and roadmap

| Concern | ADR | Issue | Status |
|---|---|---|---|
| Daemon process separation (signing/storage isolation from agent) | [ADR-0010](adr/0010-daemon-process-separation.md) | [#236](https://github.com/agent-receipts/obsigna/issues/236) | Accepted; shipped — MCP proxy and hook are keyless emitters; the daemon is the sole signer |
| Key rotation, BYOK, external anchoring | [ADR-0015](adr/0015-key-rotation-byok-anchoring.md) | [#307](https://github.com/agent-receipts/obsigna/issues/307) (PR [#319](https://github.com/agent-receipts/obsigna/pull/319)) | Accepted; rotation + anchor-first writes + file-log reference adapter shipped; production anchor adapters & checkpoint anchoring (Phase B), HSM/KMS (Phase C) pending |
| DID-based identity for issuer/key resolution | [ADR-0007](adr/0007-did-method-strategy.md) | [#46](https://github.com/agent-receipts/obsigna/issues/46) | Proposed |
| Algorithm agility (PQ-ready signing) | — (`KeySource` interface in ADR-0015 is algorithm-agnostic by design) | [#32](https://github.com/agent-receipts/obsigna/issues/32) | Tracked |
| Supply-chain integrity of the daemon binary | — | [#151](https://github.com/agent-receipts/obsigna/issues/151) | Tracked |
| Key file permission hardening | — | [#156](https://github.com/agent-receipts/obsigna/issues/156) | Tracked |

The `KeySource` interface in ADR-0015 is algorithm-agnostic by design — adding a post-quantum signing scheme later does not force a redesign of the interface, only a new adapter. This is the structural prerequisite for [#32](https://github.com/agent-receipts/obsigna/issues/32).
