<div align="center">

# obsigna

### Python SDK for the Agent Receipts protocol

[![PyPI](https://img.shields.io/pypi/v/obsigna)](https://pypi.org/project/obsigna/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://github.com/agent-receipts/obsigna/actions/workflows/sdk-py.yml/badge.svg)](https://github.com/agent-receipts/obsigna/actions/workflows/sdk-py.yml)

---

Create, sign, hash-chain, store, and verify cryptographically signed audit trails for AI agent actions.

[Spec](https://github.com/agent-receipts/spec) &bull; [TypeScript SDK](https://github.com/agent-receipts/obsigna/tree/main/sdk/ts) &bull; [Reference Implementation](https://github.com/ojongerius/attest)

</div>

---

## Why receipts?

If you're building with AI agents, you're probably already logging what they do. Receipts go further: they're **cryptographically signed, hash-chained records** that can't be quietly altered after the fact — and they follow a standard format that works across languages, agents, and systems.

Here's where that matters in practice:

- **Post-incident review** — An agent ran overnight and something broke. The receipt chain shows exactly which actions it took, in what order, and whether each succeeded or failed — with cryptographic proof the log hasn't been tampered with after the fact.

- **Compliance and audit** — Regulated environments require evidence of what systems did and why. Receipts are W3C Verifiable Credentials with Ed25519 signatures, giving auditors a tamper-evident trail they can independently verify.

- **Safer autonomous agents** — Agents can query their own audit trail mid-session. Before taking a high-risk action, an agent can check what it has already done and whether previous steps succeeded, enabling self-correcting workflows.

- **Multi-agent trust** — When agents collaborate, receipts serve as proof of prior actions. Agent B can verify that Agent A actually completed step 1 before proceeding to step 2, without trusting a shared log.

- **Usage tracking** — Every action is classified by type and risk level, giving you a structured breakdown of what agents spent their time on.

### Beyond local storage

The protocol is designed for receipts to travel — publishing to a shared ledger, forwarding to a compliance system, or exchanging between agents as proof of prior actions. Receipts are portable W3C Verifiable Credentials, but where they go is always under the user's control.

---

## Install

The Python SDK is on PyPI:

```sh
pip install obsigna
```

Receipts are signed by a separate `obsigna-daemon` process, which also
ships the `agent-receipts` CLI (including the `verify` command). Install it on
Linux or macOS (Windows is not supported yet) — see the
[Daemon Setup guide](https://agentreceipts.ai/getting-started/daemon-setup/).

## Quick start

Agent Receipts are signed by a separate `obsigna-daemon` process, not by
your application. Your code sends tool-call *events* over a local Unix socket;
the daemon holds the Ed25519 signing key, builds the receipt, signs it, and
appends it to the hash-chained store. The signing key never enters your process —
so the audit trail holds up even if the agent is compromised. This is the
canonical deployment shape
([ADR-0022](https://github.com/agent-receipts/obsigna/blob/main/docs/adr/0022-canonical-deployment-shape.md))
and the first thing you should reach for. To learn the receipt API without a
daemon, see [the in-process appendix](#appendix-in-process-signing-tutorial-and-testing-only).

### 1. Start the daemon

Generate the signing key once, then run the daemon. It listens on the per-OS
default socket — see the
[Daemon Setup guide](https://agentreceipts.ai/getting-started/daemon-setup/) for
socket paths and running it as a service.

```sh
obsigna-daemon --init   # one-time: creates the signing key
obsigna-daemon          # start the daemon (leave it running)
```

### 2. Emit a receipt

`DaemonEmitter` forwards the tool-call event to the daemon, which constructs,
signs, and chains the receipt. By default `emit()` surfaces transport failure
(ADR-0025): an unreachable daemon is logged at `DEBUG` and raised as
`EmitTransportError` rather than dropped silently, so start the daemon before
your app. The call stays non-blocking (bounded by the dial + write timeout); construct the
emitter as `DaemonEmitter(best_effort=True)` to opt into loss-tolerant emission
(`emit()` swallows the error and returns `None` instead of raising). `best_effort` is a
constructor argument, not an `emit()` argument.

<!-- snippet-check: no-run -->
```python
from obsigna import DaemonEmitter

with DaemonEmitter() as e:  # uses AGENTRECEIPTS_SOCKET or the per-OS default
    e.emit(
        channel="my-app",
        tool_name="filesystem.file.read",
        decision="allowed",
    )
```

### 3. Verify

`agent-receipts verify` reads the database directly and confirms hash linkage and
signatures — the daemon does not need to be running.

```sh
AGENTRECEIPTS_DB=~/.local/share/agent-receipts/receipts.db \
  agent-receipts verify \
  --public-key ~/.local/share/agent-receipts/signing.key.pub
```

A successful run prints the chain length and confirms the signatures are intact.
If you started the daemon with a non-default chain id (`AGENTRECEIPTS_CHAIN_ID` /
`--chain-id`) or overrode `AGENTRECEIPTS_DB` or `AGENTRECEIPTS_PUBLIC_KEY`, pass
those same values here — otherwise `verify` reads the `default` chain at the
default paths.

### Action taxonomy

The standardized action taxonomy (action types and risk levels) is defined in the
[protocol specification](https://github.com/agent-receipts/spec/tree/main/spec/taxonomy).
The SDK ships classification helpers: `classify_tool_call` maps a tool name to an
action type and risk level using your mappings, `load_taxonomy_config` loads those
mappings from a JSON config (`{ "mappings": [...] }`), and `resolve_action_type`
looks up a single action type's metadata.

```python
from obsigna import classify_tool_call, load_taxonomy_config

mappings = load_taxonomy_config("taxonomy.json")
result = classify_tool_call("read_file", mappings)
print(result.action_type, result.risk_level)
```

## Delivering receipts to a remote collector

When the agent host and the receipt-storage host differ, sign receipts
client-side and POST them to an `obsigna-collector` over HTTPS. This is an
enterprise / multi-host shape, not the first-run path — the daemon above is what
most adopters want.

`obsigna.emitters` (re-exported at the package top level) provides the
building blocks below, all delivering signed `AgentReceipt` values — the receipts
you sign with `sign_receipt`, shown in the [in-process appendix](#appendix-in-process-signing-tutorial-and-testing-only):

- **`HttpEmitter`** — POSTs each receipt to the collector with retry + backoff.
  Default `"sync"` mode waits for the collector ack (`201`, or `409` for a
  duplicate id); `"fire-and-forget"` schedules the POST on a background thread and
  never raises to the caller (call `drain()` before shutdown for a best-effort
  flush).
- **`WalEmitter`** — wraps a *synchronous* inner emitter (`HttpEmitter` in its
  default `"sync"` mode — `"fire-and-forget"` returns before the POST lands, so
  the WAL entry is cleared prematurely and the guarantee is lost) with a
  write-ahead log for at-least-once delivery. Each receipt is recorded *before*
  delivery and cleared only on ack, so a failed delivery is
  **retained and re-sent** — by `replay()` (call once at startup to drain a
  backlog a previous crash left behind) or `flush(deadline_ms)` (bounded
  best-effort drain on shutdown). Use `FileWal` for long-lived compute (survives
  restart) and `MemoryWal` for ephemeral compute (Lambda, Cloud Run).
- **`CompositeEmitter`** (fan-out), **`BufferingEmitter`** (batching), and
  **`InMemoryEmitter`** (testing) round out the set.

<!-- snippet-check: no-run -->
```python
from obsigna import (
    AgentReceipt,
    FileWal,
    HttpEmitter,
    HttpEmitterConfig,
    WalEmitter,
)

# Construct once at startup, then drain anything a previous crash left behind.
http = HttpEmitter(HttpEmitterConfig(endpoint="https://collector.example/receipts"))
emitter = WalEmitter(inner=http, wal=FileWal("/var/lib/my-app/wal"))
emitter.replay()


def deliver(receipt: AgentReceipt) -> None:
    emitter.emit(receipt)  # at-least-once: retained in the WAL until acked
```

Confirm receipts landed with `agent-receipts verify` (above) against the
collector's store.

### Signing with AWS KMS (production key custody)

Client-side signing needs a private key. Loading raw PEM bytes from an env var
or secrets manager keeps an extractable key in process memory — it will not pass
most security reviews. The optional `aws` extra provides a `Signer` whose key
never leaves AWS KMS:

```sh
pip install "obsigna[aws]"
```

<!-- snippet-check: no-run -->
```python
from obsigna.aws import KMSSigner

# keyId: a key ID, key ARN, alias name, or alias ARN. The key must be an
# ECC_NIST_EDWARDS25519 (Ed25519) key with SIGN_VERIFY usage. Credentials come
# from the ambient AWS provider chain (instance role, IRSA, env, profile).
signer = KMSSigner("arn:aws:kms:us-east-1:111122223333:key/abc…", timeout=5.0)

public_key = signer.get_public_key()  # raw 32 bytes (RFC 8032 §5.1.5)

# `sign` operates on the canonical (RFC 8785) bytes of a receipt.
canonical_receipt_bytes = b"...canonicalised AgentReceipt..."
signature = signer.sign(canonical_receipt_bytes)
```

`sign` delegates to `kms:Sign` with `SigningAlgorithm=ED25519_SHA_512` and
`MessageType=RAW` (pure Ed25519); the public key is fetched once via
`kms:GetPublicKey` and cached. The key is not extractable, not present in process
memory, and revocable via IAM — the production answer to the *"Not for
production"* caveat below. (Wiring the `Signer` into `sign_receipt` so it signs
canonical receipts end-to-end is tracked separately; this ships the key-custody
half.)

## Sequential receipt construction (parallel tool calls)

Hash chaining is inherently sequential: receipt *N* must be fully signed and its
hash computed **before** receipt *N+1* is constructed, or the
`previous_receipt_hash` link cannot be formed. A single-threaded agent satisfies
this for free, but an agent that fires **parallel tool calls** (across threads)
would race on the shared chain head (`sequence` + `previous_receipt_hash`) and
produce colliding sequence numbers or a forked chain.

`ReceiptChain` owns that head and serialises the whole build → sign → hash →
link → deliver pipeline under a lock, so concurrent `emit()` calls are sequenced
**at the receipt layer** even when the tool calls that triggered them ran in
parallel. Concurrent emission is not supported as parallel chains in v1 (a
future ADR may add forked sub-chains); overlapping calls from other threads
block until the in-flight one completes, and the first overlap logs a one-shot
warning so the misuse is visible.

```python
from obsigna import (
    ChainEmitInput,
    InMemoryEmitter,
    ReceiptChain,
    generate_key_pair,
)
from obsigna.receipt.create import ActionInput
from obsigna.receipt.types import Issuer, Outcome, Principal

keys = generate_key_pair()

# One ReceiptChain per logical chain (e.g. per agent session). It owns the
# chain head; pass any Emitter — here the in-memory test double, in production
# an HttpEmitter or a WAL-backed emitter.
chain = ReceiptChain(
    chain_id="session-1",
    private_key=keys.private_key,
    verification_method="did:agent:my-agent#key-1",
    emitter=InMemoryEmitter(),
)

# Every emit() is sequenced: receipt N is signed and hashed before N+1 is
# built, even if your tool calls run on parallel threads.
receipt = chain.emit(
    ChainEmitInput(
        issuer=Issuer(id="did:agent:my-agent"),
        principal=Principal(id="did:user:alice"),
        action=ActionInput(type="filesystem.file.read", risk_level="low"),
        outcome=Outcome(status="success"),
    )
)

print(receipt.credentialSubject.chain.sequence)  # 1
```

The head advances as soon as a receipt is signed and hashed — *before* delivery
— so a transient emitter failure does not fork or stall the chain; wrap a
`WalEmitter` around your transport for at-least-once delivery.

## Appendix: in-process signing (tutorial and testing only)

The SDK can also create and sign a receipt entirely in your process, with no
daemon. This is useful for learning the receipt API and for unit tests that
should not depend on a running daemon.

> **Not for production.** This pattern keeps the signing key inside the agent
> process. Anyone with code execution in the agent can forge receipts. For real
> deployments, use the [daemon-mediated path](#quick-start) shown above (see also
> the [Daemon Setup guide](https://agentreceipts.ai/getting-started/daemon-setup/)).

### Create and sign a receipt

```python
from obsigna import (
    ActionInput,
    Chain,
    CreateReceiptInput,
    Issuer,
    Outcome,
    Principal,
    create_receipt,
    generate_key_pair,
    hash_receipt,
    sign_receipt,
)

# Generate an Ed25519 key pair
keys = generate_key_pair()

# Create an unsigned receipt
unsigned = create_receipt(CreateReceiptInput(
    issuer=Issuer(id="did:agent:my-agent"),
    principal=Principal(id="did:user:alice"),
    action=ActionInput(
        type="filesystem.file.read",
        risk_level="low",
    ),
    outcome=Outcome(status="success"),
    chain=Chain(
        sequence=1,
        previous_receipt_hash=None,
        chain_id="chain_session-1",
    ),
))

# Sign and hash
receipt = sign_receipt(unsigned, keys.private_key, "did:agent:my-agent#key-1")
receipt_hash = hash_receipt(receipt)
```

### Verify a receipt and chain

<!-- snippet-check: continues -->
```python
from obsigna import verify_chain, verify_receipt

valid = verify_receipt(receipt, keys.public_key)
print(f"Signature valid: {valid}")  # True

# Verify a list of receipts (e.g. [receipt] from the example above)
result = verify_chain([receipt], keys.public_key)
print(f"Chain valid: {result.valid}")
print(f"Receipts verified: {result.length}")
if not result.valid:
    print(f"Broken at index: {result.broken_at}")
```

## What is an Agent Receipt?

A [W3C Verifiable Credential](https://www.w3.org/TR/vc-data-model-2.0/) signed with Ed25519, recording:

| Field | What it captures |
|:---|:---|
| **Action** | What happened, classified by a [standardized taxonomy](https://github.com/agent-receipts/spec/tree/main/spec/taxonomy) |
| **Principal** | Who authorized it (human or organization) |
| **Issuer** | Which agent performed it |
| **Outcome** | Success/failure, reversibility, undo method |
| **Chain** | SHA-256 hash link to the previous receipt (tamper-evident) |
| **Privacy** | Parameters are hashed, never stored in plaintext |

## API reference

### Receipt creation and signing

```python
from obsigna import (
    ActionInput,          # Action fields for CreateReceiptInput
    CreateReceiptInput,   # Input bundle for create_receipt
    create_receipt,       # Build an unsigned receipt from input fields
    generate_key_pair,    # Ed25519 key pair (PEM-encoded)
    sign_receipt,         # Sign with Ed25519Signature2020 proof
    verify_receipt,       # Verify a receipt's signature
)
```

### Hashing and canonicalization

```python
from obsigna import (
    canonicalize,         # RFC 8785 JSON canonicalization
    hash_receipt,         # Hash receipt (excluding proof) -> "sha256:<hex>"
    sha256,               # Hash arbitrary data -> "sha256:<hex>"
)
```

### Chain verification

```python
from obsigna import (
    verify_chain,         # Verify signatures, hash links, and sequence numbering
)
```

### Types (Pydantic v2 models)

```python
from obsigna import (
    AgentReceipt,         # Signed receipt with proof
    UnsignedAgentReceipt,  # Receipt before signing
    Action, ActionTarget, Authorization, Chain,
    CredentialSubject, Intent, Issuer, Operator,
    Outcome, Principal, Proof, StateChange,
)
```

`ActionReceipt` / `UnsignedActionReceipt` remain as deprecated aliases for
backwards compatibility — prefer `AgentReceipt` / `UnsignedAgentReceipt`.

### Subpackage imports

```python
from obsigna.receipt import create_receipt, sign_receipt
from obsigna.receipt.hash import canonicalize
from obsigna.receipt.types import CONTEXT, CREDENTIAL_TYPE
```

### TypeScript SDK compatibility

camelCase aliases are available for users coming from the TS SDK:

```python
from obsigna import (
    createReceipt,    # = create_receipt
    generateKeyPair,  # = generate_key_pair
    signReceipt,      # = sign_receipt
    verifyReceipt,    # = verify_receipt
    hashReceipt,      # = hash_receipt
    verifyChain,      # = verify_chain
)
```

## Cross-language compatibility

This SDK produces **byte-identical** output to [`@obsigna/sdk-ts`](https://github.com/agent-receipts/obsigna/tree/main/sdk/ts):

- RFC 8785 canonical JSON matches exactly
- SHA-256 hashes are identical
- Ed25519 signatures from either SDK verify in the other

Cross-language compatibility is verified by test vectors generated from the TypeScript SDK.

## Project structure

```
src/obsigna/
  receipt/
    types.py       # Pydantic models for all receipt types
    create.py      # Receipt creation with auto-generated IDs
    signing.py     # Ed25519 signing and verification
    hash.py        # RFC 8785 canonicalization + SHA-256
    chain.py       # Chain verification
```

## Development

```sh
uv sync --all-extras
uv run pytest              # run tests
uv run ruff check .        # lint
uv run ruff format .       # format
uv run pyright             # type check
```

| | |
|:---|:---|
| **Language** | Python 3.11+ |
| **Types** | Pydantic v2, pyright strict mode |
| **Linting** | ruff |
| **Testing** | pytest |
| **Dependencies** | `pydantic>=2.0`, `cryptography>=41.0` |

## Ecosystem

| Component | Description |
|:---|:---|
| [agent-receipts/obsigna](https://github.com/agent-receipts/obsigna) | Monorepo: spec, SDKs, daemon, MCP proxy, hook |
| **[Python SDK](https://github.com/agent-receipts/obsigna/tree/main/sdk/py)** (this package) | [PyPI](https://pypi.org/project/obsigna/) |
| [TypeScript SDK](https://github.com/agent-receipts/obsigna/tree/main/sdk/ts) | [npm](https://www.npmjs.com/package/@obsigna/sdk-ts) |
| [Go SDK](https://github.com/agent-receipts/obsigna/tree/main/sdk/go) | `go get github.com/agent-receipts/ar/sdk/go` |
| [obsigna-daemon](https://github.com/agent-receipts/obsigna/tree/main/daemon) | Out-of-process signer + `agent-receipts` verify CLI (canonical deployment) |
| [agent-receipts/spec](https://github.com/agent-receipts/spec) | Protocol specification, JSON Schemas, canonical taxonomy |
| [ojongerius/attest](https://github.com/ojongerius/attest) | MCP proxy + CLI (reference implementation) |

## License

Apache 2.0 — see [LICENSE](LICENSE).
