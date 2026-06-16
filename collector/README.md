# collector

Reference HTTP collector for the Agent Receipts protocol. Accepts signed
receipts from SDK `HttpEmitter` clients and persists them to a local store.

This is the server-side peer of [ADR-0020](../docs/adr/0020-emitter-abstraction-and-remote-receipt-delivery.md).
The collector is intentionally minimal: it performs no signing, no chain
construction, no sequencing, and no signature verification. Verification is
the auditor's job, not the collector's.

## Trust model

The collector is **not** a trusted component for chain construction. A
compromised collector can drop or refuse receipts, but it cannot forge, alter,
or reorder them — every receipt is signed and chained client-side before
delivery. Auditors verify the chain using only the agent's public key.

This is the property that makes ADR-0020's remote-emitter design safe for
multi-tenant operation: tenants can share collector infrastructure without
trusting the operator.

## Wire contract

```
POST /receipts
Content-Type: application/ld+json

{ ...agentReceipt }

→ 201 Created     receipt accepted and persisted
→ 409 Conflict    receipt id already exists (idempotent re-delivery acceptable)
→ 400 Bad Request malformed receipt — SDK should not retry
→ 5xx             transient error — SDK should retry with backoff
```

The collector MUST NOT:

- Modify, reorder, or rehash receipts
- Reject receipts solely on signature verification failure

The collector SHOULD:

- Be append-only
- Return 409 on duplicate `id` rather than 500, to support safe client retry

### Validation scope

Structural validation only. The collector returns 400 when:

- The body is empty or not valid JSON
- The body is over `--max-body-bytes` (default 1 MiB)
- The receipt is missing `id`, `credentialSubject.chain.chain_id`,
  `credentialSubject.action.type`, or `proof.proofValue`
- The body contains more than one JSON object

This list is the deliberate minimum, not an oversight. Full JSON-schema
conformance, signature verification, taxonomy correctness, and chain
linkage are the auditor's responsibility — not the collector's. The
collector's contract under ADR-0020 is "store what arrived, idempotently";
anything stricter would couple SDK upgrades to collector upgrades and
defeat the forward-compat-sink design.

Unknown JSON fields are accepted and persisted verbatim. A future SDK
shipping a new field MUST NOT require every collector to upgrade first.
Anything that parses and has the four minimal fields above is accepted
regardless of signature validity.

Wire bytes are stored verbatim, not a re-marshal of the Go struct, so an
auditor can later re-canonicalise and verify the agent's signature against
exactly what the agent signed over.

### Status codes

The receipts handler emits these statuses:

- `201` — accepted and persisted
- `400` — malformed body (see above)
- `409` — receipt id already exists
- `500` — store backend failure (only)

`/healthz` returns `200` when the store is reachable, `503` otherwise.

### Other routes

- `GET /healthz` — returns 200 when the store is reachable, 503 otherwise

## Running

The collector binary is **`obsigna-collector`** (ADR-0035), launched in
production via `obsigna collector run`, which `syscall.Exec`s straight into it.
The legacy `collector` binary still works as a thin deprecation shim that
forwards to `obsigna-collector` — update installers to the new name when
convenient; the shim will be removed in a future release.

```sh
go run ./cmd/obsigna-collector --addr 127.0.0.1:8787 --db collector.db
```

The default `--addr` binds to loopback (`127.0.0.1:8787`) so a `go run` on a
workstation does not expose an unauthenticated audit-trail endpoint to the
network. To expose the collector beyond localhost, opt in explicitly:

```sh
go run ./cmd/obsigna-collector --addr 0.0.0.0:8787
```

In production, run the collector behind a reverse proxy or service mesh that
terminates TLS and applies authentication — see Out of scope (v0) below.

### Configuration

| Flag | Env var | Default | Notes |
|---|---|---|---|
| `--addr` | `AGENTRECEIPTS_COLLECTOR_ADDR` | `127.0.0.1:8787` | HTTP listen address (loopback by default) |
| `--db` | `AGENTRECEIPTS_COLLECTOR_DB` | `collector.db` | SQLite path; use `:memory:` for non-durable storage |
| `--max-body-bytes` | `AGENTRECEIPTS_COLLECTOR_MAX_BODY_BYTES` | `1048576` (1 MiB) | Per-request body cap |
| `--drain-timeout` | `AGENTRECEIPTS_COLLECTOR_DRAIN_TIMEOUT` | `10s` | Graceful shutdown drain window |
| `--version` | — | — | Print version and exit |

### Sending a receipt

```sh
curl -i \
  -H 'Content-Type: application/ld+json' \
  -d @receipt.json \
  http://localhost:8787/receipts
```

## Out of scope (v0)

These are intentionally not in the reference collector and will land as
follow-ups:

- **Authentication / authorization.** The client side is covered by
  `HttpEmitterAuth` (api-key, bearer, mTLS) in ADR-0020; the server-side
  counterpart is a follow-up. Use network-level controls (private VPC,
  reverse proxy, service mesh) in v0.
- **Horizontal scaling guidance.** The SQLite store is single-node. A
  Postgres backing store is on the roadmap; SQLite is fine for low-volume
  or single-agent deployments.
- **Object-lock / WORM archive.** ADR-0019 § O2 covers receipt store
  completeness; the reference collector does not currently fan out to an
  immutable archive.
- **SIEM / OTel fan-out.** ADR-0017 (central receipt hub) covers this
  shape separately.

## Development

```sh
go test ./...        # unit tests
go vet ./...         # static analysis
go build ./cmd/...   # obsigna-collector binary + the collector deprecation shim
```

Tests use an in-memory `Store` for the HTTP layer and a fresh on-disk SQLite
database (under `t.TempDir()`) for the SQLite-adapter tests.

## References

- [ADR-0020](../docs/adr/0020-emitter-abstraction-and-remote-receipt-delivery.md)
  — emitter abstraction, collector contract
- [ADR-0035](../docs/adr/0035-collector-binary-topology.md)
  — collector binary topology (`obsigna-collector`, `obsigna collector run`)
- [ADR-0018](../docs/adr/0018-signer-abstraction-and-cloud-agnostic-keyprovider-design.md)
  — `Signer` interface (production key story for HTTP emitters)
- Issue [#533](https://github.com/agent-receipts/obsigna/issues/533) — this work
- Issue [#486](https://github.com/agent-receipts/obsigna/issues/486) — `HttpEmitter` (paired client work)
- Issue [#536](https://github.com/agent-receipts/obsigna/issues/536) — operator guide
