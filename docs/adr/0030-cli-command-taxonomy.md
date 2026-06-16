# ADR-0030: CLI Command Taxonomy

## Status

Accepted (2026-06-12). Amended (2026-06-14): added the grouped verb
`obsigna receipt disclose` — an additive change permitted by the "new
functionality only ever receives a grouped command" rule below (no rename, no
removal, no new flat alias).

## Context

The implementation layer is being rebranded `agent-receipts` → `obsigna`, and the
separate binaries (receipt CLI, daemon, collector, mcp-proxy) are consolidating under a
single `obsigna` entrypoint. The command surface becomes a stability contract the moment
it ships — the same class of commitment as the `/context/v1` spec URLs, which are
cryptographically load-bearing in issued receipts.

The existing surface is flat: `agent-receipts verify`, `agent-receipts show`. That string
appears in SDK docs, quick-starts, and user CI. Any taxonomy we pick has to (a) scale to
the five noun-groups we actually have, and (b) make the rename a name-only swap on the hot
path rather than a restructuring that breaks every pipeline.

## Decision

**Canonical form is grouped noun-verb: `obsigna <noun> <verb>`.**

Noun groups and leaves:

```
obsigna receipt verify <file|->     # alias: obsigna verify
obsigna receipt show <id>           # alias: obsigna show
obsigna receipt list
obsigna receipt verify-event        # carried over from agent-receipts (PR #788)
obsigna receipt disclose <seq>      # decrypt a receipt's parameters_disclosure (forensic key); added 2026-06-14

obsigna daemon run                  # foreground primitive
obsigna daemon status

obsigna collector run
obsigna collector status

obsigna keys generate
obsigna keys pubkey
obsigna keys rotate                 # ADR-0015 surface

obsigna mcp run                     # the mcp-proxy

obsigna doctor                      # top-level diagnostic; carried over from agent-receipts (PR #788)
```

`obsigna doctor` is an intentional exception to grouped noun-verb: a diagnostic
entrypoint that mirrors `brew doctor`. It is not a precedent for other flat top-level
verbs — new functionality still only ever receives a grouped command.

**Flat aliases are a closed two-member set: `{verify, show}`**, mapping to
`obsigna receipt verify` / `obsigna receipt show`.

**Invariant (the bound against alias sprawl):** a flat alias may exist *only* if it
corresponds to a pre-existing `agent-receipts` verb. The migration is the sole
justification for a flat alias, so the set is closed the day we ship and cannot grow. New
functionality only ever receives a grouped command — never a flat one.

**Leaf defaults:**
- `daemon run` (and `collector run`) are foreground primitives. Lifecycle —
  start/stop/daemonize, and execution under the dedicated non-agent OS user where the
  trust boundary lives — is owned by the service manager (`brew services`, systemd), not
  reimplemented in the binary.
- `mcp`, not `proxy`, as the noun — it names what is proxied; "proxy" is generic.

Aliases are shown in `--help`, documented as "shortcut for `obsigna receipt verify`", so
the canonical form stays unambiguous without hurting discoverability.

## Consequences

- The `agent-receipts` deprecation shim is a verbatim passthrough
  (`agent-receipts "$@"` → `obsigna "$@"`) for the two flat verbs. Flat→flat is preserved
  for exactly the verbs that live in everyone's scripts; the hot path migrates by name
  only.
- Unblocks the one-shot formula move+rename: a single `tap_migrations.json` entry can
  move and rename together, with no incoherent intermediate (a tap named `obsigna`
  shipping a binary named `agent-receipts`).
- The top-level noun groups, the leaf verbs, and the two flat aliases are now a frozen
  compatibility surface. Changing any of them later is itself a user-visible migration.
- `obsigna receipt verify-event` and the top-level `obsigna doctor` were carried over from
  the legacy `agent-receipts` CLI in PR #788. The golden surface test
  (`daemon/cmd/obsigna/surface_test.go`) freezes the surface the `obsigna` binary actually
  ships today — the `receipt` and `keys` groups, top-level `doctor`, and the flat aliases —
  and is the enforcement that keeps that subset and this document in lockstep. The reserved
  `daemon`, `collector`, and `mcp` nouns are not yet shipped, so they are intentionally
  absent from the gate until the consolidation ADR lands.
- This decision is agnostic to binary packaging — `obsigna daemon run` may be compiled-in
  or transparently exec `obsigna-daemon`; the verb contract and the formula consumer never
  see the difference.

## Non-goals

- Monolith vs. dispatcher packaging — deferred to a later ADR.
- Per-command flag/option design.
- Service-manager integration specifics beyond establishing `run` as the foreground
  primitive.
