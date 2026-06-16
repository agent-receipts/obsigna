# daemon_protocol

Gate #8 from ADR-0024: daemon ↔ SDK protocol compatibility at release time.

ADR-0010 (daemon process separation) and ADR-0022 (daemon-mediated primary
deployment) make the daemon the primary path, so "this SDK works with the
daemon" is a compatibility claim the project asserts. Per ADR-0024 D1 that claim
needs a gate, so a release cannot ship an SDK/daemon pair that cannot talk to
each other.

## The protocol-version surface

Both sides declare an inclusive integer range of emitter-frame schema versions
(the `v` field on the wire, currently `"1"`):

| Side | Declaration | Read by the gate via |
|------|-------------|----------------------|
| Daemon (spoken range) | `pipeline.SpokenFrameVersionMin`/`Max` | `obsigna-daemon --protocol-version` → `{"frame_version":{"min":N,"max":M}}` |
| Go SDK (declared range) | `emitter.DaemonProtocolMin`/`Max` | the SDK driver's `range` mode → `{"min":N,"max":M}` |
| TS SDK | `DAEMON_PROTOCOL_RANGE` | same |
| Python SDK | `DAEMON_PROTOCOL_RANGE` | same |

Today every side speaks exactly one version, so all ranges are `[1, 1]`. Each
side has a test that ties its declared range to the version it actually emits or
accepts, so the declaration cannot drift from the bytes on the wire.

## Layout

| File | Role |
|------|------|
| `check.py` | Downloads the released daemon tarball + installs the released SDK, asserts their ranges intersect, then runs a live handshake (boot daemon → emit from the SDK → assert a receipt lands). |
| `test_check.py` | Unit tests for the pure core (range intersection, semver "latest" selection, asset-URL construction, stdout parsing, receipt counting). No download, no install, no network. |

## Run locally

```sh
python3 scripts/daemon_protocol/test_check.py             # unit tests (no network)
python3 scripts/daemon_protocol/check.py --sdk-lang go --sdk-version 0.10.0 --daemon-version 0.8.0
python3 scripts/daemon_protocol/check.py --sdk-lang ts --sdk-version latest --daemon-version latest
python3 scripts/daemon_protocol/check.py --sdk-lang py --sdk-version latest --daemon-version latest
```

`--sdk-version`/`--daemon-version` accept an explicit `X.Y.Z` (no leading `v`)
or `latest`, which resolves from the registry / GitHub releases. Pass
`--allow-prerelease` to let `latest` consider pre-release tags.

`check.py` and `test_check.py` use only the Python standard library
(`urllib`, `json`, `tarfile`, `subprocess`); there is no third-party dependency
to install. The gate does need the toolchain for the SDK it is testing on
`PATH` (`go`, or `node`, or `python3` + `pip`) so it can install and run the
published SDK driver, and a `linux/amd64` runner for the daemon tarball.

## What this gate checks

1. **Static intersection.** The released SDK's declared range overlaps the
   released daemon's spoken range. A non-overlapping pair (e.g. an SDK that only
   speaks `v2` against a daemon that only speaks `v1`) turns the release red
   before either is treated as good.
2. **Live handshake.** Backs the static claim with the real thing: it boots the
   released daemon on a throwaway socket/db/key (`--unsafe-socket-path`, since a
   tmpdir socket is outside the per-platform safe set), emits one event through
   the released SDK, and asserts a receipt lands in the store — read back via
   the daemon's `agent-receipts list` companion. A pair that passes the static
   check but cannot actually exchange a frame still turns the release red.

## Which versions are paired

The gate runs from both release sides so either half landing turns a broken
pair red:

- An **SDK release** runs the gate with `--sdk-version <the just-released SDK>`
  and `--daemon-version latest` (the daemon consumers already have).
- A **daemon release** runs the gate for each SDK with
  `--daemon-version <the just-released daemon>` and `--sdk-version latest`.

## Relationship to the in-tree daemon integration tests and the other gates

The daemon's in-tree integration tests (`daemon/tests_*_test.go`) exercise the
same emitter → socket → daemon → DB pipeline at PR time against in-tree source —
never release-blocking, and using the in-tree emitter rather than the published
SDK artifact. Gate #8 moves the assertion to a release-blocking position against
the artifacts consumers actually install and run. It runs alongside Gate #1
(`readme-snippets`), Gate #2 (`release-verify`), Gate #6 (`schema-conformance`),
and Gate #7 (`byte-identity`); each must pass for a release to be considered
green.
