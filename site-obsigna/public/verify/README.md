# obsigna.dev/verify — client-side receipt-chain verifier

A standalone, fully client-side page that verifies an Agent Receipts chain in the
browser. Nothing the user pastes is uploaded, stored, or sent anywhere; after the
page and its WebAssembly module load, it makes no network requests.

## How it stays honest

- **One verification implementation.** The cryptographic checks
  (JCS/RFC 8785 canonicalization, Ed25519 signature verification, hash-chain
  walking) run in `obsigna-verify.wasm`, compiled from the `web-verifier`
  module (`web-verifier/cmd/wasm`), which wraps `obsigna.dev/sdk/go/receipt` —
  the same core as the `obsigna receipt verify` CLI. There is no JavaScript
  reimplementation of any verification step; `verify.js` only marshals input and
  renders output.
- **CLI ↔ WASM identity gate.** `cross-sdk-tests/verify_wasm_gate_test.go`
  (`go test -tags=integration`) runs every conformance vector through both the
  native core and the compiled WASM and asserts byte-identical results, so the
  browser verifier can never drift from the CLI.
- **Two verdicts, never collapsed.** Cryptographic consistency and
  external-anchor trust are reported separately. A cryptographically consistent
  but unanchored chain is a *qualified* pass, visually distinct from a *full*
  pass. External-anchor verification is a tracked follow-up and is not yet
  evaluated.

## Files

| File | Source | Committed? |
|------|--------|-----------|
| `index.html`, `styles.css`, `verify.js` | hand-written UI (no verification logic) | yes |
| `examples.js` | public test fixtures from `cross-sdk-tests/v0*_vectors.json` | yes |
| `obsigna-verify.wasm` | built from `web-verifier/cmd/wasm` | **no — generated** |
| `wasm_exec.js` | copied from the Go toolchain (`$GOROOT/lib/wasm/`) | **no — generated** |

The two generated files are produced fresh from source at build/deploy time (see
`.gitignore`) so the deployed binary always matches the verifier in the gate.

## Building locally

From the repo root:

```sh
scripts/build-verify-wasm.sh        # writes obsigna-verify.wasm + wasm_exec.js here
cd site-obsigna && pnpm dev         # serve at /verify
```

CI runs `scripts/build-verify-wasm.sh` before the site build (see
`.github/workflows/site-obsigna.yml`).

## Smoke-testing the built artifact

`scripts/build-verify-wasm.sh` then a Node loader (`wasm_exec.js` runs under Node)
can exercise the exact browser binary; the authoritative check is the Go gate
above.
