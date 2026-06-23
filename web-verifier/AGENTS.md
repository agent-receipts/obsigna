# AGENTS.md

The browser receipt-chain verifier behind **obsigna.dev/verify**. This module is
the single source of the verification logic that runs in the browser; it is
compiled to WebAssembly and shipped as a static page.

## Layout

```
verifier/        # package verifier: Run(reqJSON) -> resultJSON, the shared core.
                 # Delegates ALL crypto (JCS, Ed25519, hash-chain) to
                 # obsigna.dev/sdk/go/receipt — it reimplements nothing.
cmd/wasm/        # GOOS=js GOARCH=wasm browser entry (syscall/js shim).
cmd/wasm-cli/    # GOOS=wasip1 GOARCH=wasm stdin/stdout entry, run by the gate.
```

## Build & test

```sh
go vet ./...        # mains are wasm-only, excluded on host (no error)
go build ./...
# Browser artifact (also done by scripts/build-verify-wasm.sh at deploy):
GOOS=js GOARCH=wasm go build ./cmd/wasm
```

The verifier has no tests of its own. Its behavior is pinned by the
**CLI↔WASM conformance gate** in `cross-sdk-tests/verify_wasm_gate_test.go`,
which compiles `cmd/wasm-cli` and asserts byte-identical output against a native
`verifier.Run` call over the whole conformance-vector corpus. The page lives in
`site-obsigna/public/verify/`.

## Conventions

- Local `obsigna.dev/sdk/go` is wired via the repo-root `go.work`; never add a
  local `replace` directive.
- This module must never gain a second verification implementation — the Go core
  in `sdk/go/receipt` is the only one. If a mode needs something the core lacks,
  file a follow-up rather than reimplementing it here.
