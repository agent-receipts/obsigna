#!/usr/bin/env bash
# Build the obsigna.dev/verify browser verifier.
#
# Compiles the single Go verify core (cross-sdk-tests/cmd/verify-wasm, which
# wraps obsigna.dev/sdk/go/receipt — the same code as `obsigna receipt verify`)
# to GOOS=js GOARCH=wasm and stages it, plus the toolchain's matching
# wasm_exec.js loader, into the site's public dir. The CLI<->WASM conformance
# gate (cross-sdk-tests/verify_wasm_gate_test.go) pins the same wrapper, so the
# deployed binary can never diverge from the verifier the gate checks.
#
# Outputs are generated, not committed (see .gitignore). Run this before
# building/serving site-obsigna locally; CI runs it at deploy time.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
out_dir="$repo_root/site-obsigna/public/verify"

mkdir -p "$out_dir"

echo "building browser verifier -> $out_dir/obsigna-verify.wasm"
( cd "$repo_root/cross-sdk-tests" && GOOS=js GOARCH=wasm go build -trimpath \
    -o "$out_dir/obsigna-verify.wasm" ./cmd/verify-wasm )

# Fail loudly on an empty/truncated artifact rather than deploying a /verify
# page that 404s or fails to instantiate with no CI signal.
if [ ! -s "$out_dir/obsigna-verify.wasm" ]; then
  echo "error: build produced an empty obsigna-verify.wasm" >&2
  exit 1
fi

goroot="$(go env GOROOT)"
wasm_exec="$goroot/lib/wasm/wasm_exec.js"
if [ ! -f "$wasm_exec" ]; then
  wasm_exec="$goroot/misc/wasm/wasm_exec.js"
fi
if [ ! -f "$wasm_exec" ]; then
  echo "error: wasm_exec.js not found under $goroot (lib/wasm or misc/wasm)" >&2
  exit 1
fi
cp "$wasm_exec" "$out_dir/wasm_exec.js"

size="$(wc -c < "$out_dir/obsigna-verify.wasm" | tr -d ' ')"
echo "done: obsigna-verify.wasm (${size} bytes) + wasm_exec.js"
