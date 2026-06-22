//go:build wasip1

// Command verify-wasm-cli is the WASI build of the same verifier the browser
// runs. It reads a request JSON from stdin and writes the result JSON to stdout.
// The conformance gate (verify_wasm_gate_test.go) executes this binary under
// wazero and asserts its output is byte-identical to a native verifier.Run call
// on every conformance vector — that identity is what lets the browser claim it
// runs the same verifier as the CLI.
package main

import (
	"io"
	"os"

	"obsigna.dev/cross-sdk-tests/verifier"
)

func main() {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Stderr.WriteString("read stdin: " + err.Error())
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(verifier.Run(in)); err != nil {
		os.Stderr.WriteString("write stdout: " + err.Error())
		os.Exit(1)
	}
}
