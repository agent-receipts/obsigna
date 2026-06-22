//go:build js && wasm

// Command verify-wasm is the browser entry point for obsigna.dev/verify. It is a
// thin syscall/js shim over verifier.Run: the page calls the global
// obsignaVerify(requestJSON) and gets back the result JSON. All verification
// happens in verifier.Run (which delegates to the obsigna.dev/sdk/go/receipt
// core); this file adds no cryptographic logic.
package main

import (
	"syscall/js"

	"obsigna.dev/cross-sdk-tests/verifier"
)

func main() {
	js.Global().Set("obsignaVerify", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			return `{"ok":false,"verdict":"error","error":"obsignaVerify: missing request argument"}`
		}
		return string(verifier.Run([]byte(args[0].String())))
	}))
	// Park the Go runtime so the exported function stays callable for the life
	// of the page.
	select {}
}
