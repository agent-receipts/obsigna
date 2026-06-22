//go:build integration

package crosssdk_test

// Conformance gate for the browser verifier (obsigna.dev/verify).
//
// It compiles cmd/verify-wasm-cli to GOOS=wasip1 GOARCH=wasm — the same
// verifier.Run that the GOOS=js GOARCH=wasm browser build runs — executes it
// under wazero, and asserts its output is BYTE-IDENTICAL to a native
// verifier.Run call on every conformance vector. Both paths delegate to the Go
// verify core (obsigna.dev/sdk/go/receipt), so this gate is what lets the
// browser claim it runs the same verifier as `obsigna receipt verify`: any
// drift between the WASM and native paths fails CI here.
//
// The gate also pins the expected verdict per vector (valid corpus → QUALIFIED,
// malformed corpus → FAIL) so it proves the verifier is correct, not merely
// self-consistent.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"

	"obsigna.dev/cross-sdk-tests/verifier"
)

// request mirrors verifier.Request without importing it as the public wire
// contract: the gate builds requests exactly as the page does.
type request struct {
	Mode      string `json:"mode"`
	Receipts  string `json:"receipts"`
	PublicKey string `json:"public_key"`
}

// nonMatchingPublicKey is a fixed, well-known test Ed25519 public key that is
// NOT the keypair the shared vectors were signed with (all vector files share
// one keypair, per cross-sdk-tests/README.md). It exercises the "valid receipt,
// wrong key → FAIL" path. Public key only; no private key exists for it here.
const nonMatchingPublicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA7pmHrwjW2vI5/0n1c0HsEjb1w2IL4iMYPM4LwzKjhYw=
-----END PUBLIC KEY-----
`

type gateCase struct {
	name        string
	mode        string
	receipts    string
	publicKey   string
	wantVerdict string
	wantOK      bool
}

func TestWASMVerifierMatchesNativeCore(t *testing.T) {
	runner := newWASMRunner(t)
	cases := loadGateCases(t)
	if len(cases) == 0 {
		t.Fatal("no conformance cases discovered — vector loading is broken")
	}
	t.Logf("running %d conformance cases through native + WASM verifier", len(cases))

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reqJSON, err := json.Marshal(request{Mode: c.mode, Receipts: c.receipts, PublicKey: c.publicKey})
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}

			native := verifier.Run(reqJSON)
			wasm := runner.run(t, reqJSON)

			// The load-bearing assertion: the deployed verifier and the native
			// core must produce identical bytes, or "run it yourself" is a lie.
			if !bytes.Equal(native, wasm) {
				t.Fatalf("WASM and native results differ\n native: %s\n wasm:   %s", native, wasm)
			}

			var got verifier.Result
			if err := json.Unmarshal(native, &got); err != nil {
				t.Fatalf("unmarshal result: %v (raw: %s)", err, native)
			}
			if got.OK != c.wantOK {
				t.Errorf("ok = %v, want %v (detail: %s)", got.OK, c.wantOK, got.Crypto.Detail)
			}
			if got.Verdict != c.wantVerdict {
				t.Errorf("verdict = %q, want %q (detail: %s)", got.Verdict, c.wantVerdict, got.Crypto.Detail)
			}
			// A passing chain in this build must never be FULL: an unanchored
			// chain is QUALIFIED, never fully trusted.
			if got.Verdict == verifier.VerdictFull {
				t.Errorf("verdict FULL produced without anchor verification — unanchored chains must be QUALIFIED")
			}
		})
	}
}

// loadGateCases assembles the corpus: valid signed receipts and a valid chain
// (→ QUALIFIED), the malformed receipt/chain corpus (→ FAIL), and a handful of
// request-level edge cases (→ ERROR/FAIL).
func loadGateCases(t *testing.T) []gateCase {
	t.Helper()
	var cases []gateCase

	// Valid signed receipts, single-receipt mode. go_vectors.signing.signed is
	// the canonical signed receipt; the version-pinned files contribute their
	// own signed receipts via dynamic discovery.
	goPub, goSigned := loadGoSigned(t)
	cases = append(cases, gateCase{
		name: "valid/go_vectors-signed", mode: verifier.ModeSingle,
		receipts: goSigned, publicKey: goPub,
		wantVerdict: verifier.VerdictQualified, wantOK: true,
	})

	for _, f := range []string{"v020_vectors.json", "v030_vectors.json", "v040_vectors.json", "v050_vectors.json"} {
		pub, singles, chains := discoverReceipts(t, f)
		// Guard against coverage silently vanishing: if a vector file is
		// restructured so discoverReceipts finds nothing, fail rather than
		// quietly testing fewer vectors.
		if len(singles)+len(chains) == 0 {
			t.Fatalf("no receipts discovered in %s — vector loader is out of date", f)
		}
		for name, raw := range singles {
			cases = append(cases, gateCase{
				name: "valid/" + f + "/" + name, mode: verifier.ModeSingle,
				receipts: raw, publicKey: pub,
				wantVerdict: verifier.VerdictQualified, wantOK: true,
			})
		}
		for name, raw := range chains {
			cases = append(cases, gateCase{
				name: "valid/" + f + "/" + name + "-chain", mode: verifier.ModeChain,
				receipts: raw, publicKey: pub,
				wantVerdict: verifier.VerdictQualified, wantOK: true,
			})
		}
	}

	// Malformed corpus — every entry MUST be rejected (FAIL, but OK: the
	// verifier evaluated it and found it inconsistent).
	mPub, mReceipts, mChains := loadMalformed(t)
	for _, c := range mReceipts {
		cases = append(cases, gateCase{
			name: "malformed/receipt/" + c.name, mode: verifier.ModeSingle,
			receipts: c.raw, publicKey: mPub,
			wantVerdict: verifier.VerdictFail, wantOK: true,
		})
	}
	for _, c := range mChains {
		cases = append(cases, gateCase{
			name: "malformed/chain/" + c.name, mode: verifier.ModeChain,
			receipts: c.raw, publicKey: mPub,
			wantVerdict: verifier.VerdictFail, wantOK: true,
		})
	}

	// Request-level edge cases: missing/garbage key is a usage ERROR; a valid
	// receipt under the wrong key is a clean FAIL.
	cases = append(cases,
		gateCase{name: "edge/missing-key", mode: verifier.ModeSingle, receipts: goSigned, publicKey: "", wantVerdict: verifier.VerdictError, wantOK: false},
		gateCase{name: "edge/garbage-key", mode: verifier.ModeSingle, receipts: goSigned, publicKey: "not a key", wantVerdict: verifier.VerdictError, wantOK: false},
		gateCase{name: "edge/wrong-key", mode: verifier.ModeSingle, receipts: goSigned, publicKey: nonMatchingPublicKey, wantVerdict: verifier.VerdictFail, wantOK: true},
		gateCase{name: "edge/empty-chain", mode: verifier.ModeChain, receipts: "   ", publicKey: goPub, wantVerdict: verifier.VerdictError, wantOK: false},
		gateCase{name: "edge/empty-array", mode: verifier.ModeChain, receipts: "[]", publicKey: goPub, wantVerdict: verifier.VerdictError, wantOK: false},
	)

	return cases
}

// --- vector loading helpers ---

type keyed struct {
	Keys struct {
		PublicKey string `json:"publicKey"`
	} `json:"keys"`
}

func readVector(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

func publicKey(t *testing.T, data []byte, name string) string {
	t.Helper()
	var k keyed
	if err := json.Unmarshal(data, &k); err != nil {
		t.Fatalf("parse keys in %s: %v", name, err)
	}
	if k.Keys.PublicKey == "" {
		t.Fatalf("%s has no keys.publicKey", name)
	}
	return k.Keys.PublicKey
}

func loadGoSigned(t *testing.T) (pub, signed string) {
	t.Helper()
	data := readVector(t, "go_vectors.json")
	var v struct {
		Signing struct {
			Signed json.RawMessage `json:"signed"`
		} `json:"signing"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse go_vectors signing: %v", err)
	}
	return publicKey(t, data, "go_vectors.json"), string(v.Signing.Signed)
}

// discoverReceipts walks the top-level fields of a valid vector file and returns
// every single signed receipt (object with a "receipt" key) and every chain
// (object with a "receipts" key), as raw JSON text.
func discoverReceipts(t *testing.T, name string) (pub string, singles, chains map[string]string) {
	t.Helper()
	data := readVector(t, name)
	pub = publicKey(t, data, name)
	singles = map[string]string{}
	chains = map[string]string{}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	for field, raw := range top {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			continue // not an object (e.g. version string)
		}
		if r, ok := obj["receipt"]; ok {
			singles[field] = string(r)
		}
		if rs, ok := obj["receipts"]; ok {
			chains[field] = string(rs)
		}
	}
	return pub, singles, chains
}

type namedRaw struct {
	name string
	raw  string
}

func loadMalformed(t *testing.T) (pub string, receipts, chains []namedRaw) {
	t.Helper()
	data := readVector(t, "malformed_vectors.json")
	pub = publicKey(t, data, "malformed_vectors.json")
	var v struct {
		Receipts []struct {
			Name    string          `json:"name"`
			Receipt json.RawMessage `json:"receipt"`
		} `json:"receipts"`
		Chains []struct {
			Name     string          `json:"name"`
			Receipts json.RawMessage `json:"receipts"`
		} `json:"chains"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse malformed_vectors.json: %v", err)
	}
	for _, r := range v.Receipts {
		receipts = append(receipts, namedRaw{r.Name, string(r.Receipt)})
	}
	for _, c := range v.Chains {
		chains = append(chains, namedRaw{c.Name, string(c.Receipts)})
	}
	return pub, receipts, chains
}

// --- WASM runner (wazero over the wasip1 build) ---

type wasmRunner struct {
	ctx     context.Context
	runtime wazero.Runtime
	code    wazero.CompiledModule
	counter atomic.Int64
}

func newWASMRunner(t *testing.T) *wasmRunner {
	t.Helper()

	wasmPath := filepath.Join(t.TempDir(), "verify-wasm-cli.wasm")
	build := exec.Command("go", "build", "-trimpath", "-o", wasmPath, "./cmd/verify-wasm-cli")
	build.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build wasip1 verifier: %v\n%s", err, out)
	}

	wasmBytes, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("read built wasm: %v", err)
	}

	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)
	code, err := rt.CompileModule(ctx, wasmBytes)
	if err != nil {
		t.Fatalf("compile wasm: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close(ctx) })

	return &wasmRunner{ctx: ctx, runtime: rt, code: code}
}

// run executes the wasip1 verifier once: input on stdin, result on stdout. A Go
// wasip1 module runs main to completion per instantiation, so each call gets a
// fresh module with a unique name.
func (w *wasmRunner) run(t *testing.T, input []byte) []byte {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cfg := wazero.NewModuleConfig().
		WithName("verify-" + strconv.FormatInt(w.counter.Add(1), 10)).
		WithStdin(bytes.NewReader(input)).
		WithStdout(&stdout).
		WithStderr(&stderr).
		WithArgs("verify")

	mod, err := w.runtime.InstantiateModule(w.ctx, w.code, cfg)
	if err != nil {
		var exit *sys.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 0 {
			t.Fatalf("instantiate wasm: %v\nstderr: %s", err, stderr.String())
		}
	} else {
		_ = mod.Close(w.ctx)
	}
	if stderr.Len() > 0 {
		t.Fatalf("wasm wrote to stderr: %s", stderr.String())
	}
	return stdout.Bytes()
}
