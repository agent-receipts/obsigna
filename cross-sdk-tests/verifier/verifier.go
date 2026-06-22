// Package verifier is the single entry point that the browser verifier
// (obsigna.dev/verify) and its conformance gate share. It turns pasted or
// loaded receipt text into a verdict by delegating every cryptographic step —
// JCS canonicalization, Ed25519 signature checking, and hash-chain walking — to
// the Go verify core in obsigna.dev/sdk/go/receipt. It deliberately implements
// NONE of those steps itself: the same receipt.VerifyRaw / receipt.VerifyChain
// functions power `obsigna receipt verify`, so the browser and the CLI can never
// drift. The WASM gate (verify_wasm_gate_test.go) compiles this package to
// GOOS=wasip1 GOARCH=wasm and asserts that the compiled output is byte-identical
// to a native call on the full conformance-vector corpus.
//
// Run reads a JSON Request and returns a JSON Result. The result carries TWO
// independent verdicts that are never collapsed into one (spec trust-model):
//
//   - Cryptographic consistency: every signature valid, the hash chain
//     unbroken, canonicalization correct. This is what the Go core proves.
//   - External-anchor trust: a checkpoint/rotation anchor proof corroborates the
//     chain head out of band. Anchor verification (input mode "c") is a tracked
//     follow-up; this build never reports an anchor as trusted, so a
//     cryptographically clean but unanchored chain is a QUALIFIED pass, never a
//     FULL pass.
package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"strings"

	"obsigna.dev/sdk/go/receipt"
)

// Input modes. "single" verifies one receipt's signature; "chain" verifies a
// linked sequence (JSON array or JSONL). The reserved "chain-anchored" mode is
// the tracked follow-up for external-anchor proofs and is not yet evaluated.
const (
	ModeSingle = "single"
	ModeChain  = "chain"
)

// Verdicts. A verdict is never invented by JS — it is computed here from the
// two rings below and round-tripped through WASM unchanged.
const (
	// VerdictFull means cryptographically consistent AND corroborated by a
	// trusted external anchor. Unreachable until anchor verification ships;
	// defined so the type is honest and the UI can render it.
	VerdictFull = "full"
	// VerdictQualified means cryptographically consistent but not externally
	// anchored — "internally consistent; not externally anchored".
	VerdictQualified = "qualified"
	// VerdictFail means the chain is not cryptographically consistent.
	VerdictFail = "fail"
	// VerdictError means the request could not be evaluated (e.g. missing or
	// malformed public key, unparseable input) — distinct from a clean FAIL.
	VerdictError = "error"
)

// Request is the JSON the page hands to Run. Receipts holds the raw pasted text
// exactly as the user supplied it; PublicKey is the PEM-encoded SPKI Ed25519 key
// the signatures are checked against (verification proves consistency *under
// this key*, not real-world identity — the key must be obtained out of band).
type Request struct {
	Mode      string `json:"mode"`
	Receipts  string `json:"receipts"`
	PublicKey string `json:"public_key"`
	// Anchor carries an external anchor proof for the reserved "chain-anchored"
	// mode. Accepted but not yet evaluated; see Anchor.Note in the result.
	Anchor string `json:"anchor,omitempty"`
}

// CryptoRing is the cryptographic-consistency verdict.
type CryptoRing struct {
	Consistent   bool `json:"consistent"`
	ReceiptCount int  `json:"receipt_count"`
	// SignatureValid is set in single-receipt mode only.
	SignatureValid *bool `json:"signature_valid,omitempty"`
	// ReceiptHash is the canonical SHA-256 of the receipt in single mode.
	ReceiptHash string `json:"receipt_hash,omitempty"`
	// Chain is the full per-receipt breakdown from receipt.VerifyChain in chain
	// mode (signature/hash-link/sequence per receipt, warnings, advisories).
	Chain *receipt.ChainVerification `json:"chain,omitempty"`
	// Detail is a short human-readable explanation of a non-consistent result.
	Detail string `json:"detail,omitempty"`
}

// AnchorRing is the external-anchor trust verdict. Until anchor verification
// ships, Supplied may be true (the user pasted a proof) but Checked/Trusted are
// always false.
type AnchorRing struct {
	Supplied bool   `json:"supplied"`
	Checked  bool   `json:"checked"`
	Trusted  bool   `json:"trusted"`
	Note     string `json:"note"`
}

// Result is the JSON Run returns. OK is false only when the request could not be
// evaluated at all (verdict == error).
type Result struct {
	OK        bool       `json:"ok"`
	Error     string     `json:"error,omitempty"`
	Mode      string     `json:"mode"`
	InputKind string     `json:"input_kind"`
	Verdict   string     `json:"verdict"`
	Crypto    CryptoRing `json:"crypto"`
	Anchor    AnchorRing `json:"anchor"`
}

// Run is the one function the WASM module and the gate both call. It never
// panics on bad input: every failure becomes a Result with verdict error/fail.
func Run(reqJSON []byte) []byte {
	var req Request
	if err := json.Unmarshal(reqJSON, &req); err != nil {
		return mustMarshal(errorResult("", "", "invalid request JSON: "+err.Error()))
	}
	return mustMarshal(evaluate(req))
}

func evaluate(req Request) Result {
	mode := req.Mode
	if mode == "" {
		mode = inferMode(req.Receipts)
	}
	inputKind := ModeSingle
	if mode != ModeSingle {
		inputKind = ModeChain
	}

	// Boundary validation: the public key is a trust boundary. Parsing it here
	// (not a verification step — no canonicalization, signature, or hash work)
	// lets us cleanly separate a usage error (bad/absent key → ERROR) from a
	// receipt that genuinely fails to verify (→ FAIL).
	if strings.TrimSpace(req.PublicKey) == "" {
		return errorResult(mode, inputKind,
			"a public key is required: receipt signatures are verified against the issuer's Ed25519 public key, which you must obtain out of band")
	}
	if err := validatePublicKey(req.PublicKey); err != nil {
		return errorResult(mode, inputKind, "invalid public key: "+err.Error())
	}

	anchor := anchorRing(req.Anchor)

	var crypto CryptoRing
	switch inputKind {
	case ModeSingle:
		crypto = verifySingle(req.Receipts, req.PublicKey)
	default:
		var errResult *Result
		crypto, errResult = verifyChain(req.Receipts, req.PublicKey, mode, anchor)
		if errResult != nil {
			return *errResult
		}
	}

	res := Result{
		OK:        true,
		Mode:      mode,
		InputKind: inputKind,
		Crypto:    crypto,
		Anchor:    anchor,
	}
	res.Verdict = verdict(crypto.Consistent, anchor.Trusted)
	return res
}

// verifySingle checks one receipt's signature over its verbatim wire bytes
// (receipt.VerifyRaw) and records its canonical hash. A malformed proof or
// non-object body is a clean FAIL, not an error — the malformed-vector corpus
// requires exactly this rejection.
func verifySingle(text, pubPEM string) CryptoRing {
	raw := bytes.TrimSpace([]byte(text))
	valid, err := receipt.VerifyRaw(raw, pubPEM)
	c := CryptoRing{ReceiptCount: 1, SignatureValid: &valid}
	if h, herr := receipt.HashRawReceipt(raw); herr == nil {
		c.ReceiptHash = h
	}
	switch {
	case err != nil:
		c.Consistent = false
		c.Detail = err.Error()
	case !valid:
		c.Consistent = false
		c.Detail = "signature does not verify under the supplied public key"
	default:
		c.Consistent = true
	}
	return c
}

// verifyChain parses the pasted chain (JSON array or JSONL) and runs it through
// receipt.VerifyChain — the exact function `obsigna receipt verify` uses. A
// parse failure returns an error Result (the input could not be read as a
// chain), distinct from a chain that parses but fails verification (FAIL).
func verifyChain(text, pubPEM, mode string, anchor AnchorRing) (CryptoRing, *Result) {
	receipts, err := parseReceipts(text)
	if err != nil {
		er := errorResult(mode, ModeChain, "could not parse chain: "+err.Error())
		er.Anchor = anchor
		return CryptoRing{}, &er
	}
	cv := receipt.VerifyChain(receipts, pubPEM)
	c := CryptoRing{
		Consistent:   cv.Valid,
		ReceiptCount: len(receipts),
		Chain:        &cv,
	}
	if !cv.Valid && cv.Error != "" {
		c.Detail = cv.Error
	}
	return c, nil
}

// anchorRing reports the external-anchor verdict. Anchor verification is a
// tracked follow-up; a supplied proof is acknowledged but never trusted, so the
// overall verdict can rise to QUALIFIED but never FULL.
func anchorRing(anchorText string) AnchorRing {
	if strings.TrimSpace(anchorText) == "" {
		return AnchorRing{
			Supplied: false,
			Note:     "no external anchor proof supplied — the chain is checked for internal consistency only",
		}
	}
	return AnchorRing{
		Supplied: true,
		Checked:  false,
		Trusted:  false,
		Note:     "external-anchor verification is not available in this build (tracked follow-up); the supplied proof was not evaluated",
	}
}

// verdict folds the two rings into a single label without ever collapsing them:
// FULL needs both, QUALIFIED is consistent-but-unanchored, FAIL is anything not
// cryptographically consistent.
func verdict(cryptoConsistent, anchorTrusted bool) string {
	switch {
	case !cryptoConsistent:
		return VerdictFail
	case anchorTrusted:
		return VerdictFull
	default:
		return VerdictQualified
	}
}

// parseReceipts reads a chain from a JSON array of receipts or from JSONL
// (one receipt object per non-blank line). A lone object is treated as a
// length-1 chain.
func parseReceipts(text string) ([]receipt.AgentReceipt, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, errors.New("input is empty")
	}
	if trimmed[0] == '[' {
		var arr []receipt.AgentReceipt
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, err
		}
		// An empty array is not a chain — reject it like the empty-string and
		// empty-JSONL paths, so "[]" can never read as a vacuous QUALIFIED pass
		// over zero receipts.
		if len(arr) == 0 {
			return nil, errors.New("no receipts found")
		}
		return arr, nil
	}
	// JSONL (or a single object): decode successive JSON values, tolerating
	// blank lines between them.
	dec := json.NewDecoder(strings.NewReader(trimmed))
	var out []receipt.AgentReceipt
	for {
		var r receipt.AgentReceipt
		if err := dec.Decode(&r); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, errors.New("no receipts found")
	}
	return out, nil
}

// inferMode picks a default when the caller omits Mode: a lone JSON object is a
// single receipt; an array or multiple JSONL objects is a chain.
func inferMode(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return ModeSingle
	}
	if trimmed[0] == '[' {
		return ModeChain
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	count := 0
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			break
		}
		count++
		if count > 1 {
			return ModeChain
		}
	}
	return ModeSingle
}

// validatePublicKey checks that pemStr is a PEM-encoded SPKI Ed25519 public key.
// This is input validation at a trust boundary, not a verification step.
func validatePublicKey(pemStr string) error {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return errors.New("not PEM-encoded")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.New("not a valid SPKI public key")
	}
	if _, ok := key.(ed25519.PublicKey); !ok {
		return errors.New("not an Ed25519 key (Ed25519 is the only supported algorithm)")
	}
	return nil
}

func errorResult(mode, inputKind, msg string) Result {
	if inputKind == "" {
		inputKind = ModeSingle
	}
	return Result{
		OK:        false,
		Error:     msg,
		Mode:      mode,
		InputKind: inputKind,
		Verdict:   VerdictError,
		Crypto:    CryptoRing{Consistent: false, Detail: msg},
		Anchor:    AnchorRing{Note: "not evaluated"},
	}
}

func mustMarshal(r Result) []byte {
	b, err := json.Marshal(r)
	if err != nil {
		// Result is a closed struct of marshalable types; a failure here is a
		// programming error, not bad input. Surface it as a minimal valid JSON
		// error rather than panicking inside WASM.
		return []byte(`{"ok":false,"verdict":"error","error":"internal: result marshal failed"}`)
	}
	return b
}
