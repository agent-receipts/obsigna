// Package verifier is the single entry point that the browser verifier
// (obsigna.dev/verify) and its conformance gate share. It turns pasted or
// loaded receipt text into a verdict by delegating every cryptographic step —
// JCS canonicalization, Ed25519 signature checking, and hash-chain walking — to
// the Go verify core in obsigna.dev/sdk/go/receipt. It deliberately implements
// NONE of those steps itself: the same receipt.VerifyRaw / receipt.VerifyChain
// functions power `obsigna receipt verify`, so the browser and the CLI can never
// drift. The conformance gate (in cross-sdk-tests) compiles this package to
// GOOS=wasip1 GOARCH=wasm and asserts that the compiled output is byte-identical
// to a native call on the full conformance-vector corpus.
//
// Run reads a JSON Request and returns a JSON Result. The result carries TWO
// independent verdicts that are never collapsed into one (spec trust-model):
//
//   - Cryptographic consistency: every signature valid, the hash chain
//     unbroken, canonicalization correct. This is what the Go core proves.
//   - External-anchor trust: a signed checkpoint corroborates the chain head out
//     of band. When a checkpoint proof and its anchor key are supplied, the
//     checkpoint signature is verified and bound to the observed head; an
//     authentic, matching checkpoint makes the chain a FULL pass. A
//     cryptographically clean but unanchored chain is a QUALIFIED pass.
package verifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"obsigna.dev/sdk/go/checkpoint"
	"obsigna.dev/sdk/go/receipt"
)

// Input modes. "single" verifies one receipt's signature; "chain" verifies a
// linked sequence (JSON array or JSONL).
const (
	ModeSingle = "single"
	ModeChain  = "chain"
)

// Verdicts. A verdict is never invented by JS — it is computed here from the
// two rings below and round-tripped through WASM unchanged.
const (
	// VerdictFull means cryptographically consistent AND corroborated by a
	// trusted external anchor — a signed checkpoint that verifies under the
	// supplied anchor key and commits to this exact chain head.
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
	// Anchor carries an external anchor proof: the JSON of a signed checkpoint
	// (checkpoint.Signed) committing to a chain head. When supplied alongside
	// AnchorPublicKey it is verified and bound to the observed chain head; an
	// authentic, matching checkpoint raises the verdict from qualified to full.
	Anchor string `json:"anchor,omitempty"`
	// AnchorPublicKey is the PEM/SPKI Ed25519 key the checkpoint signature is
	// checked against. It may differ from the receipt issuer key — anchoring is
	// out-of-band, so the anchor key is obtained and trusted separately.
	AnchorPublicKey string `json:"anchor_public_key,omitempty"`
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

// AnchorRing is the external-anchor trust verdict. Supplied is true when the
// user pasted a proof; Checked is true once the checkpoint signature was
// evaluated; Trusted is true only when that checkpoint is authentic AND commits
// to the observed chain head.
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
		return mustMarshal(errorResult("", "", "", "invalid request JSON: "+err.Error()))
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
	// receipt that genuinely fails to verify (→ FAIL). receipt.ParsePublicKey is
	// the SDK's single shared parser for the only key format the protocol accepts.
	if strings.TrimSpace(req.PublicKey) == "" {
		return errorResult(mode, inputKind, req.Anchor,
			"a public key is required: receipt signatures are verified against the issuer's Ed25519 public key, which you must obtain out of band")
	}
	if _, err := receipt.ParsePublicKey(req.PublicKey); err != nil {
		return errorResult(mode, inputKind, req.Anchor, "invalid public key: "+err.Error())
	}

	// The observed chain head — its canonical hash, sequence, and chain id — is
	// what a supplied checkpoint is bound against. Captured per mode below.
	var (
		crypto      CryptoRing
		headHash    string
		headSeq     int
		headChainID string
		haveHead    bool
	)
	switch inputKind {
	case ModeSingle:
		crypto = verifySingle(req.Receipts, req.PublicKey)
		headHash = crypto.ReceiptHash
		if seq, chainID, ok := singleHead(req.Receipts); ok {
			headSeq, headChainID, haveHead = seq, chainID, true
		}
	default:
		var errResult *Result
		var receipts []receipt.AgentReceipt
		crypto, receipts, errResult = verifyChain(req.Receipts, req.PublicKey, mode, req.Anchor)
		if errResult != nil {
			return *errResult
		}
		if len(receipts) > 0 {
			head := receipts[len(receipts)-1]
			if h, err := receipt.HashReceipt(head); err == nil {
				headHash = h
			}
			headSeq = head.CredentialSubject.Chain.Sequence
			headChainID = head.CredentialSubject.Chain.ChainID
			haveHead = true
		}
	}

	anchor := evaluateAnchor(req.Anchor, req.AnchorPublicKey, headHash, headSeq, headChainID, haveHead)

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

// singleHead parses a single receipt for the chain-position fields a checkpoint
// binds against. A parse failure is not fatal here — verifySingle already turns
// a malformed body into a FAIL; this only means an anchor cannot be bound.
func singleHead(text string) (seq int, chainID string, ok bool) {
	var r receipt.AgentReceipt
	if err := json.Unmarshal(bytes.TrimSpace([]byte(text)), &r); err != nil {
		return 0, "", false
	}
	return r.CredentialSubject.Chain.Sequence, r.CredentialSubject.Chain.ChainID, true
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
func verifyChain(text, pubPEM, mode, anchorText string) (CryptoRing, []receipt.AgentReceipt, *Result) {
	receipts, err := parseReceipts(text)
	if err != nil {
		er := errorResult(mode, ModeChain, anchorText, "could not parse chain: "+err.Error())
		return CryptoRing{}, nil, &er
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
	return c, receipts, nil
}

// evaluateAnchor reports the external-anchor verdict. When a checkpoint proof
// and an anchor public key are supplied, it verifies the checkpoint signature
// (checkpoint.Verify) and binds the authenticated checkpoint to the observed
// chain head: same chain id, same head sequence, same head receipt hash. Only a
// proof that is both authentic AND commits to this exact head sets Trusted —
// which is what lifts the verdict to FULL.
//
// The anchor ring is independent of the crypto ring (spec trust-model). An
// authentic checkpoint that matches the head is Trusted even when an earlier
// receipt breaks the chain: that honestly reports "this head was anchored" while
// the crypto ring separately reports the break (and verdict() still yields FAIL).
func evaluateAnchor(anchorText, anchorKeyPEM, headHash string, headSeq int, headChainID string, haveHead bool) AnchorRing {
	if strings.TrimSpace(anchorText) == "" {
		return AnchorRing{
			Supplied: false,
			Note:     "no external anchor proof supplied — the chain is checked for internal consistency only",
		}
	}
	ring := AnchorRing{Supplied: true}
	if strings.TrimSpace(anchorKeyPEM) == "" {
		ring.Note = "an anchor public key is required to evaluate the supplied checkpoint proof; the proof was not evaluated"
		return ring
	}
	var signed checkpoint.Signed
	if err := json.Unmarshal([]byte(anchorText), &signed); err != nil {
		ring.Note = "anchor proof is not a valid signed checkpoint: " + err.Error()
		return ring
	}
	ok, err := checkpoint.Verify(signed, anchorKeyPEM)
	if err != nil {
		// The signature could not be evaluated at all (malformed signature, bad
		// PEM): leave Checked false so the ring reads "not evaluated", not a
		// misleading "not anchored".
		ring.Note = "checkpoint proof could not be evaluated: " + err.Error()
		return ring
	}
	ring.Checked = true
	if !ok {
		ring.Note = "checkpoint signature does not verify under the supplied anchor public key"
		return ring
	}
	// Signature is authentic; bind it to the observed chain head.
	switch {
	case !haveHead:
		ring.Note = "checkpoint is authentic but the chain head could not be read to bind it"
	case signed.ChainID != headChainID:
		ring.Note = fmt.Sprintf("checkpoint anchors chain %q but the receipts are chain %q", signed.ChainID, headChainID)
	case signed.Sequence != int64(headSeq):
		ring.Note = fmt.Sprintf("checkpoint anchors sequence %d but the chain head is sequence %d — possible tail truncation or a stale anchor", signed.Sequence, headSeq)
	case signed.ReceiptHash != headHash:
		ring.Note = "checkpoint head hash does not match the chain head receipt hash"
	default:
		ring.Trusted = true
		ring.Note = "checkpoint is authentic and commits to this exact chain head"
	}
	return ring
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

// errorResult builds an ERROR verdict (the request could not be evaluated).
// anchorText is the request's anchor proof: an unevaluable request does not
// evaluate the anchor either, but Supplied still reflects whether the user
// pasted a proof so the AnchorRing contract holds.
func errorResult(mode, inputKind, anchorText, msg string) Result {
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
		Anchor:    AnchorRing{Supplied: strings.TrimSpace(anchorText) != "", Note: "not evaluated"},
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
