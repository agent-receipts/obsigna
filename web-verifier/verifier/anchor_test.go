package verifier

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"obsigna.dev/sdk/go/checkpoint"
	"obsigna.dev/sdk/go/receipt"
)

// anchorSigner signs checkpoints with a freshly generated test key (never a
// real key — AGENTS.md security rule).
type anchorSigner struct{ priv ed25519.PrivateKey }

func (s anchorSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }
func (s anchorSigner) VerificationMethod() string      { return "did:anchor#k1" }

func newAnchorKey(t *testing.T) (anchorSigner, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return anchorSigner{priv: priv}, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// buildSignedChain returns a valid chain of count receipts and the issuer's
// public key PEM.
func buildSignedChain(t *testing.T, count int) ([]receipt.AgentReceipt, string) {
	t.Helper()
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	chain := make([]receipt.AgentReceipt, 0, count)
	var prevHash *string
	for i := 1; i <= count; i++ {
		unsigned := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: "did:agent:test"},
			Principal: receipt.Principal{ID: "did:user:test"},
			Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
			Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
			Chain:     receipt.Chain{Sequence: i, PreviousReceiptHash: prevHash, ChainID: "chain-1"},
		})
		signed, err := receipt.Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, signed)
		h, err := receipt.HashReceipt(signed)
		if err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}
	return chain, kp.PublicKey
}

func chainJSON(t *testing.T, chain []receipt.AgentReceipt) string {
	t.Helper()
	b, err := json.Marshal(chain)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func signedCheckpointJSON(t *testing.T, signer anchorSigner, cp checkpoint.Checkpoint) string {
	t.Helper()
	signed, err := checkpoint.Sign(cp, signer)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// headCheckpoint returns a checkpoint committing to the chain's actual head.
func headCheckpoint(t *testing.T, chain []receipt.AgentReceipt) checkpoint.Checkpoint {
	t.Helper()
	head := chain[len(chain)-1]
	h, err := receipt.HashReceipt(head)
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint.Checkpoint{
		ChainID:     head.CredentialSubject.Chain.ChainID,
		Sequence:    int64(head.CredentialSubject.Chain.Sequence),
		ReceiptHash: h,
		Timestamp:   "2026-06-16T00:00:00Z",
	}
}

func run(t *testing.T, req Request) Result {
	t.Helper()
	reqJSON, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(Run(reqJSON), &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func TestAnchorAuthenticMatchingHeadIsFull(t *testing.T) {
	chain, issuerPub := buildSignedChain(t, 3)
	anchorSig, anchorPub := newAnchorKey(t)
	cp := signedCheckpointJSON(t, anchorSig, headCheckpoint(t, chain))

	res := run(t, Request{
		Mode:            ModeChain,
		Receipts:        chainJSON(t, chain),
		PublicKey:       issuerPub,
		Anchor:          cp,
		AnchorPublicKey: anchorPub,
	})

	if res.Verdict != VerdictFull {
		t.Fatalf("verdict = %q, want full (crypto=%v anchor.trusted=%v note=%q)",
			res.Verdict, res.Crypto.Consistent, res.Anchor.Trusted, res.Anchor.Note)
	}
	if !res.Anchor.Supplied || !res.Anchor.Checked || !res.Anchor.Trusted {
		t.Errorf("anchor ring = %+v, want supplied+checked+trusted", res.Anchor)
	}
}

func TestAnchorWrongKeyIsQualified(t *testing.T) {
	chain, issuerPub := buildSignedChain(t, 3)
	anchorSig, _ := newAnchorKey(t)
	_, otherPub := newAnchorKey(t) // evaluate against a DIFFERENT key
	cp := signedCheckpointJSON(t, anchorSig, headCheckpoint(t, chain))

	res := run(t, Request{
		Mode: ModeChain, Receipts: chainJSON(t, chain), PublicKey: issuerPub,
		Anchor: cp, AnchorPublicKey: otherPub,
	})

	if res.Verdict != VerdictQualified {
		t.Fatalf("verdict = %q, want qualified", res.Verdict)
	}
	if res.Anchor.Trusted {
		t.Error("anchor must not be trusted when the checkpoint signature does not verify")
	}
	if !res.Anchor.Checked {
		t.Error("a parseable checkpoint with a key should be marked checked")
	}
}

func TestAnchorHeadHashMismatchIsQualified(t *testing.T) {
	chain, issuerPub := buildSignedChain(t, 3)
	anchorSig, anchorPub := newAnchorKey(t)
	cp := headCheckpoint(t, chain)
	cp.ReceiptHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	res := run(t, Request{
		Mode: ModeChain, Receipts: chainJSON(t, chain), PublicKey: issuerPub,
		Anchor: signedCheckpointJSON(t, anchorSig, cp), AnchorPublicKey: anchorPub,
	})

	if res.Anchor.Trusted {
		t.Fatalf("anchor must not be trusted when the head hash differs (note=%q)", res.Anchor.Note)
	}
	if res.Verdict != VerdictQualified {
		t.Errorf("verdict = %q, want qualified", res.Verdict)
	}
}

func TestAnchorSequenceAheadFlagsTruncation(t *testing.T) {
	chain, issuerPub := buildSignedChain(t, 3)
	anchorSig, anchorPub := newAnchorKey(t)
	cp := headCheckpoint(t, chain)
	cp.Sequence = 5 // anchor witnessed more receipts than the pasted chain has

	res := run(t, Request{
		Mode: ModeChain, Receipts: chainJSON(t, chain), PublicKey: issuerPub,
		Anchor: signedCheckpointJSON(t, anchorSig, cp), AnchorPublicKey: anchorPub,
	})

	if res.Anchor.Trusted {
		t.Fatal("anchor must not be trusted when it commits to a later sequence")
	}
	if got := res.Anchor.Note; got == "" || !contains(got, "truncation") {
		t.Errorf("note %q should flag possible truncation", got)
	}
}

func TestAnchorSuppliedWithoutKeyIsQualified(t *testing.T) {
	chain, issuerPub := buildSignedChain(t, 2)
	anchorSig, _ := newAnchorKey(t)
	cp := signedCheckpointJSON(t, anchorSig, headCheckpoint(t, chain))

	res := run(t, Request{
		Mode: ModeChain, Receipts: chainJSON(t, chain), PublicKey: issuerPub,
		Anchor: cp, // no AnchorPublicKey
	})

	if res.Verdict != VerdictQualified {
		t.Fatalf("verdict = %q, want qualified", res.Verdict)
	}
	if !res.Anchor.Supplied || res.Anchor.Checked || res.Anchor.Trusted {
		t.Errorf("anchor ring = %+v, want supplied but not checked/trusted", res.Anchor)
	}
}

func TestAnchorMalformedProofIsQualified(t *testing.T) {
	chain, issuerPub := buildSignedChain(t, 2)
	_, anchorPub := newAnchorKey(t)

	res := run(t, Request{
		Mode: ModeChain, Receipts: chainJSON(t, chain), PublicKey: issuerPub,
		Anchor: "{ not a checkpoint", AnchorPublicKey: anchorPub,
	})

	if res.Verdict != VerdictQualified {
		t.Fatalf("verdict = %q, want qualified", res.Verdict)
	}
	if res.Anchor.Checked || res.Anchor.Trusted {
		t.Errorf("malformed proof must not be checked/trusted: %+v", res.Anchor)
	}
}

func TestAnchorUnevaluableSignatureNotChecked(t *testing.T) {
	chain, issuerPub := buildSignedChain(t, 2)
	anchorSig, anchorPub := newAnchorKey(t)
	// A checkpoint that parses as JSON but whose signature cannot be evaluated
	// (wrong multibase prefix) — checkpoint.Verify returns an error, so the proof
	// was not actually checked.
	var m map[string]any
	if err := json.Unmarshal([]byte(signedCheckpointJSON(t, anchorSig, headCheckpoint(t, chain))), &m); err != nil {
		t.Fatal(err)
	}
	m["signature"] = "z" + m["signature"].(string)[1:]
	bad, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	res := run(t, Request{
		Mode: ModeChain, Receipts: chainJSON(t, chain), PublicKey: issuerPub,
		Anchor: string(bad), AnchorPublicKey: anchorPub,
	})

	if res.Anchor.Checked {
		t.Error("an unevaluable signature must leave Checked false (not evaluated, not 'not anchored')")
	}
	if !res.Anchor.Supplied || res.Anchor.Trusted {
		t.Errorf("anchor ring = %+v, want supplied, not checked, not trusted", res.Anchor)
	}
	if res.Verdict != VerdictQualified {
		t.Errorf("verdict = %q, want qualified", res.Verdict)
	}
}

func TestErrorResultStillReflectsSuppliedAnchor(t *testing.T) {
	chain, issuerPub := buildSignedChain(t, 2)
	anchorSig, anchorPub := newAnchorKey(t)
	cp := signedCheckpointJSON(t, anchorSig, headCheckpoint(t, chain))

	// Unparseable chain → ERROR verdict, but a pasted proof must still report
	// Supplied (AnchorRing contract), not be silently dropped.
	parseErr := run(t, Request{
		Mode: ModeChain, Receipts: "[ not json", PublicKey: issuerPub,
		Anchor: cp, AnchorPublicKey: anchorPub,
	})
	if parseErr.Verdict != VerdictError {
		t.Fatalf("verdict = %q, want error", parseErr.Verdict)
	}
	if !parseErr.Anchor.Supplied {
		t.Error("chain-parse error dropped Anchor.Supplied for a pasted proof")
	}

	// Missing issuer key → ERROR verdict, same contract.
	keyErr := run(t, Request{Mode: ModeChain, Receipts: chainJSON(t, chain), Anchor: cp, AnchorPublicKey: anchorPub})
	if keyErr.Verdict != VerdictError {
		t.Fatalf("verdict = %q, want error", keyErr.Verdict)
	}
	if !keyErr.Anchor.Supplied {
		t.Error("key error dropped Anchor.Supplied for a pasted proof")
	}
}

func TestNoAnchorStillQualified(t *testing.T) {
	chain, issuerPub := buildSignedChain(t, 3)
	res := run(t, Request{Mode: ModeChain, Receipts: chainJSON(t, chain), PublicKey: issuerPub})
	if res.Verdict != VerdictQualified {
		t.Fatalf("verdict = %q, want qualified", res.Verdict)
	}
	if res.Anchor.Supplied {
		t.Error("anchor should not be marked supplied when none was given")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
