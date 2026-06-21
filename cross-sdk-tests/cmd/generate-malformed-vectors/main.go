// generate-malformed-vectors writes malformed_vectors.json — a shared corpus
// of invalid receipts and chains that all three SDKs MUST reject identically.
//
// Without a shared rejection corpus, each SDK's tampering tests run in
// isolation: a regression in one SDK that silently accepts a malformed proof
// (e.g. wrong multibase prefix) wouldn't fail any cross-SDK check.
//
// Receipt-level cases live in `receipts[]` and exercise Verify on a single
// receipt; chain-level cases live in `chains[]` and exercise VerifyChain
// over an ordered list. The JSON array a case lives in IS the discriminator
// — there is no per-case `mode` field, and adding one would only duplicate
// what the surrounding key already says.
//
// Usage: go run ./cmd/generate-malformed-vectors
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"obsigna.dev/sdk/go/receipt"
)

const fixedTimestamp = "2026-04-22T00:00:00Z"

type malformedVectors struct {
	Description string        `json:"description"`
	Keys        keysSection   `json:"keys"`
	Receipts    []receiptCase `json:"receipts"`
	Chains      []chainCase   `json:"chains"`
}

type keysSection struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

type receiptCase struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Receipt     json.RawMessage `json:"receipt"`
}

type chainCase struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Receipts    []json.RawMessage `json:"receipts"`
}

func main() {
	// Use the shared keypair from ts_vectors.json so all three SDKs verify
	// against the same key.
	tsData, err := os.ReadFile("../sdk/py/tests/fixtures/ts_vectors.json")
	if err != nil {
		fail("read ts_vectors.json: %v", err)
	}
	var ts struct {
		Keys keysSection `json:"keys"`
	}
	if err := json.Unmarshal(tsData, &ts); err != nil {
		fail("parse ts_vectors.json: %v", err)
	}

	signedBase, err := signSample(ts.Keys.PrivateKey)
	if err != nil {
		fail("sign sample: %v", err)
	}

	receiptCases := []receiptCase{
		mustCase("wrong_proof_type",
			"proof.type changed from Ed25519Signature2020 to RsaSignature2018; verifiers MUST reject any other proof type (the field lives outside the signed bytes, so the Ed25519 signature still checks — this case guards the explicit type check in verify)",
			mutateProofType(signedBase, "RsaSignature2018")),

		mustCase("mutated_action_type",
			"action.type changed after signing — canonical bytes no longer match the signature",
			mutateActionType(signedBase, "filesystem.file.delete")),

		mustCase("mutated_principal_id",
			"principal.id changed after signing — payload tampering",
			mutatePrincipalID(signedBase, "did:user:attacker")),

		mustCase("truncated_proof_value",
			"signature truncated to its multibase prefix only — empty signature bytes",
			mutateProofValue(signedBase, "u")),

		mustCase("wrong_multibase_prefix",
			"proof.proofValue uses 'z' (base58) instead of 'u' (base64url) — Ed25519Signature2020 mandates base64url",
			swapMultibasePrefix(signedBase, "z")),

		mustCase("flipped_proof_byte",
			"single byte of proofValue replaced — Ed25519 verification MUST fail on any single-bit mutation",
			flipProofByte(signedBase)),
	}

	chainCases := []chainCase{
		mustChainCase("missing_previous_receipt_hash_mid_chain",
			"middle receipt is missing chain.previous_receipt_hash, breaking the hash linkage",
			buildBrokenChain(ts.Keys.PrivateKey)),
	}

	out := malformedVectors{
		Description: "Shared corpus of receipts and chains that every SDK MUST reject. " +
			"The base receipt is signed in-process by signSample() (not loaded from go_vectors.json), " +
			"then each named case mutates one field of that base. " +
			"All cases use the same Ed25519 keypair as the other cross-SDK vectors.",
		Keys:     ts.Keys,
		Receipts: receiptCases,
		Chains:   chainCases,
	}

	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fail("marshal output: %v", err)
	}
	if err := os.WriteFile("malformed_vectors.json", append(body, '\n'), 0o644); err != nil {
		fail("write malformed_vectors.json: %v", err)
	}
	fmt.Println("wrote malformed_vectors.json")
}

func signSample(privateKey string) (receipt.AgentReceipt, error) {
	r := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: "did:agent:malformed-test"},
		Principal: receipt.Principal{ID: "did:user:alice"},
		Action: receipt.Action{
			Type:      "filesystem.file.read",
			RiskLevel: receipt.RiskLow,
		},
		Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
		Chain: receipt.Chain{
			Sequence: 1,
			ChainID:  "chain_malformed_base",
		},
	})
	r.ID = "urn:receipt:00000000-0000-4000-8000-000000000001"
	r.IssuanceDate = fixedTimestamp
	r.CredentialSubject.Action.ID = "act_malformed_1"
	r.CredentialSubject.Action.Timestamp = fixedTimestamp

	signed, err := receipt.Sign(r, privateKey, "did:agent:malformed-test#key-1")
	if err != nil {
		return receipt.AgentReceipt{}, err
	}
	signed.Proof.Created = fixedTimestamp
	return signed, nil
}

func mutateProofType(base receipt.AgentReceipt, newType string) receipt.AgentReceipt {
	out := cloneReceipt(base)
	out.Proof.Type = newType
	return out
}

func mutateActionType(base receipt.AgentReceipt, newType string) receipt.AgentReceipt {
	out := cloneReceipt(base)
	out.CredentialSubject.Action.Type = newType
	return out
}

func mutatePrincipalID(base receipt.AgentReceipt, newID string) receipt.AgentReceipt {
	out := cloneReceipt(base)
	out.CredentialSubject.Principal.ID = newID
	return out
}

func mutateProofValue(base receipt.AgentReceipt, newValue string) receipt.AgentReceipt {
	out := cloneReceipt(base)
	out.Proof.ProofValue = newValue
	return out
}

func swapMultibasePrefix(base receipt.AgentReceipt, newPrefix string) receipt.AgentReceipt {
	out := cloneReceipt(base)
	if len(out.Proof.ProofValue) > 0 {
		out.Proof.ProofValue = newPrefix + out.Proof.ProofValue[1:]
	}
	return out
}

func flipProofByte(base receipt.AgentReceipt) receipt.AgentReceipt {
	out := cloneReceipt(base)
	pv := []byte(out.Proof.ProofValue)
	// Flip one base64url char near the middle (skip the multibase prefix at
	// index 0). Swap 'A' for 'B', any other char for 'A' — the goal is a
	// guaranteed-different byte that is still valid base64url.
	if len(pv) > 5 {
		idx := len(pv) / 2
		if pv[idx] == 'A' {
			pv[idx] = 'B'
		} else {
			pv[idx] = 'A'
		}
	}
	out.Proof.ProofValue = string(pv)
	return out
}

func buildBrokenChain(privateKey string) []receipt.AgentReceipt {
	chain := make([]receipt.AgentReceipt, 0, 3)
	var prev *string
	for i := 1; i <= 3; i++ {
		r := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: "did:agent:malformed-test"},
			Principal: receipt.Principal{ID: "did:user:alice"},
			Action: receipt.Action{
				Type:      "filesystem.file.read",
				RiskLevel: receipt.RiskLow,
			},
			Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
			Chain: receipt.Chain{
				Sequence:            i,
				PreviousReceiptHash: prev,
				ChainID:             "chain_malformed_broken",
			},
		})
		r.ID = fmt.Sprintf("urn:receipt:00000000-0000-4000-8000-00000000000%d", i+1)
		r.IssuanceDate = fixedTimestamp
		r.CredentialSubject.Action.ID = fmt.Sprintf("act_malformed_chain_%d", i)
		r.CredentialSubject.Action.Timestamp = fixedTimestamp

		signed, err := receipt.Sign(r, privateKey, "did:agent:malformed-test#key-1")
		if err != nil {
			fail("sign chain receipt %d: %v", i, err)
		}
		signed.Proof.Created = fixedTimestamp

		// Drop the link on receipt 2 to break chain integrity. The receipt
		// is still individually signed and verifiable, but chain verification
		// MUST fail.
		if i == 2 {
			signed.CredentialSubject.Chain.PreviousReceiptHash = nil
		}

		chain = append(chain, signed)
		h, err := receipt.HashReceipt(signed)
		if err != nil {
			fail("hash chain receipt %d: %v", i, err)
		}
		prev = &h
	}
	return chain
}

func cloneReceipt(in receipt.AgentReceipt) receipt.AgentReceipt {
	body, err := json.Marshal(in)
	if err != nil {
		fail("clone marshal: %v", err)
	}
	var out receipt.AgentReceipt
	if err := json.Unmarshal(body, &out); err != nil {
		fail("clone unmarshal: %v", err)
	}
	return out
}

func mustCase(name, desc string, r receipt.AgentReceipt) receiptCase {
	body, err := json.Marshal(r)
	if err != nil {
		fail("marshal case %s: %v", name, err)
	}
	return receiptCase{Name: name, Description: desc, Receipt: body}
}

func mustChainCase(name, desc string, receipts []receipt.AgentReceipt) chainCase {
	out := make([]json.RawMessage, len(receipts))
	for i, r := range receipts {
		body, err := json.Marshal(r)
		if err != nil {
			fail("marshal chain case %s receipt %d: %v", name, i, err)
		}
		out[i] = body
	}
	return chainCase{Name: name, Description: desc, Receipts: out}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
