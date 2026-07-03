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

// frozenContext and frozenVersion pin the wire form of the base receipts to the
// spec version the corpus was frozen at (v0.2.0 / context v1). receipt.Create
// defaults to the current SDK version, which has since advanced; without these
// overrides a regeneration would rewrite the @context and version of the frozen
// cases (and therefore their signatures). Pinning them keeps the existing cases
// byte-identical across regenerations while new cases share the same wire form.
var frozenContext = []string{
	"https://www.w3.org/ns/credentials/v2",
	"https://agentreceipts.ai/context/v1",
}

const frozenVersion = "0.2.0"

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
	Name string `json:"name"`
	// Clause names the normative spec section the case enforces, so a reviewer
	// can trace each MUST-reject vector to the requirement it guards. Rendered
	// as the "Enforces" column on the conformance page (via count.py).
	Clause      string          `json:"clause"`
	Description string          `json:"description"`
	Receipt     json.RawMessage `json:"receipt"`
}

type chainCase struct {
	Name        string            `json:"name"`
	Clause      string            `json:"clause"`
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
			"§4.3.3 proof — type MUST be Ed25519Signature2020",
			"proof.type changed from Ed25519Signature2020 to RsaSignature2018; verifiers MUST reject any other proof type (the field lives outside the signed bytes, so the Ed25519 signature still checks — this case guards the explicit type check in verify)",
			mutateProofType(signedBase, "RsaSignature2018")),

		mustCase("mutated_action_type",
			"§7.8 End-to-end receipt verification — signature over canonical bytes",
			"action.type changed after signing — canonical bytes no longer match the signature",
			mutateActionType(signedBase, "filesystem.file.delete")),

		mustCase("mutated_principal_id",
			"§7.8 End-to-end receipt verification — signature over canonical bytes",
			"principal.id changed after signing — payload tampering",
			mutatePrincipalID(signedBase, "did:user:attacker")),

		mustCase("truncated_proof_value",
			"§7.8 End-to-end receipt verification — signature over canonical bytes",
			"signature truncated to its multibase prefix only — empty signature bytes",
			mutateProofValue(signedBase, "u")),

		mustCase("wrong_multibase_prefix",
			"§4.3.3 proof — proofValue is u-prefixed base64url",
			"proof.proofValue uses 'z' (base58) instead of 'u' (base64url) — Ed25519Signature2020 mandates base64url",
			swapMultibasePrefix(signedBase, "z")),

		mustCase("flipped_proof_byte",
			"§7.8 End-to-end receipt verification — signature over canonical bytes",
			"single byte of proofValue replaced — Ed25519 verification MUST fail on any single-bit mutation",
			flipProofByte(signedBase)),

		rawCase("schema_missing_required_field",
			"§4.3.2 credentialSubject — chain.chain_id is required",
			"chain.chain_id (a schema-required field) removed from an otherwise-valid signed receipt — a schema-invalid receipt every verifier MUST reject. Verifiers that schema-validate reject it at parse time, before the signature check; removing a signed field also breaks the Ed25519 signature, so a verify-only path rejects it too",
			removeChainField(signedBase, "chain_id")),
	}

	chainCases := []chainCase{
		mustChainCase("missing_previous_receipt_hash_mid_chain",
			"§7.3 Chain integrity verification — hash linkage (previous_receipt_hash)",
			"middle receipt is missing chain.previous_receipt_hash, breaking the hash linkage",
			buildBrokenChain(ts.Keys.PrivateKey)),

		mustChainCase("chain_wrong_previous_receipt_hash",
			"§7.3 Chain integrity verification — hash linkage (previous_receipt_hash)",
			"last receipt's chain.previous_receipt_hash is the valid hash of the genesis receipt (a different receipt in the set) instead of its immediate predecessor — well-formed linkage pointing at the wrong predecessor. Distinct from the missing case; each receipt is individually signed and verifiable, so only the chain hash-linkage check fails",
			buildWrongPrevHashChain(ts.Keys.PrivateKey)),

		mustChainCase("chain_duplicate_sequence",
			"§7.3.5 Sequence number contiguity and store trust — sequence MUST equal predecessor + 1",
			"two receipts under one chain_id share sequence 2 (fork / equivocation); each receipt is individually signed and hash-linked, so only the strict-contiguity check fails",
			buildDuplicateSequenceChain(ts.Keys.PrivateKey)),

		mustChainCase("chain_sequence_gap",
			"§7.3.5 Sequence number contiguity and store trust — sequence MUST equal predecessor + 1",
			"sequences run 1, 2, 4 with a gap at 3; each receipt is individually signed and hash-linked, so only the strict-contiguity check fails (spec §7.3.5 mandates contiguity, not merely strictly-increasing)",
			buildSequenceGapChain(ts.Keys.PrivateKey)),
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
	r.Context = frozenContext
	r.Version = frozenVersion

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
		r.Context = frozenContext
		r.Version = frozenVersion

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

// newChainReceipt builds one unsigned chain receipt with the frozen wire form,
// used by the chain-negative builders below. The defect (wrong prev hash,
// duplicate/gapped sequence) is baked into the Chain input BEFORE signing so the
// signature stays valid and only the targeted chain check fails — a stronger
// test than relying on a broken signature to reject the case.
func newChainReceipt(seq int, prev *string, chainID, actionID, id string) receipt.UnsignedAgentReceipt {
	r := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: "did:agent:malformed-test"},
		Principal: receipt.Principal{ID: "did:user:alice"},
		Action: receipt.Action{
			Type:      "filesystem.file.read",
			RiskLevel: receipt.RiskLow,
		},
		Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
		Chain: receipt.Chain{
			Sequence:            seq,
			PreviousReceiptHash: prev,
			ChainID:             chainID,
		},
	})
	r.ID = id
	r.IssuanceDate = fixedTimestamp
	r.CredentialSubject.Action.ID = actionID
	r.CredentialSubject.Action.Timestamp = fixedTimestamp
	r.Context = frozenContext
	r.Version = frozenVersion
	return r
}

// signChainReceipt signs an unsigned chain receipt with the shared key and
// stamps the fixed proof timestamp.
func signChainReceipt(r receipt.UnsignedAgentReceipt, privateKey string) receipt.AgentReceipt {
	signed, err := receipt.Sign(r, privateKey, "did:agent:malformed-test#key-1")
	if err != nil {
		fail("sign chain receipt: %v", err)
	}
	signed.Proof.Created = fixedTimestamp
	return signed
}

func hashOrFail(r receipt.AgentReceipt) string {
	h, err := receipt.HashReceipt(r)
	if err != nil {
		fail("hash chain receipt: %v", err)
	}
	return h
}

// buildWrongPrevHashChain builds a 3-receipt chain whose last receipt points its
// chain.previous_receipt_hash at the genesis receipt (index 0) rather than its
// immediate predecessor (index 1). Every receipt is individually signed and
// verifiable; only the chain hash-linkage check fails. Distinct from
// missing_previous_receipt_hash_mid_chain (which nulls the field).
func buildWrongPrevHashChain(privateKey string) []receipt.AgentReceipt {
	const chainID = "chain_malformed_wrong_prev"
	chain := make([]receipt.AgentReceipt, 0, 3)
	hashes := make([]string, 0, 3)
	var prev *string
	for i := 1; i <= 3; i++ {
		linkTo := prev
		if i == 3 {
			// Point at the genesis receipt's hash — a valid hash of a DIFFERENT
			// receipt in the set — instead of the immediate predecessor's.
			wrong := hashes[0]
			linkTo = &wrong
		}
		id := fmt.Sprintf("urn:receipt:00000000-0000-4000-8000-00000000001%d", i)
		r := newChainReceipt(i, linkTo, chainID, fmt.Sprintf("act_wrong_prev_%d", i), id)
		signed := signChainReceipt(r, privateKey)
		chain = append(chain, signed)
		h := hashOrFail(signed)
		hashes = append(hashes, h)
		prev = &h
	}
	return chain
}

// buildDuplicateSequenceChain builds a 3-receipt chain in which the third
// receipt reuses sequence 2 (fork / equivocation under one chain_id). Hash
// linkage to the immediate predecessor stays correct, so only the strict
// sequence-contiguity check fails.
func buildDuplicateSequenceChain(privateKey string) []receipt.AgentReceipt {
	const chainID = "chain_malformed_dup_seq"
	sequences := []int{1, 2, 2}
	return buildSequencedChain(privateKey, chainID, "dup_seq", sequences)
}

// buildSequenceGapChain builds a 3-receipt chain whose sequences run 1, 2, 4 —
// a gap at 3. Hash linkage stays correct, so only the strict contiguity check
// fails. Exercises spec §7.3.5's contiguity mandate (not merely
// strictly-increasing).
func buildSequenceGapChain(privateKey string) []receipt.AgentReceipt {
	const chainID = "chain_malformed_seq_gap"
	sequences := []int{1, 2, 4}
	return buildSequencedChain(privateKey, chainID, "seq_gap", sequences)
}

// buildSequencedChain signs a hash-linked chain whose receipts carry the given
// sequence numbers verbatim. Each receipt links to the actual hash of its
// predecessor, so hash linkage is valid regardless of the sequence values —
// isolating the sequence check as the sole reason a non-contiguous chain fails.
func buildSequencedChain(privateKey, chainID, actionPrefix string, sequences []int) []receipt.AgentReceipt {
	chain := make([]receipt.AgentReceipt, 0, len(sequences))
	var prev *string
	for i, seq := range sequences {
		id := fmt.Sprintf("urn:receipt:00000000-0000-4000-8000-00000000002%d", i+1)
		r := newChainReceipt(seq, prev, chainID, fmt.Sprintf("act_%s_%d", actionPrefix, i+1), id)
		signed := signChainReceipt(r, privateKey)
		chain = append(chain, signed)
		h := hashOrFail(signed)
		prev = &h
	}
	return chain
}

// removeChainField marshals a signed receipt and deletes one field from its
// credentialSubject.chain object at the JSON layer, producing a schema-invalid
// receipt no typed AgentReceipt can express (the Go struct always carries the
// field). Verifiers MUST reject a receipt missing a schema-required chain field.
func removeChainField(base receipt.AgentReceipt, field string) json.RawMessage {
	body, err := json.Marshal(base)
	if err != nil {
		fail("marshal for field removal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		fail("unmarshal for field removal: %v", err)
	}
	cs, ok := m["credentialSubject"].(map[string]any)
	if !ok {
		fail("removeChainField: credentialSubject not an object")
	}
	chain, ok := cs["chain"].(map[string]any)
	if !ok {
		fail("removeChainField: chain not an object")
	}
	if _, present := chain[field]; !present {
		fail("removeChainField: field %q not present to remove", field)
	}
	delete(chain, field)
	out, err := json.Marshal(m)
	if err != nil {
		fail("re-marshal after field removal: %v", err)
	}
	return out
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

func mustCase(name, clause, desc string, r receipt.AgentReceipt) receiptCase {
	body, err := json.Marshal(r)
	if err != nil {
		fail("marshal case %s: %v", name, err)
	}
	return receiptCase{Name: name, Clause: clause, Description: desc, Receipt: body}
}

// rawCase builds a receipt-level case from an already-serialised body. Used for
// cases that mutate the receipt at the JSON layer (e.g. removing a required
// field), where no typed AgentReceipt can express the malformation.
func rawCase(name, clause, desc string, body json.RawMessage) receiptCase {
	return receiptCase{Name: name, Clause: clause, Description: desc, Receipt: body}
}

func mustChainCase(name, clause, desc string, receipts []receipt.AgentReceipt) chainCase {
	out := make([]json.RawMessage, len(receipts))
	for i, r := range receipts {
		body, err := json.Marshal(r)
		if err != nil {
			fail("marshal chain case %s receipt %d: %v", name, i, err)
		}
		out[i] = body
	}
	return chainCase{Name: name, Clause: clause, Description: desc, Receipts: out}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
