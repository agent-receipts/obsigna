// generate-vectors is the build script for the pinned cross-SDK test vectors.
// All outputs share a single Ed25519 keypair loaded from the test fixtures so
// that signature bytes can be compared across SDKs.
//
// Outputs:
//   - go_vectors.json — signs the unsigned receipt from ts_vectors.json with
//     the Go SDK; pairs with py_vectors.json / ts_vectors.json to assert
//     byte-identical signatures across the three SDKs at v0.2.x.
//   - v020_vectors.json — pinned v0.2.0 / v0.2.1 fixtures (legacy flat-map
//     parameters_disclosure shape, no envelope).
//   - v030_vectors.json — pinned v0.3.0 fixtures exercising the new
//     envelope-shape parameters_disclosure plus the peer_credential and
//     emitter_metadata typed action fields. Independently constructed
//     (NOT derived from ts_vectors.json); reuses only the shared keypair.
//
// Usage: go run ./cmd/generate-vectors
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"obsigna.dev/sdk/go/receipt"
)

type vectors struct {
	Keys             keysSection             `json:"keys"`
	Canonicalization canonicalizationSection `json:"canonicalization"`
	Hashing          hashingSection          `json:"hashing"`
	Signing          signingSection          `json:"signing"`
}

type keysSection struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

type canonicalizationSection struct {
	SimpleInput     any    `json:"simpleInput"`
	SimpleExpected  string `json:"simpleExpected"`
	ReceiptInput    any    `json:"receiptInput"`
	ReceiptExpected string `json:"receiptExpected"`
}

type hashingSection struct {
	SimpleInput     string `json:"simpleInput"`
	SimpleExpected  string `json:"simpleExpected"`
	ReceiptExpected string `json:"receiptExpected"`
}

type signingSection struct {
	Unsigned           json.RawMessage `json:"unsigned"`
	Signed             json.RawMessage `json:"signed"`
	VerificationMethod string          `json:"verificationMethod"`
}

// v020Vectors holds ADR-0008 cross-SDK test vectors.
type v020Vectors struct {
	Version                     string                             `json:"version"`
	Keys                        keysSection                        `json:"keys"`
	ResponseHash                responseHashSection                `json:"responseHash"`
	TerminalChain               terminalChainSection               `json:"terminalChain"`
	ParametersDisclosureReceipt parametersDisclosureReceiptSection `json:"parametersDisclosureReceipt"`
}

type responseHashSection struct {
	RawResponse      map[string]any `json:"rawResponse"`
	RedactedResponse map[string]any `json:"redactedResponse"`
	ExpectedHash     string         `json:"expectedHash"`
}

type terminalChainSection struct {
	Receipts                         []json.RawMessage `json:"receipts"`
	ExpectedValid                    bool              `json:"expectedValid"`
	ExpectedValidWithRequireTerminal bool              `json:"expectedValidWithRequireTerminal"`
}

// parametersDisclosureReceiptSection holds a single 0.2.1 signed receipt with
// parameters_disclosure populated. All three SDKs MUST canonicalise, hash, and
// verify it identically (per ADR-0012 Phase A).
type parametersDisclosureReceiptSection struct {
	Description         string          `json:"description"`
	Receipt             json.RawMessage `json:"receipt"`
	ExpectedReceiptHash string          `json:"expectedReceiptHash"`
	ExpectedValid       bool            `json:"expectedValid"`
}

func main() {
	// Read the TS vectors to get the shared keypair and unsigned receipt.
	// Resolve paths relative to the module root (cross-sdk-tests/) so this
	// works when invoked as `go run ./cmd/generate-vectors` from there.
	tsData, err := os.ReadFile("../sdk/py/tests/fixtures/ts_vectors.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read ts_vectors.json: %v\n", err)
		os.Exit(1)
	}

	var tsVectors vectors
	if err := json.Unmarshal(tsData, &tsVectors); err != nil {
		fmt.Fprintf(os.Stderr, "parse ts_vectors.json: %v\n", err)
		os.Exit(1)
	}

	// Parse the unsigned receipt into the Go SDK type.
	var unsigned receipt.UnsignedAgentReceipt
	if err := json.Unmarshal(tsVectors.Signing.Unsigned, &unsigned); err != nil {
		fmt.Fprintf(os.Stderr, "parse unsigned receipt: %v\n", err)
		os.Exit(1)
	}

	// Canonicalize the simple input and receipt input.
	simpleCanonical, err := receipt.Canonicalize(tsVectors.Canonicalization.SimpleInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "canonicalize simple: %v\n", err)
		os.Exit(1)
	}

	receiptCanonical, err := receipt.Canonicalize(tsVectors.Canonicalization.ReceiptInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "canonicalize receipt: %v\n", err)
		os.Exit(1)
	}

	// Hash.
	simpleHash := receipt.SHA256Hash(tsVectors.Hashing.SimpleInput)

	// Sign the unsigned receipt with the Go SDK.
	signed, err := receipt.Sign(unsigned, tsVectors.Keys.PrivateKey, tsVectors.Signing.VerificationMethod)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign receipt: %v\n", err)
		os.Exit(1)
	}

	// Hash the signed receipt.
	receiptHash, err := receipt.HashReceipt(signed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash receipt: %v\n", err)
		os.Exit(1)
	}

	// Build the Go vectors output.
	signedJSON, err := json.Marshal(signed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal signed: %v\n", err)
		os.Exit(1)
	}

	goVectors := vectors{
		Keys: tsVectors.Keys,
		Canonicalization: canonicalizationSection{
			SimpleInput:     tsVectors.Canonicalization.SimpleInput,
			SimpleExpected:  simpleCanonical,
			ReceiptInput:    tsVectors.Canonicalization.ReceiptInput,
			ReceiptExpected: receiptCanonical,
		},
		Hashing: hashingSection{
			SimpleInput:     tsVectors.Hashing.SimpleInput,
			SimpleExpected:  simpleHash,
			ReceiptExpected: receiptHash,
		},
		Signing: signingSection{
			Unsigned:           tsVectors.Signing.Unsigned,
			Signed:             json.RawMessage(signedJSON),
			VerificationMethod: tsVectors.Signing.VerificationMethod,
		},
	}

	out, err := json.MarshalIndent(goVectors, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal output: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile("go_vectors.json", append(out, '\n'), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write go_vectors.json: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("wrote go_vectors.json")

	// --- v0.2.0 vectors ---
	if err := generateV020Vectors(tsVectors.Keys); err != nil {
		fmt.Fprintf(os.Stderr, "generate v020 vectors: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("wrote v020_vectors.json")

	// --- v0.3.0 vectors ---
	if err := generateV030Vectors(tsVectors.Keys); err != nil {
		fmt.Fprintf(os.Stderr, "generate v030 vectors: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("wrote v030_vectors.json")

	// --- v0.4.0 vectors ---
	if err := generateV040Vectors(tsVectors.Keys); err != nil {
		fmt.Fprintf(os.Stderr, "generate v040 vectors: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("wrote v040_vectors.json")

	// --- v0.5.0 vectors ---
	if err := generateV050Vectors(tsVectors.Keys); err != nil {
		fmt.Fprintf(os.Stderr, "generate v050 vectors: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("wrote v050_vectors.json")
}

// generateV020Vectors builds and writes v020_vectors.json using the shared keypair
// from ts_vectors.json (passed in as keys).
//
// Fields that Create/Sign populate from the clock and the UUID package are
// overridden with fixed values so the output is byte-identical across runs.
// This keeps the checked-in test vector stable (no spurious diffs on
// regeneration) and makes the file usable as a signature-level cross-SDK
// oracle. Ed25519 is deterministic (RFC 8032), so identical signed bytes
// plus identical key produce identical proofValue.
func generateV020Vectors(keys keysSection) error {
	const fixedTimestamp = "2026-04-22T00:00:00Z"

	// Response hash vectors: redact → canonicalize → SHA-256.
	rawResponse := map[string]any{
		"result":   "ok",
		"password": "super-secret-value",
	}
	redactedResponse := map[string]any{
		"result":   "ok",
		"password": "[REDACTED]",
	}
	redactedJSON, err := json.Marshal(redactedResponse)
	if err != nil {
		return fmt.Errorf("marshal redacted: %w", err)
	}
	canonical, err := receipt.Canonicalize(redactedResponse)
	if err != nil {
		return fmt.Errorf("canonicalize redacted: %w", err)
	}
	expectedHash := receipt.SHA256Hash(canonical)

	// Build a 3-receipt terminal chain using the shared key.
	var prevHash *string
	terminalReceipts := make([]receipt.AgentReceipt, 0, 3)
	for i := 1; i <= 3; i++ {
		isTerminal := i == 3
		r := receipt.Create(receipt.CreateInput{
			Issuer:       receipt.Issuer{ID: "did:agent:test"},
			Principal:    receipt.Principal{ID: "did:user:test"},
			Action:       receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
			Outcome:      receipt.Outcome{Status: receipt.StatusSuccess},
			Chain:        receipt.Chain{Sequence: i, PreviousReceiptHash: prevHash, ChainID: "chain_v020_test"},
			ResponseBody: redactedJSON,
			Terminal:     isTerminal,
		})
		// Override Create-assigned non-deterministic fields (UUIDs, timestamps).
		r.ID = fmt.Sprintf("urn:receipt:v020-terminal-%d", i)
		r.IssuanceDate = fixedTimestamp
		r.CredentialSubject.Action.ID = fmt.Sprintf("act_v020_%d", i)
		r.CredentialSubject.Action.Timestamp = fixedTimestamp
		// Pin the protocol version: this is a *v0.2.0* fixture, so it must not
		// drift to whatever the SDK's current Version constant is (Create stamps
		// that). Without this, every protocol bump silently rewrites the pinned
		// v020 vector and its signatures.
		r.Version = "0.2.0"
		// Pin the JSON-LD context for the same reason: Create stamps the SDK's
		// current context (v2 since ADR-0026), but a v0.2.0 receipt references
		// context v1. Without this, a context bump rewrites the pinned vector.
		r.Context = []string{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"}

		s, err := receipt.Sign(r, keys.PrivateKey, "did:agent:test#key-1")
		if err != nil {
			return fmt.Errorf("sign receipt %d: %w", i, err)
		}
		// proof.created is outside the signed payload — safe to fix afterwards.
		s.Proof.Created = fixedTimestamp

		terminalReceipts = append(terminalReceipts, s)
		h, err := receipt.HashReceipt(s)
		if err != nil {
			return fmt.Errorf("hash receipt %d: %w", i, err)
		}
		prevHash = &h
	}

	// Verify the chain to confirm it's valid.
	verResult := receipt.VerifyChain(terminalReceipts, keys.PublicKey)
	if !verResult.Valid {
		return fmt.Errorf("generated terminal chain failed verification: %s", verResult.Error)
	}

	// Marshal receipts.
	receiptJSONs := make([]json.RawMessage, len(terminalReceipts))
	for i, r := range terminalReceipts {
		b, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal receipt %d: %w", i, err)
		}
		receiptJSONs[i] = json.RawMessage(b)
	}

	// Single-receipt parameters_disclosure vector (ADR-0012 Phase A, schema 0.2.1).
	// Built standalone (not part of the legacy 0.2.0 chain), signed with the same
	// shared key, deterministic via fixed timestamps and UUID overrides. Built
	// as map[string]any because the Go SDK can no longer construct the legacy
	// flat-map parameters_disclosure shape through its typed API after the
	// v0.3.0 envelope migration.
	pdReceiptJSON, pdHash, err := generateParametersDisclosureReceipt(keys)
	if err != nil {
		return fmt.Errorf("generate parameters_disclosure receipt: %w", err)
	}

	v020 := v020Vectors{
		Version: "0.2.0",
		Keys:    keys,
		ResponseHash: responseHashSection{
			RawResponse:      rawResponse,
			RedactedResponse: redactedResponse,
			ExpectedHash:     expectedHash,
		},
		TerminalChain: terminalChainSection{
			Receipts:                         receiptJSONs,
			ExpectedValid:                    true,
			ExpectedValidWithRequireTerminal: true,
		},
		ParametersDisclosureReceipt: parametersDisclosureReceiptSection{
			Description:         "Single 0.2.1 signed receipt with action.parameters_disclosure populated. All three SDKs MUST verify the signature and reproduce expectedReceiptHash byte-for-byte (ADR-0012 Phase A; ADR-0009 canonicalisation).",
			Receipt:             pdReceiptJSON,
			ExpectedReceiptHash: pdHash,
			ExpectedValid:       true,
		},
	}

	out, err := json.MarshalIndent(v020, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal v020 vectors: %w", err)
	}
	return os.WriteFile("v020_vectors.json", append(out, '\n'), 0644)
}

// generateParametersDisclosureReceipt builds a deterministic single-receipt
// vector (schema 0.2.1) with action.parameters_disclosure populated as the
// *legacy flat-map* shape, signs it with the shared private key, and returns
// the signed receipt JSON and its hash.
//
// The Go SDK's typed Action.ParametersDisclosure dropped support for the
// legacy flat-map shape during the v0.3.0 envelope migration (ADR-0012
// amendment 2026-05-18); this generator therefore builds the receipt as a
// map[string]any and signs it directly via crypto/ed25519, mirroring how
// generateV030Vectors handles the new envelope shape. The v020 fixture stays
// pinned for cross-SDK signature-preservation coverage even though the Go
// SDK can no longer construct it through its typed API.
//
// The receipt deliberately uses a fresh chain (chain_pd_test, sequence 1) so
// it cannot be confused with the legacy 0.2.0 terminalChain — that chain
// stays frozen as the signature-preservation oracle.
func generateParametersDisclosureReceipt(keys keysSection) (json.RawMessage, string, error) {
	const fixedTimestamp = "2026-04-22T00:00:00Z"

	unsigned := map[string]any{
		"@context":     []any{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"},
		"id":           "urn:receipt:v021-pd-1",
		"type":         []any{"VerifiableCredential", "AgentReceipt"},
		"version":      "0.2.1",
		"issuer":       map[string]any{"id": "did:agent:test"},
		"issuanceDate": fixedTimestamp,
		"credentialSubject": map[string]any{
			"principal": map[string]any{"id": "did:user:test"},
			"action": map[string]any{
				"id":         "act_v021_pd_1",
				"type":       "filesystem.file.read",
				"risk_level": "low",
				"parameters_disclosure": map[string]any{
					"command": "echo build",
					"user":    "ci",
				},
				"timestamp": fixedTimestamp,
			},
			"outcome": map[string]any{"status": "success"},
			"chain": map[string]any{
				"sequence":              1,
				"previous_receipt_hash": nil,
				"chain_id":              "chain_pd_test",
			},
		},
	}

	signed, hash, err := signAndHashMap(unsigned, keys, fixedTimestamp)
	if err != nil {
		return nil, "", err
	}
	return signed, hash, nil
}

// --- v0.3.0 vector generation ---
//
// The v0.3.0 receipt shape introduces three new typed fields on action:
//   - parameters_disclosure as the HPKE envelope (spec/schema parametersDisclosureEnvelope)
//   - peer_credential (OS-attested daemon ↔ SDK boundary metadata)
//   - emitter_metadata (drop_count for synthetic events_dropped receipts)
//
// The Go SDK Action struct still types parameters_disclosure as
// map[string]string (changing that is PR-C's scope, not PR-B). To keep PR-B's
// diff scoped to vectors only, the v030 receipts are built as map[string]any
// trees, signed directly with ed25519 (replicating the SDK's PEM-parse +
// sign-the-JCS-bytes flow), and hashed via the SDK's Canonicalize + SHA256.
//
// The envelope bytes come from spec/test-vectors/disclosure-envelope/vectors.json
// vector-1, which the Go SDK already pins byte-for-byte in
// sdk/go/receipt/disclosure_test.go:TestDeterministicVector1 — so cross-SDK
// reproduction of the same envelope (RFC 9180 §A.1.1 ikmE → Alice public key)
// is verified there, and these vectors just embed the result.

// v030Vectors is the top-level structure of v030_vectors.json.
//
// Mirrors the legacy v020_vectors.json layout (top-level metadata + named
// receipt sections) so the cross-SDK harness can be wired in the same pattern
// across Go, TS, and Py.
type v030Vectors struct {
	Comment        string                       `json:"$comment"`
	Version        string                       `json:"version"`
	Keys           keysSection                  `json:"keys"`
	Envelope       envelopeReceiptSection       `json:"parametersDisclosureEnvelopeReceipt"`
	DaemonAttested daemonAttestedReceiptSection `json:"peerCredentialEmitterMetadataReceipt"`
	RootCred       daemonAttestedReceiptSection `json:"peerCredentialRootReceipt"`
}

type envelopeReceiptSection struct {
	Description          string          `json:"description"`
	EnvelopeSourceVector string          `json:"envelopeSourceVector"`
	Receipt              json.RawMessage `json:"receipt"`
	ExpectedReceiptHash  string          `json:"expectedReceiptHash"`
	ExpectedValid        bool            `json:"expectedValid"`
}

type daemonAttestedReceiptSection struct {
	Description         string          `json:"description"`
	Receipt             json.RawMessage `json:"receipt"`
	ExpectedReceiptHash string          `json:"expectedReceiptHash"`
	ExpectedValid       bool            `json:"expectedValid"`
}

// Pinned envelope from spec/test-vectors/disclosure-envelope/vectors.json
// (vector-1, RFC 9180 §A.1.1 ikmE encrypting to RFC 7748 §6.1 Alice). The Go
// SDK reproduces this byte-for-byte in
// sdk/go/receipt/disclosure_test.go:TestDeterministicVector1; TS and Py do the
// same in their HPKE tests. Embedding the result here lets the receipt-level
// vector remain deterministic without rerunning HPKE at generation time.
var vector1Envelope = map[string]any{
	"v":   "1",
	"alg": "hpke-x25519-hkdf-sha256-aes-256-gcm",
	"recipients": []any{
		map[string]any{
			"kid": "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQUQUaHL9XJ7Z5W#enc-1",
			"enc": "N_2jVnvb1ijohmjDyNfpfR0SU7bU6m1EwVD3QfG_RDE",
		},
	},
	"ct": "YGn3i4NpiZxHjeZVggTP8lTxb0ZVdLl-2HjW31qsvo28PjQ_Lt_UQgAMidEXjzwhJPHM7OM",
}

func generateV030Vectors(keys keysSection) error {
	const fixedTimestamp = "2026-05-21T00:00:00Z"

	// --- envelope-shape receipt ---
	envelopeUnsigned := map[string]any{
		"@context":     []any{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"},
		"id":           "urn:receipt:030e0030-0000-4030-a030-000000000001",
		"type":         []any{"VerifiableCredential", "AgentReceipt"},
		"version":      "0.3.0",
		"issuer":       map[string]any{"id": "did:agent:test"},
		"issuanceDate": fixedTimestamp,
		"credentialSubject": map[string]any{
			"principal": map[string]any{"id": "did:user:test"},
			"action": map[string]any{
				"id":                    "act_030e0030-0000-4030-a030-000000000001",
				"type":                  "system.command.execute",
				"risk_level":            "high",
				"parameters_disclosure": vector1Envelope,
				"timestamp":             fixedTimestamp,
			},
			"outcome": map[string]any{"status": "success"},
			"chain": map[string]any{
				"sequence":              1,
				"previous_receipt_hash": nil,
				"chain_id":              "chain_v030_envelope_test",
			},
		},
	}
	envelopeSigned, envelopeHash, err := signAndHashMap(envelopeUnsigned, keys, fixedTimestamp)
	if err != nil {
		return fmt.Errorf("envelope receipt: %w", err)
	}

	// --- peer_credential + emitter_metadata receipt ---
	// Synthetic events_dropped style: daemon-attested peer metadata plus
	// drop_count emitter metadata. Uses POSIX-style values (linux peer) so
	// uid/gid are present; Windows daemons would omit those.
	daemonUnsigned := map[string]any{
		"@context":     []any{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"},
		"id":           "urn:receipt:030e0030-0000-4030-a030-000000000002",
		"type":         []any{"VerifiableCredential", "AgentReceipt"},
		"version":      "0.3.0",
		"issuer":       map[string]any{"id": "did:agent:test"},
		"issuanceDate": fixedTimestamp,
		"credentialSubject": map[string]any{
			"principal": map[string]any{"id": "did:user:test"},
			"action": map[string]any{
				"id":         "act_030e0030-0000-4030-a030-000000000002",
				"type":       "system.events_dropped",
				"risk_level": "low",
				"peer_credential": map[string]any{
					"platform": "linux",
					"pid":      12345,
					"uid":      1000,
					"gid":      1000,
					"exe_path": "/usr/local/bin/some-tool",
				},
				"emitter_metadata": map[string]any{
					"drop_count": 3,
				},
				"timestamp": fixedTimestamp,
			},
			"outcome": map[string]any{"status": "success"},
			"chain": map[string]any{
				"sequence":              1,
				"previous_receipt_hash": nil,
				"chain_id":              "chain_v030_daemon_test",
			},
		},
	}
	daemonSigned, daemonHash, err := signAndHashMap(daemonUnsigned, keys, fixedTimestamp)
	if err != nil {
		return fmt.Errorf("daemon-attested receipt: %w", err)
	}

	// --- peer_credential root receipt (uid=0, gid=0) ---
	// Exercises the *uint32 fix for issue #511: root process identity (UID 0)
	// must serialise as `"uid":0` in all three SDKs, not be silently dropped by
	// omitempty.
	rootUnsigned := map[string]any{
		"@context":     []any{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"},
		"id":           "urn:receipt:030e0030-0000-4030-a030-000000000003",
		"type":         []any{"VerifiableCredential", "AgentReceipt"},
		"version":      "0.3.0",
		"issuer":       map[string]any{"id": "did:agent:test"},
		"issuanceDate": fixedTimestamp,
		"credentialSubject": map[string]any{
			"principal": map[string]any{"id": "did:user:test"},
			"action": map[string]any{
				"id":         "act_030e0030-0000-4030-a030-000000000003",
				"type":       "system.command.execute",
				"risk_level": "high",
				"peer_credential": map[string]any{
					"platform": "linux",
					"pid":      1,
					"uid":      0,
					"gid":      0,
					"exe_path": "/sbin/init",
				},
				"timestamp": fixedTimestamp,
			},
			"outcome": map[string]any{"status": "success"},
			"chain": map[string]any{
				"sequence":              1,
				"previous_receipt_hash": nil,
				"chain_id":              "chain_v030_root_test",
			},
		},
	}
	rootSigned, rootHash, err := signAndHashMap(rootUnsigned, keys, fixedTimestamp)
	if err != nil {
		return fmt.Errorf("root peer-cred receipt: %w", err)
	}

	out := v030Vectors{
		Comment: "Cross-SDK v0.3.0 test vectors: pins (a) the HPKE envelope shape of action.parameters_disclosure (ADR-0012 amendment 2026-05-18, spec PR #496) and (b) the daemon-attested action.peer_credential / action.emitter_metadata fields (ADR-0010). All three SDKs MUST verify the signatures and reproduce expectedReceiptHash byte-for-byte. Envelope bytes come from spec/test-vectors/disclosure-envelope/vectors.json vector-1 (RFC 9180 §A.1.1 ikmE encrypting to RFC 7748 §6.1 Alice).",
		Version: "0.3.0",
		Keys:    keys,
		Envelope: envelopeReceiptSection{
			Description:          "Signed v0.3.0 receipt whose action.parameters_disclosure carries the HPKE asymmetric envelope (ADR-0012 amendment). Envelope bytes are vector-1 from spec/test-vectors/disclosure-envelope/vectors.json — deterministic against RFC 9180 §A.1.1.",
			EnvelopeSourceVector: "spec/test-vectors/disclosure-envelope/vectors.json#vector-1-single-recipient-small-payload",
			Receipt:              envelopeSigned,
			ExpectedReceiptHash:  envelopeHash,
			ExpectedValid:        true,
		},
		DaemonAttested: daemonAttestedReceiptSection{
			Description:         "Signed v0.3.0 receipt exercising the daemon-attested typed fields: action.peer_credential (linux POSIX peer metadata) and action.emitter_metadata.drop_count (synthetic events_dropped semantics per ADR-0010).",
			Receipt:             daemonSigned,
			ExpectedReceiptHash: daemonHash,
			ExpectedValid:       true,
		},
		RootCred: daemonAttestedReceiptSection{
			Description:         "Signed v0.3.0 receipt with peer_credential.uid=0 and gid=0 (root). Pins that the zero value is present on the wire (`\"uid\":0`) and not silently dropped by omitempty — fixes issue #511.",
			Receipt:             rootSigned,
			ExpectedReceiptHash: rootHash,
			ExpectedValid:       true,
		},
	}

	outBytes, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal v030 vectors: %w", err)
	}
	return os.WriteFile("v030_vectors.json", append(outBytes, '\n'), 0644)
}

// --- v0.4.0 vector generation ---
//
// The v0.4.0 receipt shape adds the optional action.idempotency_key string
// (spec §7.3.6, ADR-0019 §S5). These vectors pin two cross-SDK contracts:
//
//   - idempotencyKeyReceipt: a single signed receipt carrying
//     action.idempotency_key. All three SDKs MUST canonicalise, hash, and
//     verify it identically (the new field is just another sorted string key
//     under RFC 8785).
//   - duplicateIdempotencyChain: a two-receipt chain whose receipts share one
//     idempotency_key. All three SDK chain verifiers MUST report the chain as
//     valid (retries are legitimate) AND surface exactly one duplicate-key
//     advisory. The warning string itself is SDK-local prose and is NOT pinned;
//     only the count and the duplicated key value are.

type v040Vectors struct {
	Comment        string                       `json:"$comment"`
	Version        string                       `json:"version"`
	Keys           keysSection                  `json:"keys"`
	Idempotency    idempotencyKeyReceiptSection `json:"idempotencyKeyReceipt"`
	DuplicateChain duplicateChainSection        `json:"duplicateIdempotencyChain"`
}

type idempotencyKeyReceiptSection struct {
	Description         string          `json:"description"`
	IdempotencyKey      string          `json:"idempotencyKey"`
	Receipt             json.RawMessage `json:"receipt"`
	ExpectedReceiptHash string          `json:"expectedReceiptHash"`
	ExpectedValid       bool            `json:"expectedValid"`
}

type duplicateChainSection struct {
	Description          string            `json:"description"`
	DuplicateKey         string            `json:"duplicateKey"`
	Receipts             []json.RawMessage `json:"receipts"`
	ExpectedValid        bool              `json:"expectedValid"`
	ExpectedWarningCount int               `json:"expectedWarningCount"`
}

// v050Vectors holds the ADR-0026 cross-SDK vectors: a v0.5.0 receipt whose
// issuer carries the open `runtime` sub-object (agent_id / agent_type), and a
// root-agent receipt that omits `runtime` entirely. Receipts at 0.5.0 reference
// JSON-LD context v2.
type v050Vectors struct {
	Comment   string                `json:"$comment"`
	Version   string                `json:"version"`
	Keys      keysSection           `json:"keys"`
	Runtime   runtimeReceiptSection `json:"runtimeReceipt"`
	Extended  runtimeReceiptSection `json:"extendedRuntimeReceipt"`
	RootAgent runtimeReceiptSection `json:"rootAgentReceipt"`
}

type runtimeReceiptSection struct {
	Description         string          `json:"description"`
	Receipt             json.RawMessage `json:"receipt"`
	ExpectedReceiptHash string          `json:"expectedReceiptHash"`
	ExpectedValid       bool            `json:"expectedValid"`
}

func generateV040Vectors(keys keysSection) error {
	const fixedTimestamp = "2026-05-23T00:00:00Z"

	// --- single receipt carrying action.idempotency_key ---
	const singleKey = "jsonrpc-req-7c3a9f10"
	idemUnsigned := map[string]any{
		"@context":     []any{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"},
		"id":           "urn:receipt:040e0040-0000-4040-a040-000000000001",
		"type":         []any{"VerifiableCredential", "AgentReceipt"},
		"version":      "0.4.0",
		"issuer":       map[string]any{"id": "did:agent:test"},
		"issuanceDate": fixedTimestamp,
		"credentialSubject": map[string]any{
			"principal": map[string]any{"id": "did:user:test"},
			"action": map[string]any{
				"id":              "act_040e0040-0000-4040-a040-000000000001",
				"type":            "system.command.execute",
				"risk_level":      "high",
				"idempotency_key": singleKey,
				"timestamp":       fixedTimestamp,
			},
			"outcome": map[string]any{"status": "success"},
			"chain": map[string]any{
				"sequence":              1,
				"previous_receipt_hash": nil,
				"chain_id":              "chain_v040_idempotency_test",
			},
		},
	}
	idemSigned, idemHash, err := signAndHashMap(idemUnsigned, keys, fixedTimestamp)
	if err != nil {
		return fmt.Errorf("idempotency receipt: %w", err)
	}

	// --- two-receipt chain sharing one idempotency_key (a recorded retry) ---
	const dupKey = "jsonrpc-req-retry-001"
	const dupChainID = "chain_v040_duplicate_test"
	dup1Unsigned := map[string]any{
		"@context":     []any{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"},
		"id":           "urn:receipt:040e0040-0000-4040-a040-000000000002",
		"type":         []any{"VerifiableCredential", "AgentReceipt"},
		"version":      "0.4.0",
		"issuer":       map[string]any{"id": "did:agent:test"},
		"issuanceDate": fixedTimestamp,
		"credentialSubject": map[string]any{
			"principal": map[string]any{"id": "did:user:test"},
			"action": map[string]any{
				"id":              "act_040e0040-0000-4040-a040-000000000002",
				"type":            "data.api.read",
				"risk_level":      "low",
				"idempotency_key": dupKey,
				"timestamp":       fixedTimestamp,
			},
			"outcome": map[string]any{"status": "failure", "error": "upstream timeout"},
			"chain": map[string]any{
				"sequence":              1,
				"previous_receipt_hash": nil,
				"chain_id":              dupChainID,
			},
		},
	}
	dup1Signed, dup1Hash, err := signAndHashMap(dup1Unsigned, keys, fixedTimestamp)
	if err != nil {
		return fmt.Errorf("duplicate chain receipt 1: %w", err)
	}
	dup2Unsigned := map[string]any{
		"@context":     []any{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"},
		"id":           "urn:receipt:040e0040-0000-4040-a040-000000000003",
		"type":         []any{"VerifiableCredential", "AgentReceipt"},
		"version":      "0.4.0",
		"issuer":       map[string]any{"id": "did:agent:test"},
		"issuanceDate": fixedTimestamp,
		"credentialSubject": map[string]any{
			"principal": map[string]any{"id": "did:user:test"},
			"action": map[string]any{
				"id":              "act_040e0040-0000-4040-a040-000000000003",
				"type":            "data.api.read",
				"risk_level":      "low",
				"idempotency_key": dupKey,
				"timestamp":       fixedTimestamp,
			},
			"outcome": map[string]any{"status": "success"},
			"chain": map[string]any{
				"sequence":              2,
				"previous_receipt_hash": dup1Hash,
				"chain_id":              dupChainID,
			},
		},
	}
	dup2Signed, _, err := signAndHashMap(dup2Unsigned, keys, fixedTimestamp)
	if err != nil {
		return fmt.Errorf("duplicate chain receipt 2: %w", err)
	}

	// Self-check: the duplicate chain must verify as valid with exactly one
	// idempotency warning, matching what the TS and Py SDK tests assert.
	var r1, r2 receipt.AgentReceipt
	if err := json.Unmarshal(dup1Signed, &r1); err != nil {
		return fmt.Errorf("unmarshal dup receipt 1: %w", err)
	}
	if err := json.Unmarshal(dup2Signed, &r2); err != nil {
		return fmt.Errorf("unmarshal dup receipt 2: %w", err)
	}
	res := receipt.VerifyChain([]receipt.AgentReceipt{r1, r2}, keys.PublicKey)
	if !res.Valid {
		return fmt.Errorf("generated duplicate chain failed verification: %s", res.Error)
	}
	if len(res.Warnings) != 1 {
		return fmt.Errorf("generated duplicate chain produced %d warnings, want 1", len(res.Warnings))
	}

	out := v040Vectors{
		Comment: "Cross-SDK v0.4.0 test vectors: pins the optional action.idempotency_key field (spec §7.3.6, ADR-0019 §S5, #480). All three SDKs MUST verify the signatures and reproduce expectedReceiptHash byte-for-byte, and MUST report the duplicate-key chain as valid with exactly one warning. Warning text is SDK-local prose and is intentionally not pinned.",
		Version: "0.4.0",
		Keys:    keys,
		Idempotency: idempotencyKeyReceiptSection{
			Description:         "Signed v0.4.0 receipt carrying action.idempotency_key. The new field is an ordinary sorted string key under RFC 8785; cross-SDK hash/sign/verify must be byte-identical.",
			IdempotencyKey:      singleKey,
			Receipt:             idemSigned,
			ExpectedReceiptHash: idemHash,
			ExpectedValid:       true,
		},
		DuplicateChain: duplicateChainSection{
			Description:          "Two-receipt chain whose receipts share one action.idempotency_key — a tool call that timed out (failure) and was retried (success). Verifiers MUST report valid: true (retries are legitimate) and surface exactly one duplicate-key advisory.",
			DuplicateKey:         dupKey,
			Receipts:             []json.RawMessage{dup1Signed, dup2Signed},
			ExpectedValid:        true,
			ExpectedWarningCount: 1,
		},
	}

	outBytes, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal v040 vectors: %w", err)
	}
	return os.WriteFile("v040_vectors.json", append(outBytes, '\n'), 0644)
}

// generateV050Vectors builds and writes v050_vectors.json: a v0.5.0 receipt
// whose issuer carries the open `runtime` sub-object (ADR-0026), plus a
// root-agent receipt that omits `runtime`. Both reference JSON-LD context v2.
// All three SDKs MUST canonicalise, hash, sign, and verify these byte-for-byte.
func generateV050Vectors(keys keysSection) error {
	const fixedTimestamp = "2026-06-09T00:00:00Z"
	contextV2 := []any{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v2"}

	// --- sub-agent receipt carrying issuer.runtime ---
	runtimeUnsigned := map[string]any{
		"@context": contextV2,
		"id":       "urn:receipt:050e0050-0000-4050-a050-000000000001",
		"type":     []any{"VerifiableCredential", "AgentReceipt"},
		"version":  "0.5.0",
		"issuer": map[string]any{
			"id":         "did:agent-receipts-daemon:test",
			"session_id": "a9a50488-d6f2-4dee-ac2e-ed3db47b9d00",
			"runtime": map[string]any{
				"agent_id":   "a3e49db54342a92d4",
				"agent_type": "general-purpose",
			},
		},
		"issuanceDate": fixedTimestamp,
		"credentialSubject": map[string]any{
			"principal": map[string]any{"id": "did:user:test"},
			"action": map[string]any{
				"id":         "act_050e0050-0000-4050-a050-000000000001",
				"type":       "filesystem.file.read",
				"risk_level": "low",
				"timestamp":  fixedTimestamp,
			},
			"outcome": map[string]any{"status": "success"},
			"chain": map[string]any{
				"sequence":              1,
				"previous_receipt_hash": nil,
				"chain_id":              "chain_v050_test/agent/a3e49db54342a92d4",
			},
		},
	}
	runtimeSigned, runtimeHash, err := signAndHashMap(runtimeUnsigned, keys, fixedTimestamp)
	if err != nil {
		return fmt.Errorf("runtime receipt: %w", err)
	}

	// --- receipt whose issuer.runtime carries a key beyond the typed members ---
	// (trace_id) — pins that the open container preserves unknown runtime keys
	// byte-identically across all three SDKs (ADR-0026 D2). A newer SDK adding
	// trace_id must not diverge from an older SDK that does not model it.
	extendedUnsigned := map[string]any{
		"@context": contextV2,
		"id":       "urn:receipt:050e0050-0000-4050-a050-000000000003",
		"type":     []any{"VerifiableCredential", "AgentReceipt"},
		"version":  "0.5.0",
		"issuer": map[string]any{
			"id":         "did:agent-receipts-daemon:test",
			"session_id": "a9a50488-d6f2-4dee-ac2e-ed3db47b9d00",
			"runtime": map[string]any{
				"agent_id":   "a3e49db54342a92d4",
				"agent_type": "general-purpose",
				"trace_id":   "4bf92f3577b34da6a3ce929d0e0e4736",
			},
		},
		"issuanceDate": fixedTimestamp,
		"credentialSubject": map[string]any{
			"principal": map[string]any{"id": "did:user:test"},
			"action": map[string]any{
				"id":         "act_050e0050-0000-4050-a050-000000000003",
				"type":       "filesystem.file.read",
				"risk_level": "low",
				"timestamp":  fixedTimestamp,
			},
			"outcome": map[string]any{"status": "success"},
			"chain": map[string]any{
				"sequence":              1,
				"previous_receipt_hash": nil,
				"chain_id":              "chain_v050_test/agent/a3e49db54342a92d4",
			},
		},
	}
	extendedSigned, extendedHash, err := signAndHashMap(extendedUnsigned, keys, fixedTimestamp)
	if err != nil {
		return fmt.Errorf("extended runtime receipt: %w", err)
	}

	// --- root-agent receipt: issuer omits runtime (backward-compatible shape) ---
	rootUnsigned := map[string]any{
		"@context": contextV2,
		"id":       "urn:receipt:050e0050-0000-4050-a050-000000000002",
		"type":     []any{"VerifiableCredential", "AgentReceipt"},
		"version":  "0.5.0",
		"issuer": map[string]any{
			"id":         "did:agent-receipts-daemon:test",
			"session_id": "a9a50488-d6f2-4dee-ac2e-ed3db47b9d00",
		},
		"issuanceDate": fixedTimestamp,
		"credentialSubject": map[string]any{
			"principal": map[string]any{"id": "did:user:test"},
			"action": map[string]any{
				"id":         "act_050e0050-0000-4050-a050-000000000002",
				"type":       "filesystem.file.read",
				"risk_level": "low",
				"timestamp":  fixedTimestamp,
			},
			"outcome": map[string]any{"status": "success"},
			"chain": map[string]any{
				"sequence":              1,
				"previous_receipt_hash": nil,
				"chain_id":              "chain_v050_test",
			},
		},
	}
	rootSigned, rootHash, err := signAndHashMap(rootUnsigned, keys, fixedTimestamp)
	if err != nil {
		return fmt.Errorf("root receipt: %w", err)
	}

	// Self-check: all receipts must verify against the shared public key.
	for label, signed := range map[string]json.RawMessage{"runtime": runtimeSigned, "extended": extendedSigned, "root": rootSigned} {
		var r receipt.AgentReceipt
		if err := json.Unmarshal(signed, &r); err != nil {
			return fmt.Errorf("unmarshal %s receipt: %w", label, err)
		}
		res := receipt.VerifyChain([]receipt.AgentReceipt{r}, keys.PublicKey)
		if !res.Valid {
			return fmt.Errorf("generated %s receipt failed verification: %s", label, res.Error)
		}
	}

	out := v050Vectors{
		Comment: "Cross-SDK v0.5.0 test vectors: pins the open issuer.runtime sub-object (agent_id / agent_type) and JSON-LD context v2 (spec §4.3.1, ADR-0026). runtime is an ordinary nested object under RFC 8785 — its keys sort like any other — so cross-SDK hash/sign/verify must be byte-identical. The root-agent receipt pins that omitting runtime stays backward-compatible.",
		Version: "0.5.0",
		Keys:    keys,
		Runtime: runtimeReceiptSection{
			Description:         "Signed v0.5.0 sub-agent receipt whose issuer carries runtime.agent_id and runtime.agent_type.",
			Receipt:             runtimeSigned,
			ExpectedReceiptHash: runtimeHash,
			ExpectedValid:       true,
		},
		Extended: runtimeReceiptSection{
			Description:         "Signed v0.5.0 receipt whose issuer.runtime carries an extra key (trace_id) beyond the typed members. All three SDKs MUST preserve the unknown key and reproduce this hash byte-for-byte (ADR-0026 open-container invariant).",
			Receipt:             extendedSigned,
			ExpectedReceiptHash: extendedHash,
			ExpectedValid:       true,
		},
		RootAgent: runtimeReceiptSection{
			Description:         "Signed v0.5.0 root-agent receipt whose issuer omits runtime entirely.",
			Receipt:             rootSigned,
			ExpectedReceiptHash: rootHash,
			ExpectedValid:       true,
		},
	}

	outBytes, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal v050 vectors: %w", err)
	}
	return os.WriteFile("v050_vectors.json", append(outBytes, '\n'), 0644)
}

// signAndHashMap signs an unsigned-receipt JSON map with the Ed25519 PEM
// private key from keys, attaches the resulting proof, and returns the signed
// receipt JSON (sorted by JCS at canonicalization time, not at marshal time)
// alongside its receipt hash.
//
// Receipt JSON is built via Go's encoding/json default marshalling (struct or
// map). Verifiers MUST canonicalize before hashing/verifying.
func signAndHashMap(unsigned map[string]any, keys keysSection, fixedTimestamp string) (json.RawMessage, string, error) {
	canonical, err := receipt.Canonicalize(unsigned)
	if err != nil {
		return nil, "", fmt.Errorf("canonicalize unsigned: %w", err)
	}
	hash := receipt.SHA256Hash(canonical)

	priv, err := parseEd25519PrivatePEM(keys.PrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("parse private key: %w", err)
	}
	sig := ed25519.Sign(priv, []byte(canonical))
	proofValue := "u" + base64.RawURLEncoding.EncodeToString(sig)

	signed := make(map[string]any, len(unsigned)+1)
	for k, v := range unsigned {
		signed[k] = v
	}
	signed["proof"] = map[string]any{
		"type":               "Ed25519Signature2020",
		"created":            fixedTimestamp,
		"verificationMethod": "did:agent:test#key-1",
		"proofPurpose":       "assertionMethod",
		"proofValue":         proofValue,
	}

	// Sanity-check: verify the signature we just produced against the public key.
	pub, err := parseEd25519PublicPEM(keys.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("parse public key: %w", err)
	}
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		return nil, "", errors.New("self-verify failed after signing v030 receipt")
	}

	raw, err := json.Marshal(signed)
	if err != nil {
		return nil, "", fmt.Errorf("marshal signed: %w", err)
	}
	return json.RawMessage(raw), hash, nil
}

func parseEd25519PrivatePEM(pemStr string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("decode PEM private key: no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return edKey, nil
}

func parseEd25519PublicPEM(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("decode PEM public key: no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SPKI public key: %w", err)
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return edKey, nil
}
