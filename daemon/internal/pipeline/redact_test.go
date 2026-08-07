package pipeline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"obsigna.dev/daemon/internal/chain"
	"obsigna.dev/daemon/internal/socket"
	"obsigna.dev/sdk/go/receipt"
)

// TestRedactor_BuiltinPatternsRedactKnownSecretShapes verifies that the
// default Redactor (built-in patterns only) catches common secret shapes.
func TestRedactor_BuiltinPatternsRedactKnownSecretShapes(t *testing.T) {
	r := NewRedactor(nil)

	cases := []struct {
		name  string
		input string
		want  string // substring that must NOT appear in output
		keep  string // substring that MUST still appear in output
	}{
		{
			name:  "github-pat-classic",
			input: `{"note":"ghp_` + strings.Repeat("a", 36) + `"}`,
			want:  "ghp_",
		},
		{
			name:  "openai-key",
			input: `{"key":"sk-` + strings.Repeat("a", 20) + `"}`,
			want:  "sk-",
		},
		{
			name:  "aws-access-key",
			input: `AKIA` + strings.Repeat("A", 16),
			want:  "AKIA",
		},
		{
			name:  "bearer-token",
			input: `Bearer ` + strings.Repeat("a", 20),
			want:  strings.Repeat("a", 20),
			keep:  "[REDACTED]",
		},
		{
			name:  "sensitive-json-key-password",
			input: `{"username":"alice","password":"hunter2"}`,
			want:  "hunter2",
			keep:  "alice",
		},
		{
			name:  "sensitive-json-key-api-key",
			input: `{"host":"example.com","api_key":"secret123"}`,
			want:  "secret123",
			keep:  "example.com",
		},
		{
			name:  "pem-private-key",
			input: "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAA\n-----END RSA PRIVATE KEY-----",
			want:  "MIIBogIBAA",
		},
		{
			name:  "jwt-bare",
			input: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsIm5hbWUiOiJBbGljZSJ9.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			want:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		{
			name:  "jwt-in-npmrc",
			input: "//registry.npmjs.org/:_authToken=eyJ2ZXIiOjEsImlzdSI6MzQ1Njc4OTB9.eyJzdWIiOiJucG0tdXNlciIsImlhdCI6MTYwMDAwMDAwMH0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			want:  "eyJ2ZXIiOjEsImlzdSI6MzQ1Njc4OTB9",
			keep:  "//registry.npmjs.org/:_authToken=",
		},
		{
			name:  "jwt-unsigned",
			input: "token: eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.",
			want:  "eyJhbGciOiJub25lIn0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := r.Redact(tc.input)
			if strings.Contains(out, tc.want) {
				t.Errorf("secret not redacted: output %q still contains %q", out, tc.want)
			}
			if !strings.Contains(out, "[REDACTED]") {
				t.Errorf("expected [REDACTED] in output, got %q", out)
			}
			if tc.keep != "" && !strings.Contains(out, tc.keep) {
				t.Errorf("expected %q to remain in output, got %q", tc.keep, out)
			}
		})
	}
}

// TestRedactor_CustomPatternsApplied verifies that patterns loaded from a YAML
// file are applied in addition to the built-ins.
func TestRedactor_CustomPatternsApplied(t *testing.T) {
	yaml := `patterns:
  - name: internal-token
    pattern: 'CORP-[A-Z0-9]{8}'
`
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadPatternFile(path)
	if err != nil {
		t.Fatalf("LoadPatternFile: %v", err)
	}
	r := NewRedactor(patterns)

	out := r.Redact("request with token CORP-ABCD1234 inside")
	if strings.Contains(out, "CORP-ABCD1234") {
		t.Errorf("custom pattern not applied: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected [REDACTED], got %q", out)
	}
}

// TestRedactor_BothBuiltinAndCustomPatternsApply verifies that both built-in
// and user-supplied patterns are applied when a Redactor has both.
func TestRedactor_BothBuiltinAndCustomPatternsApply(t *testing.T) {
	yaml := `patterns:
  - name: corp-key
    pattern: 'MYCO-[A-Z0-9]+'
`
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadPatternFile(path)
	if err != nil {
		t.Fatalf("LoadPatternFile: %v", err)
	}
	r := NewRedactor(patterns)

	// Both custom and builtin must trigger on the same string.
	input := `MYCO-ABCDEF and ghp_` + strings.Repeat("a", 36)
	out := r.Redact(input)
	if strings.Contains(out, "MYCO-ABCDEF") {
		t.Errorf("custom pattern not applied: %q", out)
	}
	if strings.Contains(out, "ghp_") {
		t.Errorf("builtin pattern not applied: %q", out)
	}
}

// TestRedactor_InvalidYAML verifies that LoadPatternFile returns an error for
// syntactically invalid YAML.
func TestRedactor_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("patterns:\n  - name: x\n    pattern: [invalid regex: ("), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPatternFile(path); err == nil {
		t.Error("expected error for invalid regex in pattern file, got nil")
	}
}

// TestRedactor_EmptyPatternFile verifies that an empty patterns list is valid.
func TestRedactor_EmptyPatternFile(t *testing.T) {
	yaml := "patterns: []\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	patterns, err := LoadPatternFile(path)
	if err != nil {
		t.Fatalf("LoadPatternFile: %v", err)
	}
	if len(patterns) != 0 {
		t.Errorf("expected 0 patterns, got %d", len(patterns))
	}
}

// TestPipeline_HashesComputedBeforeRedaction is the critical correctness test:
// the parameters_hash and response_hash must match the RAW (unredacted) input.
// Redaction only affects what is stored in the receipt body text fields.
//
// The daemon does not store raw body text in receipts — only hashes — so this
// test focuses on verifying that the hash over the raw value is stable and
// independent of what redaction does to the string form.
func TestPipeline_HashesComputedBeforeRedaction(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")

	// Use the default redactor (built-in patterns only). The input contains an
	// api_key and sk- pattern that the built-ins would redact if applied to the
	// stored body — but input/output are only stored as hashes, never as text.
	// We verify the hashes match the RAW (pre-redaction) canonical JSON.
	redactor := NewRedactor(nil)

	p := New(state, ks, st, "did:agent-receipts-daemon:test")
	p.Redactor = redactor

	// Input containing a secret — the hash must reflect the raw value.
	rawInput := json.RawMessage(`{"path":"/etc/secrets","api_key":"sk-` + strings.Repeat("a", 20) + `"}`)
	rawOutput := json.RawMessage(`{"status":"ok","token":"` + strings.Repeat("b", 30) + `"}`)

	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "secret-tool"},
		Input:     rawInput,
		Output:    rawOutput,
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("Process: %v", err)
	}

	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	r := receipts[0]

	// Recompute expected hashes from the RAW (unredacted) inputs.
	var inVal any
	if err := json.Unmarshal(rawInput, &inVal); err != nil {
		t.Fatal(err)
	}
	inCanonical, err := receipt.Canonicalize(inVal)
	if err != nil {
		t.Fatal(err)
	}
	wantParamsHash := receipt.SHA256Hash(inCanonical)

	var outVal any
	if err := json.Unmarshal(rawOutput, &outVal); err != nil {
		t.Fatal(err)
	}
	outCanonical, err := receipt.Canonicalize(outVal)
	if err != nil {
		t.Fatal(err)
	}
	wantResponseHash := receipt.SHA256Hash(outCanonical)

	if got := r.CredentialSubject.Action.ParametersHash; got != wantParamsHash {
		t.Errorf("parameters_hash mismatch: got %q want %q (hash must be over raw input, not redacted)", got, wantParamsHash)
	}
	if got := r.CredentialSubject.Outcome.ResponseHash; got != wantResponseHash {
		t.Errorf("response_hash mismatch: got %q want %q (hash must be over raw output, not redacted)", got, wantResponseHash)
	}
}

// TestPipeline_ErrorFieldIsRedactedInReceipt verifies the one field that IS
// stored as text — outcome.error — is redacted before persistence when it
// contains a recognisable secret shape.
func TestPipeline_ErrorFieldIsRedactedInReceipt(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-error-redact")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")
	p.Redactor = NewRedactor(nil)

	secret := "ghp_" + strings.Repeat("x", 36)
	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "failing-tool"},
		Error:     `{"message":"auth failed: ` + secret + `"}`,
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("Process: %v", err)
	}

	receipts, err := st.GetChain("chain-error-redact")
	if err != nil {
		t.Fatal(err)
	}
	errField := receipts[0].CredentialSubject.Outcome.Error
	if strings.Contains(errField, secret) {
		t.Errorf("outcome.error contains raw secret — redaction did not run: %q", errField)
	}
	if !strings.Contains(errField, "[REDACTED]") {
		t.Errorf("outcome.error does not contain [REDACTED]: %q", errField)
	}
}

// TestPipeline_RedactionDoesNotAffectProof verifies that the cryptographic
// proof and signature fields are not touched by redaction.
func TestPipeline_RedactionDoesNotAffectProof(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")
	p.Redactor = NewRedactor(nil)

	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "t"},
		Input:     json.RawMessage(`{"password":"supersecret"}`),
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("Process: %v", err)
	}

	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	r := receipts[0]

	// Proof fields must be present and non-empty.
	if r.Proof.ProofValue == "" {
		t.Error("proof.proofValue is empty — redaction must not touch the proof")
	}
	if r.Proof.Type == "" {
		t.Error("proof.type is empty")
	}
	if r.Proof.VerificationMethod == "" {
		t.Error("proof.verificationMethod is empty")
	}

	// The receipt must still verify correctly with the public key.
	pubPEM, err := ks.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ok, err := receipt.Verify(r, pubPEM)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("signature did not verify — redaction must not corrupt the signed bytes")
	}
}

// TestPipeline_RedactionAppliedToError verifies that the error field of the
// frame is redacted before being persisted in outcome.error.
func TestPipeline_RedactionAppliedToError(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")
	p.Redactor = NewRedactor(nil)

	secretToken := "ghp_" + strings.Repeat("z", 36)
	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "t"},
		Error:     "upstream failed: " + secretToken,
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("Process: %v", err)
	}

	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	r := receipts[0]
	if strings.Contains(r.CredentialSubject.Outcome.Error, secretToken) {
		t.Errorf("outcome.error contains unredacted secret: %q", r.CredentialSubject.Outcome.Error)
	}
	if !strings.Contains(r.CredentialSubject.Outcome.Error, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in outcome.error, got %q", r.CredentialSubject.Outcome.Error)
	}
}

// TestPipeline_PromptPreviewIsRedactedInReceipt verifies intent.prompt_preview
// — the second inline plaintext field alongside outcome.error (issue #1012) —
// is redacted before persistence when it contains a recognisable secret shape.
func TestPipeline_PromptPreviewIsRedactedInReceipt(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-preview-redact")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")
	p.Redactor = NewRedactor(nil)

	secret := "ghp_" + strings.Repeat("x", 36)
	body, err := json.Marshal(EmitterFrame{
		Version:       "1",
		TsEmit:        "2026-05-03T00:00:00Z",
		SessionID:     "s",
		Channel:       "sdk",
		Tool:          EmitterTool{Name: "t"},
		PromptPreview: "use token " + secret + " to authenticate",
		Decision:      "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("Process: %v", err)
	}

	receipts, err := st.GetChain("chain-preview-redact")
	if err != nil {
		t.Fatal(err)
	}
	intent := receipts[0].CredentialSubject.Intent
	if intent == nil {
		t.Fatal("intent nil; daemon must populate intent.prompt_preview")
	}
	if strings.Contains(intent.PromptPreview, secret) {
		t.Errorf("prompt_preview contains raw secret — redaction did not run: %q", intent.PromptPreview)
	}
	if !strings.Contains(intent.PromptPreview, "[REDACTED]") {
		t.Errorf("prompt_preview does not contain [REDACTED]: %q", intent.PromptPreview)
	}
}

// TestPipeline_PromptPreviewRedactedBeforeTruncation verifies redaction runs
// before the rune cap, matching the ordering already used for outcome.error
// (build.go:852-856): redaction can lengthen a string (a short secret replaced
// by the longer "[REDACTED]" placeholder), so capping first could leave an
// over-cap value, and redacting after truncation could leave a secret's tail
// exposed if the cap split it mid-match.
func TestPipeline_PromptPreviewRedactedBeforeTruncation(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-preview-redact-trunc")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")
	p.Redactor = NewRedactor(nil)
	p.MaxPromptPreviewLen = 4096

	secret := "ghp_" + strings.Repeat("x", 36)
	preview := "leading text " + secret + " trailing text"
	body, err := json.Marshal(EmitterFrame{
		Version:       "1",
		TsEmit:        "2026-05-03T00:00:00Z",
		SessionID:     "s",
		Channel:       "sdk",
		Tool:          EmitterTool{Name: "t"},
		PromptPreview: preview,
		Decision:      "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("Process: %v", err)
	}

	receipts, err := st.GetChain("chain-preview-redact-trunc")
	if err != nil {
		t.Fatal(err)
	}
	intent := receipts[0].CredentialSubject.Intent
	if intent == nil {
		t.Fatal("intent nil")
	}
	if intent.PromptPreview != "leading text [REDACTED] trailing text" {
		t.Errorf("prompt_preview = %q, want redacted", intent.PromptPreview)
	}
	if intent.PromptPreviewTruncated != nil {
		t.Error("prompt_preview_truncated must be absent; well within cap after redaction")
	}
}

// TestPipeline_NoRedactorIsNoop verifies that when no Redactor is set (nil),
// the pipeline behaves exactly as before — hashes and error field are
// unmodified. Nil Redactor must not panic.
func TestPipeline_NoRedactorIsNoop(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")
	// p.Redactor is nil by default.

	secretToken := "ghp_" + strings.Repeat("z", 36)
	input := json.RawMessage(`{"key":"value"}`)
	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "t"},
		Input:     input,
		Error:     "err: " + secretToken,
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("Process: %v", err)
	}

	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	r := receipts[0]

	// Without a Redactor, the raw error string must appear unchanged.
	if !strings.Contains(r.CredentialSubject.Outcome.Error, secretToken) {
		t.Errorf("expected raw error preserved when no Redactor; got %q", r.CredentialSubject.Outcome.Error)
	}

	// Hash should still be computed correctly.
	if r.CredentialSubject.Action.ParametersHash == "" {
		t.Error("parameters_hash should be set even without a Redactor")
	}
}

// TestPipeline_LoadPatternFile_MissingFile verifies LoadPatternFile returns
// an error for a non-existent file.
func TestPipeline_LoadPatternFile_MissingFile(t *testing.T) {
	_, err := LoadPatternFile("/nonexistent/path/patterns.yaml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

// TestPipeline_LoadPatternFile_MissingName verifies that a pattern entry
// without a name is rejected.
func TestPipeline_LoadPatternFile_MissingName(t *testing.T) {
	yaml := `patterns:
  - pattern: '[A-Z]+'
`
	dir := t.TempDir()
	path := filepath.Join(dir, "noname.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPatternFile(path); err == nil {
		t.Error("expected error for pattern without name, got nil")
	}
}

// TestPipeline_LoadPatternFile_MissingPattern verifies that a pattern entry
// without a regex is rejected.
func TestPipeline_LoadPatternFile_MissingPattern(t *testing.T) {
	yaml := `patterns:
  - name: empty
    pattern: ''
`
	dir := t.TempDir()
	path := filepath.Join(dir, "nopat.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPatternFile(path); err == nil {
		t.Error("expected error for pattern with empty regex, got nil")
	}
}
