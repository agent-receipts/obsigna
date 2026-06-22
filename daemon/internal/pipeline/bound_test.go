package pipeline

import (
	"encoding/json"
	"strings"
	"testing"

	"obsigna.dev/daemon/internal/chain"
	"obsigna.dev/daemon/internal/socket"
	"obsigna.dev/sdk/go/receipt"
)

// processFrame runs one EmitterFrame through a fresh pipeline and returns the
// single stored receipt. It is the common harness for the bounding tests below.
func processFrame(t *testing.T, f EmitterFrame, mutate func(*Pipeline)) receipt.AgentReceipt {
	t.Helper()
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")
	if mutate != nil {
		mutate(p)
	}
	body, err := json.Marshal(f)
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
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1", len(receipts))
	}
	return receipts[0]
}

func errorFrame(errText string) EmitterFrame {
	return EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "t"},
		Decision:  "allowed",
		Error:     errText,
	}
}

// TestBuildAndSign_CapsOversizedError verifies the daemon truncates an oversized
// outcome.error to the configured rune cap and records the truncation in-band
// (the outcome object's schema forbids an extra flag field), so a hostile or
// runaway error message cannot inflate the receipt.
func TestBuildAndSign_CapsOversizedError(t *testing.T) {
	const cap = 64
	huge := strings.Repeat("e", 5000)
	r := processFrame(t, errorFrame(huge), func(p *Pipeline) { p.MaxErrorLen = cap })

	got := r.CredentialSubject.Outcome.Error
	if got == huge {
		t.Fatal("error was not truncated")
	}
	if !strings.HasSuffix(got, errorTruncatedSuffix) {
		t.Errorf("truncated error %q missing truncation marker %q", got, errorTruncatedSuffix)
	}
	// The kept prefix must be exactly the cap, with the marker appended.
	if want := huge[:cap] + errorTruncatedSuffix; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
	if r.CredentialSubject.Outcome.Status != receipt.StatusFailure {
		t.Errorf("status = %q, want failure", r.CredentialSubject.Outcome.Status)
	}
}

// TestBuildAndSign_UndersizedErrorUntouched verifies an error within the cap is
// stored verbatim with no truncation marker.
func TestBuildAndSign_UndersizedErrorUntouched(t *testing.T) {
	const cap = 256
	msg := "permission denied: cannot write /etc/hosts"
	r := processFrame(t, errorFrame(msg), func(p *Pipeline) { p.MaxErrorLen = cap })

	if got := r.CredentialSubject.Outcome.Error; got != msg {
		t.Errorf("error = %q, want untouched %q", got, msg)
	}
}

// TestBuildAndSign_ErrorAtCapUntouched checks the boundary: an error exactly at
// the cap must pass through without a truncation marker.
func TestBuildAndSign_ErrorAtCapUntouched(t *testing.T) {
	const cap = 64
	msg := strings.Repeat("x", cap)
	r := processFrame(t, errorFrame(msg), func(p *Pipeline) { p.MaxErrorLen = cap })

	if got := r.CredentialSubject.Outcome.Error; got != msg {
		t.Errorf("error at cap = %q, want untouched %q", got, msg)
	}
	if strings.Contains(r.CredentialSubject.Outcome.Error, errorTruncatedSuffix) {
		t.Error("error exactly at cap must not be marked truncated")
	}
}

// TestBuildAndSign_ErrorCapIsRuneSafe verifies the cap counts runes, not bytes,
// so truncating a multi-byte string never splits a UTF-8 sequence.
func TestBuildAndSign_ErrorCapIsRuneSafe(t *testing.T) {
	const cap = 3
	msg := "héllo wörld" // multi-byte runes
	r := processFrame(t, errorFrame(msg), func(p *Pipeline) { p.MaxErrorLen = cap })

	got := r.CredentialSubject.Outcome.Error
	if want := string([]rune(msg)[:cap]) + errorTruncatedSuffix; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

func previewFrame(preview string) EmitterFrame {
	f := errorFrame("")
	f.Error = ""
	f.PromptPreview = preview
	return f
}

// TestBuildAndSign_TruncatesPromptPreview verifies the daemon enforces
// TruncatePromptPreview on an oversized prompt_preview and sets the
// prompt_preview_truncated flag the schema already defines.
func TestBuildAndSign_TruncatesPromptPreview(t *testing.T) {
	const cap = 16
	huge := strings.Repeat("p", 4096)
	r := processFrame(t, previewFrame(huge), func(p *Pipeline) { p.MaxPromptPreviewLen = cap })

	intent := r.CredentialSubject.Intent
	if intent == nil {
		t.Fatal("intent nil; daemon must populate intent.prompt_preview")
	}
	if got := intent.PromptPreview; got != huge[:cap] {
		t.Errorf("prompt_preview = %q, want first %d runes", got, cap)
	}
	if intent.PromptPreviewTruncated == nil || !*intent.PromptPreviewTruncated {
		t.Error("prompt_preview_truncated must be true after truncation")
	}
}

// TestBuildAndSign_PromptPreviewUntouched verifies a preview within the cap is
// stored verbatim and the truncated flag is left absent (nil), not false.
func TestBuildAndSign_PromptPreviewUntouched(t *testing.T) {
	const cap = 256
	preview := "Send the Q3 report to the team"
	r := processFrame(t, previewFrame(preview), func(p *Pipeline) { p.MaxPromptPreviewLen = cap })

	intent := r.CredentialSubject.Intent
	if intent == nil {
		t.Fatal("intent nil; daemon must populate intent.prompt_preview")
	}
	if intent.PromptPreview != preview {
		t.Errorf("prompt_preview = %q, want untouched %q", intent.PromptPreview, preview)
	}
	if intent.PromptPreviewTruncated != nil {
		t.Errorf("prompt_preview_truncated = %v, want absent for an untruncated preview", *intent.PromptPreviewTruncated)
	}
}

// TestBuildAndSign_PromptPreviewAtCapUntouched checks the boundary: a preview
// exactly at the cap must not be flagged truncated.
func TestBuildAndSign_PromptPreviewAtCapUntouched(t *testing.T) {
	const cap = 32
	preview := strings.Repeat("z", cap)
	r := processFrame(t, previewFrame(preview), func(p *Pipeline) { p.MaxPromptPreviewLen = cap })

	intent := r.CredentialSubject.Intent
	if intent == nil {
		t.Fatal("intent nil")
	}
	if intent.PromptPreview != preview {
		t.Errorf("prompt_preview at cap = %q, want untouched", intent.PromptPreview)
	}
	if intent.PromptPreviewTruncated != nil {
		t.Error("prompt_preview exactly at cap must not be flagged truncated")
	}
}

// TestBuildAndSign_NegativePromptPreviewCapDisables verifies a non-positive cap
// disables truncation (the documented "negative disables" contract) rather than
// dropping the whole preview. The shared TruncatePromptPreview helper treats
// maxLen <= 0 as "return empty, mark truncated"; intentFromFrame must not.
func TestBuildAndSign_NegativePromptPreviewCapDisables(t *testing.T) {
	preview := strings.Repeat("p", 4096)
	r := processFrame(t, previewFrame(preview), func(p *Pipeline) { p.MaxPromptPreviewLen = -1 })

	intent := r.CredentialSubject.Intent
	if intent == nil {
		t.Fatal("intent nil; a disabled cap must still store the preview")
	}
	if intent.PromptPreview != preview {
		t.Errorf("prompt_preview = %q (len %d), want full preview untruncated (len %d)",
			intent.PromptPreview, len(intent.PromptPreview), len(preview))
	}
	if intent.PromptPreviewTruncated != nil {
		t.Errorf("prompt_preview_truncated = %v, want absent when truncation is disabled", *intent.PromptPreviewTruncated)
	}
}

// TestBuildAndSign_NoPromptPreviewNoIntent verifies a frame without a prompt
// preview produces no intent block at all (omitempty), keeping the receipt
// byte-identical to today's output for emitters that send no preview.
func TestBuildAndSign_NoPromptPreviewNoIntent(t *testing.T) {
	r := processFrame(t, previewFrame(""), nil)
	if r.CredentialSubject.Intent != nil {
		t.Errorf("intent = %#v, want nil when no prompt_preview is sent", r.CredentialSubject.Intent)
	}
}

// TestNew_DefaultsBoundCaps pins that New installs sane non-zero default caps so
// a Pipeline built without explicit configuration still bounds both fields.
func TestNew_DefaultsBoundCaps(t *testing.T) {
	p := New(chain.New("c"), nil, nil, "did:test")
	if p.MaxErrorLen != DefaultMaxErrorLen {
		t.Errorf("MaxErrorLen = %d, want default %d", p.MaxErrorLen, DefaultMaxErrorLen)
	}
	if p.MaxPromptPreviewLen != DefaultMaxPromptPreviewLen {
		t.Errorf("MaxPromptPreviewLen = %d, want default %d", p.MaxPromptPreviewLen, DefaultMaxPromptPreviewLen)
	}
}
