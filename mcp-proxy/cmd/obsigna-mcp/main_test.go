package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
	"github.com/agent-receipts/ar/mcp-proxy/internal/policy"
)

func TestBuildApprovalDeniedMessageTimeout(t *testing.T) {
	got := buildApprovalDeniedMessage("create_pull_request", "pause_high_risk", 70, "abc123", audit.ApprovalTimedOut, 15*time.Second)

	for _, want := range []string{
		"timed out after 15s",
		"tool=create_pull_request",
		"rule=pause_high_risk",
		"risk=70",
		"approval_id=abc123",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q to contain %q", got, want)
		}
	}
}

func TestBuildApprovalDeniedMessageExplicitDeny(t *testing.T) {
	got := buildApprovalDeniedMessage("create_pull_request", "pause_high_risk", 70, "abc123", audit.ApprovalDenied, 15*time.Second)

	if !strings.Contains(got, "denied by approval workflow") {
		t.Fatalf("expected explicit deny message, got %q", got)
	}
	if strings.Contains(got, "timed out") {
		t.Fatalf("explicit deny message should not mention timeout: %q", got)
	}
}

func withHomeDirResolver(t *testing.T, resolver func() (string, error)) {
	t.Helper()
	prev := userHomeDir
	userHomeDir = resolver
	t.Cleanup(func() { userHomeDir = prev })
}

// withXDGDataHome temporarily sets XDG_DATA_HOME to dir and restores the
// previous value on cleanup. Pass "" to disable XDG override (xdgDataHome
// treats an empty value the same as unset).
func withXDGDataHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", dir)
}

func TestXDGDataHomeUsesHomeDir(t *testing.T) {
	home := t.TempDir()
	withHomeDirResolver(t, func() (string, error) { return home, nil })
	withXDGDataHome(t, "") // ensure XDG_DATA_HOME does not override

	got := xdgDataHome()
	want := filepath.Join(home, ".local", "share")
	if got != want {
		t.Fatalf("xdgDataHome() = %q, want %q", got, want)
	}
}

func TestXDGDataHomeRespectsAbsoluteEnv(t *testing.T) {
	xdgDir := t.TempDir()
	withXDGDataHome(t, xdgDir)

	if got := xdgDataHome(); got != xdgDir {
		t.Fatalf("xdgDataHome() = %q, want %q", got, xdgDir)
	}
}

func TestXDGDataHomeIgnoresRelativeEnv(t *testing.T) {
	home := t.TempDir()
	withHomeDirResolver(t, func() (string, error) { return home, nil })
	withXDGDataHome(t, "relative/xdg") // relative — must be ignored per XDG spec

	got := xdgDataHome()
	want := filepath.Join(home, ".local", "share")
	if got != want {
		t.Fatalf("xdgDataHome() = %q, want %q; expected relative XDG_DATA_HOME to be ignored", got, want)
	}
}

func TestXDGDataHomeFallsBackOnResolverError(t *testing.T) {
	withHomeDirResolver(t, func() (string, error) { return "", errors.New("no home") })
	withXDGDataHome(t, "") // ensure XDG_DATA_HOME does not override

	if got := xdgDataHome(); got != "" {
		t.Fatalf("xdgDataHome() with resolver error = %q, want empty string", got)
	}
}

func TestXDGDataHomeRejectsRelativeHome(t *testing.T) {
	withHomeDirResolver(t, func() (string, error) { return "relative/path", nil })
	withXDGDataHome(t, "") // ensure XDG_DATA_HOME does not override

	if got := xdgDataHome(); got != "" {
		t.Fatalf("xdgDataHome() with relative HOME = %q, want empty string", got)
	}
}

// TestNoteLegacyAuditDB verifies the one-line legacy-DB nudge: emit when the
// pre-v0.9.0 file is present, stay silent otherwise. The proxy MUST NOT delete
// the file — operators may want to archive it.
func TestNoteLegacyAuditDBPresent(t *testing.T) {
	home := t.TempDir()
	withHomeDirResolver(t, func() (string, error) { return home, nil })
	withXDGDataHome(t, "") // resolve via HOME

	legacy := filepath.Join(home, ".local", "share", "agent-receipts", "audit.db")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(legacy, []byte("legacy"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	out := captureStderr(t, noteLegacyAuditDB)
	if !strings.Contains(out, "legacy audit DB") || !strings.Contains(out, "safe to delete") {
		t.Errorf("expected legacy-DB notice, got: %s", out)
	}
	// Critically, the file must still exist after the nudge.
	if _, err := os.Stat(legacy); err != nil {
		t.Errorf("noteLegacyAuditDB should not remove the file, got stat err: %v", err)
	}
}

func TestNoteLegacyAuditDBAbsent(t *testing.T) {
	home := t.TempDir()
	withHomeDirResolver(t, func() (string, error) { return home, nil })
	withXDGDataHome(t, "")

	out := captureStderr(t, noteLegacyAuditDB)
	if strings.Contains(out, "legacy audit DB") {
		t.Errorf("did not expect legacy-DB notice when file absent, got: %s", out)
	}
}

// captureStderr redirects os.Stderr for the duration of fn and returns the
// captured output. Log package output is routed through the same pipe.
//
// fn() runs inside an IIFE with a deferred w.Close(), so the reader
// goroutine unblocks even if fn() panics or calls t.Fatal — otherwise the
// test would hang indefinitely on io.ReadAll. The write end is closed
// exactly once.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStderr := os.Stderr
	oldLog := log.Writer()
	os.Stderr = w
	log.SetOutput(w)

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	t.Cleanup(func() {
		os.Stderr = oldStderr
		log.SetOutput(oldLog)
		r.Close()
	})

	func() {
		defer w.Close()
		fn()
	}()
	return <-done
}

// TestStartupBannerDefaultNone: -http not set at all (httpExplicit=false).
// With default rules containing pause_high_risk, the banner should emit INFO
// (not WARN) with a soft hint about opt-in.
func TestStartupBannerDefaultNone(t *testing.T) {
	summary := policy.NewEngine(policy.DefaultRules()).Describe()
	// approverDisabled=true (default is "none"), httpExplicit=false
	out := captureStderr(t, func() { emitStartupBanner(summary, "", true, false) })

	if strings.Contains(out, "[WARN]") {
		t.Errorf("did not expect WARN for default-off approver, got: %s", out)
	}
	if !strings.Contains(out, "[INFO]") {
		t.Errorf("expected INFO marker for default-off case, got: %s", out)
	}
	if !strings.Contains(out, "approver off by default") {
		t.Errorf("expected 'approver off by default' hint, got: %s", out)
	}
	if !strings.Contains(out, "pass -http") {
		t.Errorf("expected '-http' opt-in hint, got: %s", out)
	}
	if !strings.Contains(out, "pause_high_risk") {
		t.Errorf("expected pause rule name listed, got: %s", out)
	}
	if !strings.Contains(out, `"event":"policy_banner"`) {
		t.Errorf("expected machine-readable companion line, got: %s", out)
	}
}

// TestStartupBannerExplicitNone: operator passed -http=none explicitly.
// The banner line and JSON companion still print; what's suppressed is the
// trailing opt-in suffix and the WARN level — the operator made an informed
// choice and doesn't need a nudge.
func TestStartupBannerExplicitNone(t *testing.T) {
	summary := policy.NewEngine(policy.DefaultRules()).Describe()
	// approverDisabled=true, httpExplicit=true
	out := captureStderr(t, func() { emitStartupBanner(summary, "", true, true) })

	if strings.Contains(out, "[WARN]") {
		t.Errorf("did not expect WARN for explicit -http=none, got: %s", out)
	}
	if strings.Contains(out, "approver off by default") {
		t.Errorf("did not expect default-off hint for explicit -http=none, got: %s", out)
	}
	if !strings.Contains(out, "approver: disabled") {
		t.Errorf("expected 'approver: disabled' for explicit -http=none, got: %s", out)
	}
	if !strings.Contains(out, `"event":"policy_banner"`) {
		t.Errorf("expected machine-readable companion line to still print, got: %s", out)
	}
}

// TestStartupBannerExplicitAddr: operator passed -http 127.0.0.1:0 and the
// listener is up. Banner should show INFO with the resolved URL.
func TestStartupBannerExplicitAddr(t *testing.T) {
	summary := policy.NewEngine(policy.DefaultRules()).Describe()
	// approverDisabled=false, httpExplicit=true, approvalURL set
	out := captureStderr(t, func() {
		emitStartupBanner(summary, "http://127.0.0.1:8081", false, true)
	})

	if !strings.Contains(out, "[INFO]") {
		t.Errorf("expected INFO marker, got: %s", out)
	}
	if !strings.Contains(out, "approver: http://127.0.0.1:8081") {
		t.Errorf("expected approver URL in banner, got: %s", out)
	}
	if strings.Contains(out, "WARN") {
		t.Errorf("did not expect WARN when approver is set, got: %s", out)
	}
}

func TestStartupBannerNoPauseRulesNoWarn(t *testing.T) {
	// Pure-flag ruleset: no approver needed, so empty URL should not warn.
	summary := policy.NewEngine([]policy.Rule{
		{Name: "flag_all", Enabled: true, Action: "flag"},
	}).Describe()
	out := captureStderr(t, func() { emitStartupBanner(summary, "", false, false) })

	if strings.Contains(out, "WARN") {
		t.Errorf("did not expect WARN for flag-only ruleset, got: %s", out)
	}
}

// TestStartupBannerWarnsWhenApproverMissing covers the edge case where
// approverDisabled=false but approvalURL is also empty (i.e. no listener and
// no explicit opt-out). This should not happen in normal operation (the default
// is now "none" so approverDisabled will be true), but the WARN path must
// remain reachable for safety.
func TestStartupBannerWarnsWhenApproverMissing(t *testing.T) {
	summary := policy.NewEngine(policy.DefaultRules()).Describe()
	// approverDisabled=false and approvalURL="" — the unusual "neither" case
	out := captureStderr(t, func() { emitStartupBanner(summary, "", false, true) })

	if !strings.Contains(out, "[WARN]") {
		t.Errorf("expected WARN marker in banner, got: %s", out)
	}
	if !strings.Contains(out, "approver: NONE") {
		t.Errorf("expected 'approver: NONE' in banner, got: %s", out)
	}
	if !strings.Contains(out, "pause rules will fail") {
		t.Errorf("expected pause-rules-will-fail hint, got: %s", out)
	}
	if !strings.Contains(out, "pause_high_risk") {
		t.Errorf("expected pause rule name listed, got: %s", out)
	}
	if !strings.Contains(out, `"event":"policy_banner"`) {
		t.Errorf("expected machine-readable companion line, got: %s", out)
	}
}

// TestStartupBannerInfoWhenApproverSet covers the normal opt-in case:
// operator passed -http 127.0.0.1:8081 and the listener is up.
func TestStartupBannerInfoWhenApproverSet(t *testing.T) {
	summary := policy.NewEngine(policy.DefaultRules()).Describe()
	out := captureStderr(t, func() { emitStartupBanner(summary, "http://127.0.0.1:8081", false, true) })

	if !strings.Contains(out, "[INFO]") {
		t.Errorf("expected INFO marker, got: %s", out)
	}
	if !strings.Contains(out, "approver: http://127.0.0.1:8081") {
		t.Errorf("expected approver URL in banner, got: %s", out)
	}
	if strings.Contains(out, "WARN") {
		t.Errorf("did not expect WARN when approver is set, got: %s", out)
	}
}

// TestBindFailureDiagnostic verifies that the actionable error message on a
// busy port names the address and suggests both remediation options. It calls
// the same formatBindFailure helper main.go uses, so the test fails if the
// real output regresses (rather than asserting against a re-implemented copy).
// The os.Exit(1) is not exercised here — that's integration-level.
func TestBindFailureDiagnostic(t *testing.T) {
	// Reproduce a real bind failure so the err string in the message matches
	// what an operator would actually see.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not bind listener for test setup: %v", err)
	}
	defer ln.Close()
	busyAddr := ln.Addr().String()

	_, bindErr := net.Listen("tcp", busyAddr)
	if bindErr == nil {
		t.Skip("could not reproduce busy-port condition on this platform")
	}

	msg := formatBindFailure(busyAddr, bindErr)

	for _, want := range []string{
		busyAddr,
		bindErr.Error(),
		"Fix:",
		"-http 127.0.0.1:0",
		"-http=none",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("bind-failure message missing %q:\n%s", want, msg)
		}
	}
}

func TestApprovalRejectionResponseDistinguishesCases(t *testing.T) {
	cases := []struct {
		status   audit.ApprovalStatus
		wantCode int
		wantMsg  string
	}{
		{audit.ApprovalDenied, -32002, "denied by approval workflow"},
		{audit.ApprovalTimedOut, -32002, "timed out"},
		{audit.ApprovalNoApprover, -32003, "no approver configured"},
	}
	for _, c := range cases {
		t.Run(string(c.status), func(t *testing.T) {
			code, msg := approvalRejectionResponse("create_pull_request", "pause_high_risk", 70, "abc", c.status, 15*time.Second)
			if code != c.wantCode {
				t.Errorf("code = %d, want %d", code, c.wantCode)
			}
			if !strings.Contains(msg, c.wantMsg) {
				t.Errorf("msg = %q, should contain %q", msg, c.wantMsg)
			}
		})
	}
}

func TestBuildApprovalDeniedMessageNoApprover(t *testing.T) {
	got := buildApprovalDeniedMessage("create_pull_request", "pause_high_risk", 70, "abc", audit.ApprovalNoApprover, 15*time.Second)
	for _, want := range []string{
		"no approver configured",
		"pause_high_risk",
		"create_pull_request",
		"-http",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in message, got %q", want, got)
		}
	}
}

func TestDiagnoseConfigNoApproverWithPauseRules(t *testing.T) {
	report, healthy := DiagnoseConfig("", "", func(url string) (string, error) {
		t.Fatalf("probe should not be called when URL empty")
		return "", nil
	})

	if healthy {
		t.Errorf("expected unhealthy when pause rules exist but no approver, got healthy")
	}
	if len(report.Issues) == 0 {
		t.Errorf("expected at least one issue")
	}
	if report.ApproverReach != "not_configured" {
		t.Errorf("approver reach = %q, want not_configured", report.ApproverReach)
	}
	if len(report.PauseRules) == 0 {
		t.Errorf("expected pause rules listed from defaults")
	}
}

func TestDiagnoseConfigHealthyWithReachableApprover(t *testing.T) {
	report, healthy := DiagnoseConfig("", "http://example.invalid", func(url string) (string, error) {
		return "HTTP 200", nil
	})

	if !healthy {
		t.Errorf("expected healthy when approver probe succeeds, got issues: %v", report.Issues)
	}
	if report.ApproverReach != "reachable" {
		t.Errorf("approver reach = %q, want reachable", report.ApproverReach)
	}
}

func TestDiagnoseConfigUnreachableApproverIsUnhealthy(t *testing.T) {
	report, healthy := DiagnoseConfig("", "http://example.invalid", func(url string) (string, error) {
		return "", errors.New("connection refused")
	})

	if healthy {
		t.Errorf("expected unhealthy when approver unreachable")
	}
	if report.ApproverReach != "unreachable" {
		t.Errorf("approver reach = %q, want unreachable", report.ApproverReach)
	}
}

// ---------------------------------------------------------------------------
// resolveVersion
// ---------------------------------------------------------------------------

func TestResolveVersionFallback(t *testing.T) {
	// version is the package-level var set by ldflags. Save and restore it.
	orig := version
	version = ""
	t.Cleanup(func() { version = orig })

	// When no ldflags version is set and this runs under `go test` (devel),
	// resolveVersion must return a non-empty string — either the module
	// version or "dev".
	got := resolveVersion()
	if got == "" {
		t.Error("resolveVersion() returned empty string")
	}
}

func TestResolveVersionLDFlags(t *testing.T) {
	orig := version
	version = "v1.2.3"
	t.Cleanup(func() { version = orig })

	if got := resolveVersion(); got != "v1.2.3" {
		t.Errorf("resolveVersion() = %q, want %q", got, "v1.2.3")
	}
}

// ---------------------------------------------------------------------------
// generateToken
// ---------------------------------------------------------------------------

func TestGenerateTokenLength(t *testing.T) {
	tok := generateToken(16)
	// 16 bytes → 32 hex chars.
	if len(tok) != 32 {
		t.Errorf("generateToken(16) len = %d, want 32", len(tok))
	}
}

func TestGenerateTokenUnique(t *testing.T) {
	a, b := generateToken(16), generateToken(16)
	if a == b {
		t.Errorf("generateToken produced identical tokens: %s", a)
	}
}

func TestGenerateTokenHexCharset(t *testing.T) {
	tok := generateToken(32)
	for _, c := range tok {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("generateToken returned non-hex character %q in %q", c, tok)
		}
	}
}

// ---------------------------------------------------------------------------
// emitPolicyEvent
// ---------------------------------------------------------------------------

func TestEmitPolicyEventLogsStructuredLine(t *testing.T) {
	out := captureStderr(t, func() {
		emitPolicyEvent("create_pr", "pause_high_risk", 75, "pause", "http://127.0.0.1:7778", "approved", 120)
	})

	for _, want := range []string{
		`tool="create_pr"`,
		`rule="pause_high_risk"`,
		`risk=75`,
		`action="pause"`,
		`approver="http://127.0.0.1:7778"`,
		`outcome="approved"`,
		`duration_ms=120`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("emitPolicyEvent output missing %q:\n%s", want, out)
		}
	}
}

func TestEmitPolicyEventNoApproverShowsNONE(t *testing.T) {
	out := captureStderr(t, func() {
		emitPolicyEvent("delete_file", "block_deletes", 90, "block", "", "blocked", 0)
	})
	if !strings.Contains(out, `approver="NONE"`) {
		t.Errorf("expected approver=NONE when URL is empty, got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// buildApprovalDeniedMessage — default (unknown status) branch
// ---------------------------------------------------------------------------

func TestBuildApprovalDeniedMessageDefaultBranch(t *testing.T) {
	// Use an ApprovalStatus value that doesn't match Denied, TimedOut or NoApprover.
	got := buildApprovalDeniedMessage("tool", "rule", 50, "id", audit.ApprovalStatus("unknown"), time.Second)
	if !strings.Contains(got, "denied by approval workflow") {
		t.Errorf("default branch should contain 'denied by approval workflow', got %q", got)
	}
}

// ---------------------------------------------------------------------------
// approvalHTTPHandler — unit tests via httptest using the production buildApprovalMux
// ---------------------------------------------------------------------------

func TestApprovalHandlerApproveAfterConsumed(t *testing.T) {
	// Verifies that the HTTP approve handler returns 404 when the approval ID
	// has already been consumed (no pending waiter).
	token := generateToken(16)
	approvals := audit.NewApprovalManager()
	mux := buildApprovalMux(approvals, token)
	approvalID := generateToken(8)

	result := make(chan audit.ApprovalStatus, 1)
	go func() {
		result <- approvals.WaitForApproval(context.Background(), approvalID, 3*time.Second)
	}()

	// Spin until WaitForApproval has registered, consuming it via direct Approve.
	deadline := time.Now().Add(2 * time.Second)
	for !approvals.Approve(approvalID) {
		if time.Now().After(deadline) {
			t.Fatal("WaitForApproval did not register within 2s")
		}
		time.Sleep(time.Millisecond)
	}

	// The waiter was already consumed — HTTP handler should return 404.
	req := httptest.NewRequest(http.MethodPost, "/api/tool-calls/"+approvalID+"/approve", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("post-consumed approve: status = %d, want 404", rec.Code)
	}

	select {
	case status := <-result:
		if status != audit.ApprovalApproved {
			t.Errorf("WaitForApproval = %s, want approved", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for approval status")
	}
}

func TestApprovalHandlerApproveFlowHTTP(t *testing.T) {
	// This test exercises the full HTTP handler approve path end-to-end
	// by registering a pending waiter first, then sending the approve request.
	token := generateToken(16)
	approvals := audit.NewApprovalManager()
	mux := buildApprovalMux(approvals, token)
	approvalID := generateToken(8)

	// Register the waiter synchronously so it's definitely present before the HTTP call.
	ch := make(chan audit.ApprovalStatus, 1)

	// We embed WaitForApproval inline: register via direct map access is internal,
	// so instead start the goroutine and poll until it has registered.
	go func() {
		ch <- approvals.WaitForApproval(context.Background(), approvalID, 5*time.Second)
	}()

	// Poll via HTTP until the waiter registers; 10ms between attempts to avoid CPU churn.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for waiter to register")
		}
		req := httptest.NewRequest(http.MethodPost, "/api/tool-calls/"+approvalID+"/approve", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			break
		}
		// 404 means not registered yet — back off briefly.
		time.Sleep(10 * time.Millisecond)
	}

	select {
	case status := <-ch:
		if status != audit.ApprovalApproved {
			t.Errorf("WaitForApproval = %s, want approved", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for approval status")
	}
}

func TestApprovalHandlerDenyFlow(t *testing.T) {
	token := generateToken(16)
	approvals := audit.NewApprovalManager()
	mux := buildApprovalMux(approvals, token)
	approvalID := generateToken(8)

	result := make(chan audit.ApprovalStatus, 1)
	go func() {
		result <- approvals.WaitForApproval(context.Background(), approvalID, 5*time.Second)
	}()

	// Spin until the waiter goroutine has registered its channel, then send deny via HTTP.
	deadline := time.Now().Add(2 * time.Second)
	for {
		time.Sleep(time.Millisecond)
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for waiter to register")
		}
		req := httptest.NewRequest(http.MethodPost, "/api/tool-calls/"+approvalID+"/deny", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			break
		}
	}

	select {
	case status := <-result:
		if status != audit.ApprovalDenied {
			t.Errorf("WaitForApproval = %s, want denied", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for denial status")
	}
}

func TestApprovalHandlerWrongToken(t *testing.T) {
	token := generateToken(16)
	mux := buildApprovalMux(audit.NewApprovalManager(), token)

	req := httptest.NewRequest(http.MethodPost, "/api/tool-calls/id/approve", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", rec.Code)
	}
}

func TestApprovalHandlerShortPath(t *testing.T) {
	token := generateToken(16)
	mux := buildApprovalMux(audit.NewApprovalManager(), token)

	// /api/tool-calls/approve has only 4 path parts — missing the action segment.
	req := httptest.NewRequest(http.MethodPost, "/api/tool-calls/approve", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("short path: status = %d, want 400", rec.Code)
	}
}

func TestApprovalHandlerNoPendingApproval(t *testing.T) {
	token := generateToken(16)
	mux := buildApprovalMux(audit.NewApprovalManager(), token)

	req := httptest.NewRequest(http.MethodPost, "/api/tool-calls/nonexistent/approve", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("no pending: status = %d, want 404", rec.Code)
	}
}

func TestApprovalHandlerNoPendingDeny(t *testing.T) {
	token := generateToken(16)
	mux := buildApprovalMux(audit.NewApprovalManager(), token)

	req := httptest.NewRequest(http.MethodPost, "/api/tool-calls/nonexistent/deny", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("no pending deny: status = %d, want 404", rec.Code)
	}
}

func TestApprovalHandlerUnknownAction(t *testing.T) {
	token := generateToken(16)
	mux := buildApprovalMux(audit.NewApprovalManager(), token)

	req := httptest.NewRequest(http.MethodPost, "/api/tool-calls/id/badaction", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown action: status = %d, want 404", rec.Code)
	}
}

func TestApprovalHandlerGetMethodIsNotFound(t *testing.T) {
	token := generateToken(16)
	mux := buildApprovalMux(audit.NewApprovalManager(), token)

	req := httptest.NewRequest(http.MethodGet, "/api/tool-calls/id/approve", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("GET approve: status = %d, want 404", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// DiagnoseConfig with rules file
// ---------------------------------------------------------------------------

func TestDiagnoseConfigWithRulesFile(t *testing.T) {
	dir := t.TempDir()
	rulesPath := dir + "/rules.yaml"
	if err := os.WriteFile(rulesPath, []byte(`rules:
  - name: flag_all
    enabled: true
    action: flag
`), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	report, healthy := DiagnoseConfig(rulesPath, "", func(url string) (string, error) {
		return "", nil
	})

	// flag_all has no pause rules, so no approver issues.
	if !healthy {
		t.Errorf("expected healthy for flag-only ruleset, got issues: %v", report.Issues)
	}
	if report.RulesPath != rulesPath {
		t.Errorf("RulesPath = %q, want %q", report.RulesPath, rulesPath)
	}
	if len(report.FlagRules) == 0 {
		t.Errorf("expected at least one flag rule in FlagRules")
	}
}

func TestDiagnoseConfigBadRulesFile(t *testing.T) {
	report, healthy := DiagnoseConfig("/nonexistent/rules.yaml", "", func(url string) (string, error) {
		return "", nil
	})
	if healthy {
		t.Errorf("expected unhealthy for missing rules file")
	}
	if len(report.Issues) == 0 {
		t.Errorf("expected issues for bad rules file")
	}
}

// ---------------------------------------------------------------------------
// emitStartupBanner — block rules and disabled rules branches
// ---------------------------------------------------------------------------

func TestStartupBannerWithBlockRules(t *testing.T) {
	summary := policy.NewEngine([]policy.Rule{
		{Name: "block_deletes", Enabled: true, Action: "block"},
		{Name: "flag_reads", Enabled: true, Action: "flag"},
	}).Describe()
	out := captureStderr(t, func() { emitStartupBanner(summary, "", true, false) })

	if !strings.Contains(out, "block_deletes") {
		t.Errorf("expected block rule name in banner, got: %s", out)
	}
	if !strings.Contains(out, "block") {
		t.Errorf("expected 'block' in banner, got: %s", out)
	}
}

func TestStartupBannerWithDisabledRules(t *testing.T) {
	summary := policy.NewEngine([]policy.Rule{
		{Name: "active_rule", Enabled: true, Action: "flag"},
		{Name: "disabled_rule", Enabled: false, Action: "block"},
	}).Describe()
	out := captureStderr(t, func() { emitStartupBanner(summary, "http://example.com", false, true) })

	if !strings.Contains(out, "disabled") {
		t.Errorf("expected 'disabled' in banner when rules are disabled, got: %s", out)
	}
}

// ---------------------------------------------------------------------------
// DiagnoseConfig — healthy no-approver no-pause-rules case
// ---------------------------------------------------------------------------

func TestDiagnoseConfigNoApproverReturnsNotConfigured(t *testing.T) {
	report, _ := DiagnoseConfig("", "", func(url string) (string, error) {
		t.Fatalf("probe should not be called when URL is empty")
		return "", nil
	})
	// When approver URL is empty, the diagnosis should report not_configured.
	if report.ApproverReach != "not_configured" {
		t.Errorf("approver reach = %q, want not_configured", report.ApproverReach)
	}
}

// ---------------------------------------------------------------------------
// emitToContext nil emitter (already tested in emitter_integration_test.go
// but we cover the branch again without the build tag constraint)
// ---------------------------------------------------------------------------

func TestEmitToContextNilEmitterNoOp(t *testing.T) {
	// Must not panic with nil emitter.
	emitToContext(nil, "server", "tool", nil, nil, "", "allowed", "", "")
}

// ---------------------------------------------------------------------------
// generateToken edge cases
// ---------------------------------------------------------------------------

func TestGenerateTokenZeroLength(t *testing.T) {
	tok := generateToken(0)
	if tok != "" {
		t.Errorf("generateToken(0) = %q, want empty string", tok)
	}
}

func TestGenerateToken1Byte(t *testing.T) {
	tok := generateToken(1)
	if len(tok) != 2 {
		t.Errorf("generateToken(1) len = %d, want 2 (1 byte = 2 hex chars)", len(tok))
	}
}
