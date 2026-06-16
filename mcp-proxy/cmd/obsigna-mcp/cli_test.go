package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runInit tests — use t.TempDir() as dir and a fixed binPath so they are
// independent of the real home directory and installed binary.

func TestRunInit_FreshSetup(t *testing.T) {
	dir := t.TempDir()
	var errOut, out bytes.Buffer

	if err := runInit(dir, "default", false, 7778, "/usr/local/bin/mcp-proxy", &errOut, &out); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	// Data directory must exist and not contain key files or receipts.db
	// (those are no longer created by mcp-proxy init — signing is in the daemon).
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("data directory must exist: %v", err)
	}
	for _, unexpected := range []string{"default.pem", "default.pem.pub", "receipts.db"} {
		if _, err := os.Stat(filepath.Join(dir, unexpected)); err == nil {
			t.Errorf("unexpected file created by runInit: %s", unexpected)
		}
	}

	// Config snippet must contain the binary and approval port.
	snippet := out.String()
	for _, want := range []string{"/usr/local/bin/mcp-proxy", "127.0.0.1:7778"} {
		if !strings.Contains(snippet, want) {
			t.Errorf("snippet missing %q:\n%s", want, snippet)
		}
	}
	// Snippet must NOT contain removed flags.
	for _, removed := range []string{"-key", "-receipt-db"} {
		if strings.Contains(snippet, removed) {
			t.Errorf("snippet should not contain %q (flag removed):\n%s", removed, snippet)
		}
	}
}

func TestRunInit_Idempotent(t *testing.T) {
	dir := t.TempDir()
	var errOut, out bytes.Buffer

	if err := runInit(dir, "default", false, 7778, "/bin/mcp-proxy", &errOut, &out); err != nil {
		t.Fatalf("first runInit: %v", err)
	}

	var errOut2, out2 bytes.Buffer
	if err := runInit(dir, "default", false, 7778, "/bin/mcp-proxy", &errOut2, &out2); err != nil {
		t.Fatalf("second runInit should not error: %v", err)
	}

	// Snippet must still be emitted on the second run.
	if out2.Len() == 0 {
		t.Error("second run produced no config snippet")
	}
}

func TestRunInit_NameFlag(t *testing.T) {
	dir := t.TempDir()
	var errOut, out bytes.Buffer

	if err := runInit(dir, "github", false, 7778, "/bin/mcp-proxy", &errOut, &out); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	snippet := out.String()
	if !strings.Contains(snippet, `"github"`) {
		t.Errorf("snippet should contain instance name \"github\":\n%s", snippet)
	}
}

func TestRunInit_Permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not enforced on Windows")
	}
	dir := t.TempDir()
	var errOut, out bytes.Buffer

	if err := runInit(dir, "default", false, 7778, "/bin/mcp-proxy", &errOut, &out); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	// Data directory must be 0700.
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("data dir permissions = %04o, want no group/world access", perm)
	}
}

func TestRunInit_NoApproval(t *testing.T) {
	dir := t.TempDir()
	var errOut, out bytes.Buffer

	if err := runInit(dir, "default", true, 7778, "/bin/mcp-proxy", &errOut, &out); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	snippet := out.String()
	if strings.Contains(snippet, "-http") {
		t.Errorf("snippet should not contain -http when noApproval=true:\n%s", snippet)
	}
}

func TestValidInitName(t *testing.T) {
	valid := []string{"default", "github", "github-proxy", "my_server", "server.1", "A", strings.Repeat("a", 64)}
	for _, n := range valid {
		if !validInitName(n) {
			t.Errorf("validInitName(%q) = false, want true", n)
		}
	}

	invalid := []string{
		"",                      // empty
		strings.Repeat("a", 65), // too long
		"../evil",               // path traversal
		"foo/bar",               // slash
		"foo bar",               // space
		"foo\x00bar",            // NUL
		"foo$bar",               // shell metachar
	}
	for _, n := range invalid {
		if validInitName(n) {
			t.Errorf("validInitName(%q) = true, want false", n)
		}
	}
}
