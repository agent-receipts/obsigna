package binresolve

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSibling_FoundOnPath covers the $PATH fallback: when no sibling sits beside
// the test binary, Sibling resolves the name from $PATH.
func TestSibling_FoundOnPath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "widget")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	got, err := Sibling("widget")
	if err != nil {
		t.Fatalf("Sibling: %v", err)
	}
	if got != bin {
		t.Errorf("Sibling = %q, want %q", got, bin)
	}
}

// TestSibling_NotFound is the error path: absent from both the sibling dir and
// $PATH, Sibling reports a locatable error rather than returning an empty path.
func TestSibling_NotFound(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // an empty dir, so the name resolves nowhere
	if got, err := Sibling("nonexistent-binary"); err == nil {
		t.Errorf("Sibling = %q, want error for a missing binary", got)
	}
}

// TestSibling_IgnoresNonExecutable confirms a non-executable file of the right
// name on $PATH is not accepted (LookPath requires the exec bit).
func TestSibling_IgnoresNonExecutable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "widget"), []byte("not exec"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if got, err := Sibling("widget"); err == nil {
		t.Errorf("Sibling = %q, want error: a 0644 file is not executable", got)
	}
}
