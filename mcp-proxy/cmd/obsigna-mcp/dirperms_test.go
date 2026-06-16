package main

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

// TestDataDirPermWarning is the unit test for the pure perm-check helper. It is
// OS-independent (it takes an fs.FileMode, not a real directory) so it runs and
// is meaningful on every platform, including Windows CI.
//
// The mask is 0o077: any group or world bit (read, write, or execute) means the
// agent-receipts data home — which holds the daemon's SQLite store and signing
// keys — is reachable by other local users and should warn.
func TestDataDirPermWarning(t *testing.T) {
	const dir = "/home/alice/.local/share/agent-receipts"

	tests := []struct {
		name     string
		mode     fs.FileMode
		wantWarn bool
	}{
		{"owner-only 0700", 0o700, false},
		{"owner-only 0600 (no exec)", 0o600, false},
		{"owner-only 0500", 0o500, false},
		{"world rx 0755", 0o755, true},
		{"group rx 0750", 0o750, true},
		{"world rwx 0707", 0o707, true},
		{"world exec only 0701", 0o701, true},
		{"group read only 0740", 0o740, true},
		{"world read only 0704", 0o704, true},
		{"group write only 0720", 0o720, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dataDirPermWarning(dir, tc.mode)
			if tc.wantWarn && got == "" {
				t.Fatalf("dataDirPermWarning(%q, %#o) = %q, want a warning", dir, tc.mode, got)
			}
			if !tc.wantWarn {
				if got != "" {
					t.Fatalf("dataDirPermWarning(%q, %#o) = %q, want no warning", dir, tc.mode, got)
				}
				return
			}
			// A warning was produced: it must be a single grep-able line that
			// states the current mode and the chmod fix-hint.
			if strings.ContainsRune(got, '\n') {
				t.Errorf("warning must be a single line (no embedded newlines), got: %q", got)
			}
			if !strings.Contains(got, "WARNING") {
				t.Errorf("warning must contain WARNING, got: %q", got)
			}
			if !strings.Contains(got, dir) {
				t.Errorf("warning must name the directory %q, got: %q", dir, got)
			}
			// Mode is rendered as 4-digit octal (matching the daemon doctor's
			// "%04o" style).
			wantMode := fmt.Sprintf("%04o", tc.mode.Perm())
			if !strings.Contains(got, wantMode) {
				t.Errorf("warning must state the current mode %s, got: %q", wantMode, got)
			}
			if !strings.Contains(got, "chmod 0700") {
				t.Errorf("warning must include the chmod fix-hint, got: %q", got)
			}
		})
	}
}
