//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWarnDataDirPermsUnix exercises the real wrapper against on-disk
// directories. It is Unix-only: it relies on os.Chmod honouring Unix perm bits,
// which Windows does not. dataDirPermWarning's pure logic is covered for all
// platforms in dirperms_test.go.
func TestWarnDataDirPermsUnix(t *testing.T) {
	tests := []struct {
		name     string
		mode     os.FileMode
		wantWarn bool
	}{
		{"owner-only 0700", 0o700, false},
		{"world rx 0755", 0o755, true},
		{"group rx 0750", 0o750, true},
		{"world exec only 0701", 0o701, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			withHomeDirResolver(t, func() (string, error) { return home, nil })
			withXDGDataHome(t, "") // resolve via HOME

			dir := filepath.Join(home, ".local", "share", "agent-receipts")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.Chmod(dir, tc.mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			// Confirm the FS actually applied the mode; some environments (e.g.
			// restrictive mounts) may mask bits, which would make the test
			// vacuous.
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if info.Mode().Perm() != tc.mode.Perm() {
				t.Skipf("filesystem did not honour mode %#o (got %#o); skipping", tc.mode, info.Mode().Perm())
			}

			var buf bytes.Buffer
			warnDataDirPerms(&buf)
			out := buf.String()

			if tc.wantWarn {
				if !strings.Contains(out, "WARNING") || !strings.Contains(out, dir) {
					t.Errorf("expected perm WARNING naming %q, got: %q", dir, out)
				}
				if strings.Count(out, "\n") > 1 {
					t.Errorf("expected a single warning line, got: %q", out)
				}
			} else if out != "" {
				t.Errorf("expected no warning for mode %#o, got: %q", tc.mode, out)
			}
		})
	}
}

// TestWarnDataDirPermsAbsentDir verifies the wrapper stays silent when the data
// directory does not exist (nothing created yet — common before first init).
func TestWarnDataDirPermsAbsentDir(t *testing.T) {
	home := t.TempDir()
	withHomeDirResolver(t, func() (string, error) { return home, nil })
	withXDGDataHome(t, "")

	var buf bytes.Buffer
	warnDataDirPerms(&buf)
	if out := buf.String(); out != "" {
		t.Errorf("expected no output when data dir is absent, got: %q", out)
	}
}
