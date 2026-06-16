package anchor

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitLogCommitsEachWrite(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := filepath.Join(t.TempDir(), "anchor-repo")
	g, err := OpenGitLog(dir)
	if err != nil {
		t.Fatalf("OpenGitLog: %v", err)
	}
	defer func() { _ = g.Close() }()

	if err := g.Write(EventTypeCheckpoint, []byte(`{"seq":1}`)); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if err := g.Write(EventTypeCheckpoint, []byte(`{"seq":2}`)); err != nil {
		t.Fatalf("write 2: %v", err)
	}

	// The tracked log holds both records in the shared anchor.Record format, so
	// the verify side reads a git anchor exactly like a file anchor.
	f, err := os.Open(filepath.Join(dir, gitCheckpointFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var recs []Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("git anchor line is not a Record: %v", err)
		}
		recs = append(recs, r)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs[0].EventType != EventTypeCheckpoint {
		t.Errorf("event_type = %q, want %q", recs[0].EventType, EventTypeCheckpoint)
	}

	// Each write is its own commit — the commit chain is the tamper-evident
	// Merkle structure (ADR-0008). Two writes => two commits.
	out, err := gitOutput(t, dir, "rev-list", "--count", "HEAD")
	if err != nil {
		t.Fatalf("git rev-list: %v", err)
	}
	if got := strings.TrimSpace(out); got != "2" {
		t.Errorf("commit count = %q, want 2", got)
	}
}

func TestOpenGitLogRequiresDir(t *testing.T) {
	if _, err := OpenGitLog(""); err == nil {
		t.Fatal("expected error for empty git dir")
	}
}

// TestGitLogConfiguresPreExistingRepo guards the fix for the case where an
// operator points --checkpoint-anchor at a repo they created themselves: the
// repo lacks the daemon's local identity and commit.gpgsign=false, so without
// applying config on every open, the first commit would fail on a host that
// enforces signed commits. OpenGitLog must configure an existing repo too.
func TestGitLogConfiguresPreExistingRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := filepath.Join(t.TempDir(), "preexisting")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Pre-create the repo WITHOUT the daemon's config (mirrors an operator's
	// `git init`). On a host enforcing commit signing globally this repo cannot
	// commit until commit.gpgsign=false is set locally.
	preInit := exec.Command("git", "init", "--quiet")
	preInit.Dir = dir
	if err := preInit.Run(); err != nil {
		t.Fatalf("pre-init: %v", err)
	}

	g, err := OpenGitLog(dir)
	if err != nil {
		t.Fatalf("OpenGitLog on existing repo: %v", err)
	}
	defer func() { _ = g.Close() }()

	if err := g.Write(EventTypeCheckpoint, []byte(`{"seq":1}`)); err != nil {
		t.Fatalf("write to pre-existing repo failed (config not applied?): %v", err)
	}
}

func TestGitLogRejectsInvalidJSON(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	g, err := OpenGitLog(filepath.Join(t.TempDir(), "repo"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if err := g.Write(EventTypeCheckpoint, []byte("not json")); err == nil {
		t.Fatal("expected error for invalid JSON payload")
	}
}

func gitOutput(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	return string(out), err
}
