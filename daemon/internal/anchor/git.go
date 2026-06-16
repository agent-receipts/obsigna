package anchor

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// gitCheckpointFile is the tracked, newline-delimited-JSON log inside the git
// anchor repo. Each Write appends one Record line and commits, so the file's
// content is the same format a FileLog produces (verify reads either the
// same way) while the git commit chain adds the tamper-evident layer.
const gitCheckpointFile = "anchor.ndjson"

// GitLog is an append-only Sink that records each event as a commit in a git
// repository. It is the "different fate-sharing domain" backend of the
// checkpoint seam: the daemon commits to a directory the agent UID cannot
// write (enforced operationally by directory ownership/permissions, the same
// way FileLog's immutability rests on filesystem perms), so an attacker who
// later controls the agent cannot rewrite the anchored history alone.
//
// The git commit chain is the ONLY Merkle structure introduced — receipts stay
// linear (ADR-0008). Each commit's tree head fixes the full checkpoint log up
// to that point, so reordering or dropping an interior checkpoint breaks the
// commit chain.
//
// Implementation note: GitLog shells out to the `git` binary via os/exec
// rather than vendoring a git library — dependency-free and portable across
// macOS and Linux (the daemon's only platforms). git operations are serialised
// under mu; a repo is created on first use if the directory is empty.
type GitLog struct {
	mu  sync.Mutex
	dir string
	now func() time.Time
}

// OpenGitLog opens (initialising if absent) a git anchor repository at dir.
// dir is created with mode 0700 if it does not exist; an existing directory is
// used as-is. The repo is configured with a fixed identity so commits do not
// depend on the host's global git config (which the daemon may not have).
func OpenGitLog(dir string) (*GitLog, error) {
	if dir == "" {
		return nil, errors.New("anchor: git dir is required")
	}
	if _, err := exec.LookPath("git"); err != nil {
		return nil, fmt.Errorf("anchor: git binary not found: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("anchor: create git dir %s: %w", dir, err)
	}
	g := &GitLog{dir: dir, now: time.Now}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		if err := g.run("init", "--quiet"); err != nil {
			return nil, fmt.Errorf("anchor: git init %s: %w", dir, err)
		}
		// Pin a deterministic committer so commits never fail for want of a
		// global git identity, and never leak the host's configured one.
		if err := g.run("config", "user.email", "daemon@agent-receipts.local"); err != nil {
			return nil, fmt.Errorf("anchor: git config user.email: %w", err)
		}
		if err := g.run("config", "user.name", "obsigna-daemon"); err != nil {
			return nil, fmt.Errorf("anchor: git config user.name: %w", err)
		}
		// Disable commit signing for the anchor repo. Tamper-evidence comes from
		// the commit chain and the Ed25519-signed checkpoint payload itself, not
		// from a git commit signature — so the anchor must not fail (or stall on a
		// passphrase/signing server) just because the host enforces signed commits
		// globally.
		if err := g.run("config", "commit.gpgsign", "false"); err != nil {
			return nil, fmt.Errorf("anchor: git config commit.gpgsign: %w", err)
		}
	}
	return g, nil
}

// Write appends the record to the tracked log file and commits it. The commit
// is the durable acceptance point: a non-nil error means nothing was committed.
func (g *GitLog) Write(eventType string, payload []byte) error {
	line, err := recordLine(g.now(), eventType, payload)
	if err != nil {
		return err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	logPath := filepath.Join(g.dir, gitCheckpointFile)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("anchor: open git log %s: %w", logPath, err)
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return fmt.Errorf("anchor: append git log: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("anchor: close git log: %w", err)
	}

	if err := g.run("add", gitCheckpointFile); err != nil {
		return fmt.Errorf("anchor: git add: %w", err)
	}
	msg := fmt.Sprintf("anchor %s @ %s", eventType, g.now().UTC().Format(time.RFC3339Nano))
	if err := g.run("commit", "--quiet", "-m", msg); err != nil {
		return fmt.Errorf("anchor: git commit: %w", err)
	}
	return nil
}

// Close is a no-op: GitLog holds no long-lived handles (each Write opens and
// closes the log file and runs git fresh). Present to satisfy Sink.
func (g *GitLog) Close() error { return nil }

// run executes `git <args...>` in the repo directory. Output is captured so a
// failure surfaces git's own diagnostic rather than a bare exit code.
func (g *GitLog) run(args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = g.dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("%w: %s", err, bytes.TrimSpace(stderr.Bytes()))
		}
		return err
	}
	return nil
}
