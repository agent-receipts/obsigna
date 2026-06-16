package main

import (
	"fmt"
	"io/fs"
)

// dataDirGroupOtherMask matches any group or world permission bit (read, write,
// or execute). The agent-receipts data home holds the daemon's SQLite store and
// signing keys; any bit here means another local user can reach those files.
const dataDirGroupOtherMask fs.FileMode = 0o077

// dataDirPermWarning returns a one-line warning when dir's permission bits grant
// any access to group or other, and "" otherwise. The check is pure (it takes
// the mode rather than touching the filesystem) so it is unit-testable on every
// platform.
//
// The directory is created 0o700, but os.MkdirAll is a no-op on a pre-existing
// directory: if ~/.agent-receipts/ already existed with broader perms, the
// proxy keeps using it. We only warn — a broad mode may be a deliberate choice
// (e.g. shared group access), so silently tightening it could surprise the
// operator. The returned line is grep-able and states both the current mode and
// the chmod that fixes it.
func dataDirPermWarning(dir string, mode fs.FileMode) string {
	perm := mode.Perm()
	if perm&dataDirGroupOtherMask == 0 {
		return ""
	}
	return fmt.Sprintf(
		"mcp-proxy: [WARNING] data directory %s has mode %04o (group/other-accessible); "+
			"the daemon's receipt store and keys may be readable by other local users — run `chmod 0700 %s` to restrict it",
		dir, perm, dir)
}
