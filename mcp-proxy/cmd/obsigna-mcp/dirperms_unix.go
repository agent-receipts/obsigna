//go:build unix

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// warnDataDirPerms stats the agent-receipts data directory and, when it grants
// any group/other access, writes a single grep-able WARNING line to w. It is
// expected to fire on every startup until the operator tightens the mode. The
// proxy never tightens the directory itself (see dataDirPermWarning).
//
// Errors resolving or stat-ing the directory are silent: a missing directory is
// the normal pre-init state, and a stat failure here must not block startup.
// This wrapper is Unix-only — os.MkdirAll does not honour Unix perm bits on
// Windows, so a perm warning there would be meaningless (dirperms_other.go
// provides a no-op).
func warnDataDirPerms(w io.Writer) {
	dh := xdgDataHome()
	if dh == "" {
		return
	}
	dir := filepath.Join(dh, "agent-receipts")
	info, err := os.Stat(dir)
	if err != nil {
		return
	}
	if warning := dataDirPermWarning(dir, info.Mode()); warning != "" {
		fmt.Fprintln(w, warning)
	}
}
