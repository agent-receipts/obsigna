// Package binresolve locates sibling binaries that ship together. The
// goreleaser/Homebrew layout drops obsigna, obsigna-daemon, and the
// agent-receipts deprecation shim into one bin directory, so a binary that
// needs to invoke another (obsigna → obsigna-daemon, the shim → obsigna)
// resolves it beside itself before falling back to $PATH.
package binresolve

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Sibling returns the path to a binary named name, preferring one installed
// beside the current executable and falling back to $PATH. Resolving beside the
// current binary first avoids picking up an unrelated binary of the same name
// earlier on $PATH.
func Sibling(name string) (string, error) {
	if self, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(self), name)
		if isExecutableFile(candidate) {
			return candidate, nil
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("cannot locate the %q binary (expected beside the current binary or on $PATH)", name)
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}
