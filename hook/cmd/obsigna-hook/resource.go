package main

import (
	"os"
	"path/filepath"
)

// absoluteResource resolves a filesystem resource path to an absolute, lexically
// cleaned path so every emitted action.target.resource is unambiguous, whatever
// relative path the runtime happened to pass (a native Write of "out.go", a Bash
// "rm build"). A resource recorded as a bare relative path is meaningless in a
// forensic trail — it cannot be located without also knowing the working
// directory the tool ran in, which the receipt does not carry.
//
// A relative resource is resolved against base — the working directory the tool
// ran in, taken from the Claude Code frame's cwd — falling back to the hook
// process's own working directory when the frame omits cwd (the hook is a child
// of the runtime and inherits that directory). An already-absolute resource is
// returned lexically cleaned.
//
// Resolution is purely lexical: no symlink evaluation or other canonicalisation,
// which is spec-level content/inode identity and out of scope here. When no
// absolute base can be determined, the cleaned (still-relative) path is returned
// rather than fabricating one — the CI gate (gate_absolute_resource_test.go)
// guards against that path silently becoming the norm.
func absoluteResource(resource, base string) string {
	if resource == "" {
		return ""
	}
	if filepath.IsAbs(resource) {
		return filepath.Clean(resource)
	}
	if !filepath.IsAbs(base) {
		if wd, err := os.Getwd(); err == nil {
			base = wd
		}
	}
	if filepath.IsAbs(base) {
		return filepath.Join(base, resource)
	}
	return filepath.Clean(resource)
}
