// Command collector is the deprecation shim for the renamed `obsigna-collector`
// binary (ADR-0035). The reference HTTP collector is now its own minimal binary,
// obsigna-collector, launched in production via `obsigna collector run`
// (ADR-0030, ADR-0034). This shim preserves the old `collector` entrypoint —
// every flag is identical — by replacing its own process image with
// obsigna-collector via syscall.Exec, forwarding argv and the environment
// unchanged. It prints a one-line deprecation notice to STDERR before the exec.
//
// syscall.Exec (not exec.Command) is deliberate: the collector is a long-running
// HTTP service. Replacing the image keeps the same PID and inherited
// stdin/stdout/stderr, so the shim adds no extra process and is indistinguishable
// from invoking obsigna-collector directly. The trade-off is platform restriction
// to where syscall.Exec exists (darwin, linux) — the only release targets,
// matching obsigna's launcher.
//
// This file must remain a thin shim: it deliberately does not import the
// collector library or re-implement its flags. The entrypoint-guard test in
// cmd/obsigna-collector asserts that, so `collector` can never be reintroduced as
// a primary entrypoint.
package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// deprecationShimMarker identifies this entrypoint as the collector →
// obsigna-collector deprecation shim. The entrypoint-guard test
// (cmd/obsigna-collector) greps for it to prove cmd/collector is only ever the
// shim.
const deprecationShimMarker = "collector-deprecation-shim"

// targetBinary is the binary the shim forwards to. Releases target darwin and
// linux only, so no platform-specific extension is needed.
const targetBinary = "obsigna-collector"

// execImage replaces the current process image with the named binary, the way
// execve(2) does. It is a package var so tests can stub it and assert it
// defaults to syscall.Exec. This MUST be syscall.Exec, never exec.Command:
// forking would insert an extra process and change the PID the service manager
// supervises, whereas replacing the image keeps the collector indistinguishable
// from a direct obsigna-collector invocation.
var execImage = syscall.Exec

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run prints the deprecation notice, resolves obsigna-collector, and replaces
// this process with it, forwarding args and the current environment. On success
// it does not return — the image is gone. A return means the exec never happened
// (binary missing or not executable); that is the only error path, reported with
// a non-zero exit code.
func run(args []string, stderr io.Writer) int {
	fmt.Fprintf(stderr,
		"collector is deprecated; use 'obsigna-collector' (or 'obsigna collector run'). Forwarding…\n")

	bin, err := resolveSibling(targetBinary)
	if err != nil {
		fmt.Fprintf(stderr, "collector: %v\n", err)
		return 1
	}
	// argv[0] is the resolved binary path so ps/`/proc/self/cmdline` show
	// obsigna-collector, not collector. The target parses os.Args[1:] exactly as
	// if invoked directly — the collector's flag surface is identical.
	argv := append([]string{bin}, args...)
	if err := execImage(bin, argv, os.Environ()); err != nil {
		fmt.Fprintf(stderr, "collector: exec %s: %v\n", bin, err)
		return 1
	}
	return 0 // unreachable with the real syscall.Exec; the image is replaced
}

// resolveSibling returns the path to a binary named name, preferring one
// installed beside the current executable and falling back to $PATH. Resolving
// beside the current binary first avoids picking up an unrelated binary of the
// same name earlier on $PATH. This mirrors daemon/internal/binresolve, which the
// collector module cannot import across the module's internal boundary.
func resolveSibling(name string) (string, error) {
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
