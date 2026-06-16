// Command agent-receipts-hook is the deprecation shim for the renamed
// obsigna-hook binary (ADR-0036). The hook is now its own primary binary,
// obsigna-hook. This shim preserves the old agent-receipts-hook entrypoint —
// every flag is identical — by replacing its own process image with obsigna-hook
// via syscall.Exec, forwarding argv and the environment unchanged.
//
// The shim is load-bearing, not cosmetic: agent runtimes (Claude Code and
// others) invoke the hook by path from their settings (e.g. a PostToolUse
// "command": "agent-receipts-hook"), so the shim is what keeps every existing
// configuration working through the rename until users repoint at obsigna-hook.
//
// syscall.Exec (not exec.Command) keeps the shim transparent: the hook is a
// short-lived process that reads stdin and forwards one event. Replacing the
// image preserves the inherited stdin/stdout/stderr and the exit status of
// obsigna-hook, so the runtime sees exactly what it would have seen invoking
// obsigna-hook directly — and avoids forking a second process per tool call. The
// trade-off is a platform restriction to where syscall.Exec exists (darwin,
// linux) — the only release targets. The exec adds a transitional per-event exec
// on the old path; users drop it by pointing their config at obsigna-hook.
//
// This file must remain a thin shim: it deliberately does not import the hook's
// emitter wiring or re-implement its surface. The entrypoint-guard test in
// cmd/obsigna-hook asserts that, so agent-receipts-hook can never be
// reintroduced as a primary entrypoint.
package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// deprecationShimMarker identifies this entrypoint as the agent-receipts-hook →
// obsigna-hook deprecation shim. The entrypoint-guard test (cmd/obsigna-hook)
// greps for it to prove cmd/agent-receipts-hook is only ever the shim.
const deprecationShimMarker = "agent-receipts-hook-deprecation-shim"

// targetBinary is the binary the shim forwards to. Releases target darwin and
// linux only, so no platform-specific extension is needed.
const targetBinary = "obsigna-hook"

// execImage replaces the current process image with the named binary, the way
// execve(2) does. It is a package var so tests can stub it and assert it
// defaults to syscall.Exec. This MUST be syscall.Exec, never exec.Command:
// forking would add a second process per tool call and could decouple the hook's
// exit status from what the runtime observes, whereas replacing the image keeps
// the shim indistinguishable from a direct obsigna-hook invocation.
var execImage = syscall.Exec

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run prints the deprecation notice, resolves obsigna-hook, and replaces this
// process with it, forwarding args and the current environment. On success it
// does not return — the image is gone. A return means the exec never happened
// (binary missing or not executable); that is the only error path, reported with
// a non-zero exit code.
func run(args []string, stderr io.Writer) int {
	fmt.Fprintf(stderr,
		"agent-receipts-hook is deprecated; point your hook config at 'obsigna-hook'. Forwarding…\n")

	bin, err := resolveSibling(targetBinary)
	if err != nil {
		fmt.Fprintf(stderr, "agent-receipts-hook: %v\n", err)
		return 1
	}
	// argv[0] is the resolved binary path so ps/`/proc/self/cmdline` show
	// obsigna-hook, not agent-receipts-hook. The target parses os.Args[1:]
	// exactly as if invoked directly — the hook's flag surface is identical.
	argv := append([]string{bin}, args...)
	if err := execImage(bin, argv, os.Environ()); err != nil {
		fmt.Fprintf(stderr, "agent-receipts-hook: exec %s: %v\n", bin, err)
		return 1
	}
	return 0 // unreachable with the real syscall.Exec; the image is replaced
}

// resolveSibling returns the path to a binary named name, preferring one
// installed beside the current executable and falling back to $PATH. Resolving
// beside the current binary first avoids picking up an unrelated binary of the
// same name earlier on $PATH. Mirrors the mcp-proxy shim's resolver.
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
