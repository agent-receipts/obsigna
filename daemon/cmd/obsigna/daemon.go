package main

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/agent-receipts/ar/daemon/internal/binresolve"
)

// execImage replaces the current process image with the named binary, the way
// execve(2) does. It is a package var so tests can both stub it and assert that
// it defaults to syscall.Exec.
//
// This MUST be syscall.Exec, never exec.Command: forking a child would make
// obsigna the launched process's parent instead of the service manager, so the
// daemon's parent PID (part of the attestation tuple ADR-0031 preserves) would
// point at a launcher that has already exited rather than the supervisor.
// Replacing the image keeps the PID, the parent PID, the start time, and the
// inherited stdio/fds intact — indistinguishable from a direct exec.
var execImage = syscall.Exec

// runLauncher implements `obsigna <noun> <subcommand>` for a process launcher
// (ADR-0031). The sole subcommand is `run`, which execs the launcher's sibling
// binary in place and forwards the remaining args. There is no getenv parameter
// because the launched binary inherits obsigna's environment wholesale across
// the exec — there is nothing to look up here.
func runLauncher(noun string, l launcher, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, launcherUsage(noun, l))
		return exitUsageError
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, launcherUsage(noun, l))
		return exitOK
	case "run":
		return execLauncher(noun, l.binary, args[1:], stderr)
	default:
		fmt.Fprintf(stderr, "obsigna %s: unknown subcommand %q\n\n%s", noun, args[0], launcherUsage(noun, l))
		return exitUsageError
	}
}

// execLauncher resolves the launcher's binary and replaces this process with it,
// forwarding args and the current environment. On success it does not return —
// the image is gone. A return means the exec never happened (binary missing or
// not executable); that is the only error path.
func execLauncher(noun, binary string, args []string, stderr io.Writer) int {
	bin, err := binresolve.Sibling(binary)
	if err != nil {
		fmt.Fprintf(stderr, "obsigna %s run: %v\n", noun, err)
		return 1
	}
	// argv[0] is the resolved binary path so ps/`/proc/self/cmdline` show the
	// launched process, not obsigna. The target parses os.Args[1:] exactly as if
	// invoked directly.
	argv := append([]string{bin}, args...)
	if err := execImage(bin, argv, os.Environ()); err != nil {
		fmt.Fprintf(stderr, "obsigna %s run: exec %s: %v\n", noun, bin, err)
		return 1
	}
	return exitOK // unreachable with the real syscall.Exec; the image is replaced
}

// launcherUsage is the help for a process-launcher subtree.
func launcherUsage(noun string, l launcher) string {
	return fmt.Sprintf(
		"Usage: obsigna %s run [flags]\n\n"+
			"Replace this process with %s (ADR-0031), forwarding any flags and the\n"+
			"current environment. In production, the service manager's start command\n"+
			"should point straight at %s; `obsigna %s run` is the same image via PATH.\n",
		noun, l.binary, l.binary, noun)
}
