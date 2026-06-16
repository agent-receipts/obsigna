// Command agent-receipts is the deprecation shim for the renamed `obsigna` CLI
// (ADR-0030). It preserves every subcommand the historical agent-receipts CLI
// exposed — verify, show, list, verify-event, doctor — by translating each into
// the equivalent obsigna command and exec-forwarding to the obsigna binary, so
// there is a single source of truth for behaviour. It prints a one-line
// deprecation notice to STDERR (never stdout, so piped output stays byte-clean)
// and exits with the forwarded command's status.
//
// This file must remain a thin shim: it deliberately does not re-implement the
// command surface. The entrypoint-guard test in cmd/obsigna asserts that, so
// `agent-receipts` can never be reintroduced as a primary CLI.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/agent-receipts/ar/daemon/internal/binresolve"
)

// deprecationShimMarker identifies this entrypoint as the agent-receipts → obsigna
// deprecation shim. The anti-regression guard test (cmd/obsigna) greps for it to
// prove cmd/agent-receipts is only ever the shim.
const deprecationShimMarker = "agent-receipts-deprecation-shim"

// obsignaBinary is the name of the binary the shim forwards to. Releases target
// darwin and linux only, so no platform-specific extension is needed.
const obsignaBinary = "obsigna"

// legacyMap translates each historical agent-receipts subcommand to its obsigna
// equivalent. The flat verbs verify/show map 1:1 to the obsigna flat aliases;
// list/verify-event move under the `receipt` noun; doctor stays top-level.
var legacyMap = map[string][]string{
	"verify":       {"verify"},
	"show":         {"show"},
	"list":         {"receipt", "list"},
	"verify-event": {"receipt", "verify-event"},
	"doctor":       {"doctor"},
}

func main() {
	args := os.Args[1:]
	target, ok := translate(args)
	if !ok {
		fmt.Fprintf(os.Stderr,
			"agent-receipts: unknown command %q — agent-receipts is deprecated; run 'obsigna --help' for the current commands\n",
			args[0])
		os.Exit(2)
	}
	printDeprecationNotice(os.Stderr, target)
	os.Exit(execObsigna(target, os.Stdin, os.Stdout, os.Stderr))
}

// translate maps the shim's args to the obsigna args to forward. ok is false for
// an unknown subcommand (so the caller can report it); for no args and for the
// help flags it returns ok=true with the obsigna form (no args / --help).
func translate(args []string) (target []string, ok bool) {
	if len(args) == 0 {
		// Forward with no args: obsigna prints its usage and exits non-zero,
		// matching the historical bare-invocation behaviour.
		return nil, true
	}
	switch args[0] {
	case "-h", "--help", "help":
		return []string{"--help"}, true
	}
	mapped, found := legacyMap[args[0]]
	if !found {
		return nil, false
	}
	return append(append([]string{}, mapped...), args[1:]...), true
}

// printDeprecationNotice writes the single-line notice to stderr. It is the only
// thing the shim ever writes itself; the forwarded obsigna process owns stdout
// and the rest of stderr.
func printDeprecationNotice(w io.Writer, target []string) {
	newForm := obsignaBinary
	if len(target) > 0 {
		newForm = obsignaBinary + " " + strings.Join(target, " ")
	}
	fmt.Fprintf(w, "agent-receipts is deprecated; use '%s'. Forwarding…\n", newForm)
}

// execObsigna runs the obsigna binary with target and forwards stdio, returning
// its exit code.
func execObsigna(target []string, stdin io.Reader, stdout, stderr io.Writer) int {
	bin, err := binresolve.Sibling(obsignaBinary)
	if err != nil {
		fmt.Fprintf(stderr, "agent-receipts: %v\n", err)
		return 1
	}
	cmd := exec.Command(bin, target...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		fmt.Fprintf(stderr, "agent-receipts: failed to run obsigna: %v\n", err)
		return 1
	}
	return 0
}

// The obsigna binary is located via binresolve.Sibling: beside this shim (the
// Homebrew/goreleaser layout installs both into the same bin dir), falling back
// to $PATH.
