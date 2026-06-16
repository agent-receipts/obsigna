// Command obsigna is the Agent Receipts read-side CLI. It is the renamed
// successor to `agent-receipts` (ADR-0030): the canonical surface is grouped
// noun-verb (`obsigna receipt verify`, `obsigna keys rotate`), with a closed set
// of flat aliases {verify, show} preserved for the verbs that live in existing
// scripts.
//
// Subcommand logic lives in internal/{verifycli,showcli,listcli,verifyeventcli,
// doctorcli,keyscli} so each verb is testable without shelling out to the
// binary; this file is only the dispatcher and the help surface, both driven by
// the declarative tree in registry.go.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
)

const (
	exitOK         = 0
	exitUsageError = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

// run dispatches a single invocation. It is split from main so tests can drive
// it with captured I/O and an injected environment.
func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	t := commandTree()

	if len(args) == 0 {
		fmt.Fprint(stderr, t.usage())
		return exitUsageError
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, t.usage())
		return exitOK
	}

	// Process launchers (ADR-0031) exec a sibling binary in place rather than
	// calling a subcommand library, so they dispatch from their own table.
	if l, ok := t.launchers[cmd]; ok {
		return runLauncher(cmd, l, rest, stdout, stderr)
	}

	if g, ok := t.groups[cmd]; ok {
		return t.dispatchGroup(cmd, g, rest, stdout, stderr, getenv)
	}
	if lf, ok := t.topLeaves[cmd]; ok {
		return lf.run(rest, stdout, stderr, getenv)
	}
	if a, ok := t.aliases[cmd]; ok {
		return t.groups[a.group].leaves[a.verb].run(rest, stdout, stderr, getenv)
	}

	fmt.Fprintf(stderr, "obsigna: unknown command %q\n\n%s", cmd, t.usage())
	return exitUsageError
}

// dispatchGroup routes `obsigna <noun> <verb> [flags]`. A bare noun or `<noun>
// -h` prints the group's help; an unknown verb is a usage error.
func (t tree) dispatchGroup(name string, g group, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, t.groupUsage(name, g))
		return exitUsageError
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, t.groupUsage(name, g))
		return exitOK
	}
	verb := args[0]
	lf, ok := g.leaves[verb]
	if !ok {
		fmt.Fprintf(stderr, "obsigna %s: unknown subcommand %q\n\n%s", name, verb, t.groupUsage(name, g))
		return exitUsageError
	}
	return lf.run(args[1:], stdout, stderr, getenv)
}

// usage renders the top-level help: every group's verbs, the top-level
// diagnostics, and the flat aliases — all read from the tree so help and
// dispatch never drift.
func (t tree) usage() string {
	w := newUsageWriter()
	fmt.Fprintln(w.buf, "obsigna — cryptographically signed audit trails for AI agent actions")
	fmt.Fprintln(w.buf)
	fmt.Fprintln(w.buf, "Usage:")
	fmt.Fprintln(w.buf, "  obsigna <command> [flags]")

	for _, gname := range t.groupOrder {
		g := t.groups[gname]
		fmt.Fprintf(w.buf, "\n%s:\n", g.heading)
		w.start()
		for _, v := range g.order {
			fmt.Fprintf(w.tab, "  obsigna %s %s\t%s\n", gname, v, g.leaves[v].summary)
		}
		w.flush()
	}

	fmt.Fprintf(w.buf, "\nDiagnostics:\n")
	w.start()
	for _, name := range t.topOrder {
		fmt.Fprintf(w.tab, "  obsigna %s\t%s\n", name, t.topLeaves[name].summary)
	}
	w.flush()

	if len(t.launcherOrder) > 0 {
		fmt.Fprintf(w.buf, "\nProcesses:\n")
		w.start()
		for _, name := range t.launcherOrder {
			fmt.Fprintf(w.tab, "  obsigna %s run\t%s\n", name, t.launchers[name].summary)
		}
		w.flush()
	}

	fmt.Fprintf(w.buf, "\nAliases:\n")
	w.start()
	for _, name := range t.aliasOrder {
		a := t.aliases[name]
		fmt.Fprintf(w.tab, "  obsigna %s\tshortcut for 'obsigna %s %s'\n", name, a.group, a.verb)
	}
	w.flush()

	fmt.Fprintln(w.buf, "\nRun 'obsigna <command> -h' for command-specific flags.")
	return w.buf.String()
}

// usageWriter accumulates help text into a single buffer while letting each
// aligned section use its own tabwriter (column widths are per-section, so verbs
// in `receipt` don't pad against the longer `verify-event` summaries elsewhere).
type usageWriter struct {
	buf *strings.Builder
	tab *tabwriter.Writer
}

func newUsageWriter() *usageWriter {
	return &usageWriter{buf: &strings.Builder{}}
}

// start opens a fresh tab-aligned section writing into the shared buffer.
func (u *usageWriter) start() {
	u.tab = tabwriter.NewWriter(u.buf, 0, 0, 2, ' ', 0)
}

// flush writes the current section's aligned rows into the buffer.
func (u *usageWriter) flush() {
	_ = u.tab.Flush()
	u.tab = nil
}

// groupUsage renders the help for a single noun group, e.g. `obsigna receipt -h`.
func (t tree) groupUsage(name string, g group) string {
	w := newUsageWriter()
	fmt.Fprintf(w.buf, "Usage: obsigna %s <subcommand> [flags]\n\n", name)
	fmt.Fprintf(w.buf, "Subcommands:\n")
	w.start()
	for _, v := range g.order {
		fmt.Fprintf(w.tab, "  %s\t%s\n", v, g.leaves[v].summary)
	}
	w.flush()
	fmt.Fprintf(w.buf, "\nRun 'obsigna %s <subcommand> -h' for subcommand-specific flags.\n", name)
	return w.buf.String()
}
