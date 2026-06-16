package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// noEnv is an injected environment that returns nothing, so dispatch tests don't
// pick up the host's AGENTRECEIPTS_* configuration.
func noEnv(string) string { return "" }

// runCapture invokes the dispatcher with captured stdout/stderr.
func runCapture(args []string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut, noEnv)
	return code, out.String(), errOut.String()
}

// TestAliasMatchesGrouped is the acceptance check that `obsigna verify …` and
// `obsigna receipt verify …` are the same command: pointed at the same
// (nonexistent) store they must produce byte-identical output and the same exit
// code. Same for show. This proves the alias is a true shortcut, not a
// re-implementation that could drift.
func TestAliasMatchesGrouped(t *testing.T) {
	db := filepath.Join(t.TempDir(), "absent.db")
	cases := []struct {
		alias   []string
		grouped []string
	}{
		{[]string{"verify", "--db", db}, []string{"receipt", "verify", "--db", db}},
		{[]string{"show", "--db", db, "--seq", "1"}, []string{"receipt", "show", "--db", db, "--seq", "1"}},
	}
	for _, c := range cases {
		ac, ao, ae := runCapture(c.alias)
		gc, go_, ge := runCapture(c.grouped)
		if ac != gc {
			t.Errorf("%v exit=%d, %v exit=%d; want equal", c.alias, ac, c.grouped, gc)
		}
		if ao != go_ {
			t.Errorf("%v stdout=%q, %v stdout=%q; want equal", c.alias, ao, c.grouped, go_)
		}
		if ae != ge {
			t.Errorf("%v stderr=%q, %v stderr=%q; want equal", c.alias, ae, c.grouped, ge)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, stderr := runCapture([]string{"frobnicate"})
	if code != exitUsageError {
		t.Errorf("unknown command exit = %d, want %d", code, exitUsageError)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("stderr = %q, want it to report the unknown command", stderr)
	}
}

func TestUnknownSubcommand(t *testing.T) {
	code, _, stderr := runCapture([]string{"receipt", "frobnicate"})
	if code != exitUsageError {
		t.Errorf("unknown subcommand exit = %d, want %d", code, exitUsageError)
	}
	if !strings.Contains(stderr, "unknown subcommand") {
		t.Errorf("stderr = %q, want it to report the unknown subcommand", stderr)
	}
}

func TestBareNounPrintsGroupHelp(t *testing.T) {
	code, _, stderr := runCapture([]string{"keys"})
	if code != exitUsageError {
		t.Errorf("bare noun exit = %d, want %d", code, exitUsageError)
	}
	if !strings.Contains(stderr, "Usage: obsigna keys <subcommand>") {
		t.Errorf("stderr = %q, want group usage", stderr)
	}
}

func TestTopLevelHelp(t *testing.T) {
	code, stdout, _ := runCapture([]string{"--help"})
	if code != exitOK {
		t.Errorf("--help exit = %d, want %d", code, exitOK)
	}
	for _, want := range []string{"obsigna receipt verify", "obsigna keys rotate", "obsigna doctor", "obsigna daemon run", "obsigna mcp run", "shortcut for 'obsigna receipt verify'"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("--help missing %q\n%s", want, stdout)
		}
	}
}
