// Package listcli implements the `obsigna receipt list` subcommand:
// query recent receipts from a daemon-written SQLite store and print them in
// tabular or JSON form. It opens the database read-only so it is safe to run
// while the daemon is the active writer.
//
// Logic lives here, away from cmd/agent-receipts/main.go, so tests can drive
// the subcommand directly with arbitrary args / captured I/O without shelling
// out to a built binary.
package listcli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"text/tabwriter"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

const (
	ExitOK         = 0
	ExitUsageError = 2
)

const defaultLimit = 50

// Run executes the list subcommand with the given args (sans the program name
// and "list" subcommand token), writing output to stdout and diagnostics to
// stderr. Returns one of the Exit* constants.
//
// envLookup is split out so tests can inject a deterministic environment
// without touching the real process env. Pass os.Getenv for the production
// caller.
func Run(args []string, stdout, stderr io.Writer, envLookup func(string) string) int {
	if envLookup == nil {
		envLookup = os.Getenv
	}
	envOr := func(key, fallback string) string {
		if v := envLookup(key); v != "" {
			return v
		}
		return fallback
	}

	fs := flag.NewFlagSet("receipt list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", envOr("AGENTRECEIPTS_DB", daemon.DefaultDBPath()), "SQLite receipt-store path (env: AGENTRECEIPTS_DB)")
	asJSON := fs.Bool("json", false, "Output raw JSON array instead of tabular text")
	limit := fs.Int("limit", defaultLimit, "Maximum number of receipts to return")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsageError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "obsigna receipt list: unexpected positional argument(s): %v\n", fs.Args())
		return ExitUsageError
	}
	if *dbPath == "" {
		fmt.Fprintln(stderr, "obsigna receipt list: --db is required (no AGENTRECEIPTS_DB and no home directory)")
		return ExitUsageError
	}
	if *limit <= 0 {
		fmt.Fprintln(stderr, "obsigna receipt list: --limit must be a positive integer")
		return ExitUsageError
	}

	s, err := store.OpenReadOnly(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "obsigna receipt list: open store: %v\n", err)
		return ExitUsageError
	}
	defer s.Close()

	lim := *limit
	receipts, err := s.QueryReceipts(store.Query{
		Limit:       &lim,
		NewestFirst: true,
	})
	if err != nil {
		fmt.Fprintf(stderr, "obsigna receipt list: query: %v\n", err)
		return ExitUsageError
	}

	if *asJSON {
		return writeJSON(stdout, stderr, receipts)
	}
	return writeTabular(stdout, receipts)
}

func writeJSON(stdout, stderr io.Writer, receipts []receipt.AgentReceipt) int {
	if receipts == nil {
		receipts = []receipt.AgentReceipt{}
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(receipts); err != nil {
		fmt.Fprintf(stderr, "obsigna receipt list: encode JSON: %v\n", err)
		return ExitUsageError
	}
	return ExitOK
}

func writeTabular(stdout io.Writer, receipts []receipt.AgentReceipt) int {
	if len(receipts) == 0 {
		fmt.Fprintln(stdout, "no receipts found")
		return ExitOK
	}

	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEQ\tTIMESTAMP\tCHAIN\tTOOL / ACTION TYPE")
	for _, r := range receipts {
		subj := r.CredentialSubject
		tool := subj.Action.ToolName
		if tool == "" {
			tool = subj.Action.Type
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n",
			subj.Chain.Sequence,
			subj.Action.Timestamp,
			subj.Chain.ChainID,
			tool,
		)
	}
	return exitFromFlush(w)
}

func exitFromFlush(w *tabwriter.Writer) int {
	if err := w.Flush(); err != nil {
		if errors.Is(err, syscall.EPIPE) || errors.Is(err, io.ErrClosedPipe) {
			return ExitOK
		}
		return ExitUsageError
	}
	return ExitOK
}
