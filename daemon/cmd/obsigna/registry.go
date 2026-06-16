package main

import (
	"io"

	"github.com/agent-receipts/ar/daemon/internal/disclosecli"
	"github.com/agent-receipts/ar/daemon/internal/doctorcli"
	"github.com/agent-receipts/ar/daemon/internal/keyscli"
	"github.com/agent-receipts/ar/daemon/internal/listcli"
	"github.com/agent-receipts/ar/daemon/internal/showcli"
	"github.com/agent-receipts/ar/daemon/internal/verifycli"
	"github.com/agent-receipts/ar/daemon/internal/verifyeventcli"
)

// runFunc is the shape every subcommand implementation shares (verifycli.Run,
// keyscli.RunRotate, …): parse args, write to stdout/stderr, return an exit
// code. envLookup is injected so subcommands stay unit-testable.
type runFunc func(args []string, stdout, stderr io.Writer, envLookup func(string) string) int

// leaf is a single executable verb.
type leaf struct {
	summary string
	run     runFunc
}

// group is a noun with a set of verbs under it (e.g. `receipt`, `keys`). order
// fixes the help/listing order; leaves holds the verbs.
type group struct {
	heading string // section title in top-level help
	order   []string
	leaves  map[string]leaf
}

// aliasTarget is the grouped command a flat alias forwards to.
type aliasTarget struct {
	group string
	verb  string
}

// launcher is a noun whose `run` verb replaces the process image with a sibling
// binary (ADR-0031) instead of dispatching to a library subcommand. Launchers
// live in their own table rather than the receipt/keys tree because they exec
// rather than return, and because they must stay out of obsigna's own import
// graph (Gate A) — obsigna resolves and execs the binary, it never links it.
type launcher struct {
	summary string
	binary  string // sibling binary to exec, e.g. "obsigna-daemon"
}

// commandTree is the single source of truth for the obsigna command surface.
// Both the dispatcher and the golden surface test read it, so any drift from the
// ADR-0030 contract (the receipt + keys subtrees, the two carried-over
// diagnostics, and the closed alias set) fails CI rather than shipping silently.
//
// ADR-0030 freezes the canonical grouped form; `verify-event` and `doctor` are
// carried over from the legacy `agent-receipts` CLI so the deprecation shim can
// preserve every current subcommand. The reserved process nouns live in the
// launchers table below: `daemon` is wired (ADR-0031), `mcp` is wired
// (ADR-0033, execs obsigna-mcp), and `collector` is wired (ADR-0035, execs
// obsigna-collector).
func commandTree() tree {
	return tree{
		groupOrder: []string{"receipt", "keys"},
		groups: map[string]group{
			"receipt": {
				heading: "Receipt commands",
				order:   []string{"verify", "show", "list", "verify-event", "disclose"},
				leaves: map[string]leaf{
					"verify":       {"Verify a stored chain's signatures and hash links.", verifycli.Run},
					"show":         {"Print the full fields of a single receipt by sequence number.", showcli.Run},
					"list":         {"List recent receipts from the store.", listcli.Run},
					"verify-event": {"Verify one historical receipt's end-to-end pipeline provenance.", verifyeventcli.Run},
					"disclose":     {"Decrypt a receipt's parameters_disclosure with the forensic key.", disclosecli.Run},
				},
			},
			"keys": {
				heading: "Key commands",
				order:   []string{"generate", "pubkey", "rotate"},
				leaves: map[string]leaf{
					"generate": {"Generate a new Ed25519 signing key pair.", keyscli.RunGenerate},
					"pubkey":   {"Print the SPKI public key for the signing key.", keyscli.RunPubkey},
					"rotate":   {"Rotate the signing key (ADR-0015).", keyscli.RunRotate},
				},
			},
		},
		topOrder: []string{"doctor"},
		topLeaves: map[string]leaf{
			"doctor": {"Diagnose pipeline health end-to-end (emitter → socket → daemon → DB → verify).", doctorcli.Run},
		},
		// The flat aliases are a closed two-member set {verify, show} — the only
		// migration shortcuts ADR-0030 permits. New functionality never gets a
		// flat alias; the golden test enforces the membership.
		aliasOrder: []string{"verify", "show"},
		aliases: map[string]aliasTarget{
			"verify": {"receipt", "verify"},
			"show":   {"receipt", "show"},
		},
		launcherOrder: []string{"daemon", "mcp", "collector"},
		launchers: map[string]launcher{
			"daemon":    {"Launch the receipts daemon (execs obsigna-daemon; ADR-0031).", "obsigna-daemon"},
			"mcp":       {"Launch the MCP proxy (execs obsigna-mcp; ADR-0030, ADR-0033).", "obsigna-mcp"},
			"collector": {"Launch the receipt collector (execs obsigna-collector; ADR-0034, ADR-0035).", "obsigna-collector"},
		},
	}
}

// tree is the resolved command surface.
type tree struct {
	groupOrder    []string
	groups        map[string]group
	topOrder      []string
	topLeaves     map[string]leaf
	aliasOrder    []string
	aliases       map[string]aliasTarget
	launcherOrder []string
	launchers     map[string]launcher
}
