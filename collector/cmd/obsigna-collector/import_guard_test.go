package main

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// Gate A for the collector (ADR-0035) is a structural DENYLIST, not the
// fail-closed allowlist mcp-proxy uses (ADR-0033). The difference is load-bearing:
// the collector is a receipt hub (ADR-0017/ADR-0020) whose whole job is to
// persist receipts, so it *legitimately* links a store and a SQLite driver
// (sdk/go/store, modernc.org/sqlite) plus the receipt type (sdk/go/receipt). An
// allowlist that exists to keep persistence *out* — the proxy's property — is the
// wrong tool here; enumerating SQLite's large transitive tree would also be
// brittle. What the collector must *never link* is the daemon's signing/chaining
// library or the operator read-side, so we forbid exactly those imports, mirroring
// the daemon's structural Gate A (ADR-0031):
//
//   - the daemon library (the signer that owns the private key, ADR-0010) — the
//     hub must never link signing/chaining code; and
//   - any operator-facing read-side CLI package (internal/*cli) — receipt
//     verify/show/list/doctor/keys tooling has no place in a hub process.
//
// Keying on the "cli" suffix (rather than an enumerated list) means a newly added
// operator package is caught automatically. The hub's legitimate dependencies —
// sdk/go/store, sdk/go/receipt, modernc.org/sqlite, google/uuid — carry neither
// signal and are allowed.
//
// Scope, so this gate is not over-read: it bounds what the collector *links*, not
// which functions it calls within an allowed package. sdk/go/receipt is allowed (the
// hub needs the AgentReceipt type) and also exposes Sign/Create; the collector does
// not sign because it holds no signing key, not because this gate forbids the call.
// Gate A's contract is the import boundary — keep the daemon signer and the operator
// CLI out of the link.
var forbiddenImports = []forbiddenRule{
	{
		// The daemon library: the signing process (ADR-0010). The collector
		// receives already-signed receipts over HTTP; it never signs, chains, or
		// holds a key, so it must not link the daemon — directly or transitively.
		pattern: regexp.MustCompile(`^github\.com/agent-receipts/ar/daemon($|/)`),
		reason:  "the daemon library (the signer, ADR-0010); the collector is a sink, not a writer — it must never link signing/chaining code",
	},
	{
		// Operator read-side CLI packages (internal/*cli — verifycli, showcli,
		// listcli, doctorcli, keyscli, …). These belong to operator tooling, not a
		// receipt hub. Anchored on an `internal/` segment so the rule matches the
		// stated target exactly and cannot surprise-deny an unrelated package whose
		// import path merely ends in "cli".
		pattern: regexp.MustCompile(`^github\.com/agent-receipts/ar/.*internal/[a-z0-9]+cli$`),
		reason:  "an operator read-side CLI package (internal/*cli); operator tooling has no place in a hub process",
	},
}

type forbiddenRule struct {
	pattern *regexp.Regexp
	reason  string
}

// TestImportGraphExcludesSignerAndOperatorSurface is Gate A (ADR-0035): the
// collector stays a dumb append-only sink (ADR-0020). Its production import graph
// must never reach the daemon library (the signer) or any operator read-side
// (*cli) package; either would mean the hub had grown a responsibility that
// belongs to the daemon or the operator CLI, eroding the trust boundary the
// topology exists to keep crisp. Persistence (sdk/go/store, a SQLite driver) is
// the hub's job and is deliberately *allowed* — that is why this is a denylist,
// not the allowlist obsigna-mcp uses.
//
// This is the source of truth for Gate A; the collector.yml import-graph job just
// runs this test so the rule lives in one place next to the code it guards.
func TestImportGraphExcludesSignerAndOperatorSurface(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps .: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, rule := range forbiddenImports {
			if rule.pattern.MatchString(dep) {
				t.Errorf("obsigna-collector reaches forbidden package %q: %s. ADR-0035 keeps the collector a dumb sink — the daemon is the sole writer (ADR-0010) and operator tooling lives in the obsigna CLI", dep, rule.reason)
			}
		}
	}
}
