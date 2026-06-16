package main

import (
	"os/exec"
	"strings"
	"testing"
)

// allowedNonStdlibDeps is the fail-closed allowlist of non-stdlib packages
// obsigna-hook's production graph may reach (ADR-0036's Gate A). The hook is a
// thin "read stdin → map to emitter.Event → forward to the daemon over AF_UNIX →
// exit" process. ADR-0010 makes the daemon the sole receipt writer — it owns
// redaction, hashing, signing, chaining, and persistence — so the hook must link
// only the emitter and its own event-mapping code, never the receipt store, a
// SQLite driver, receipt signing, the daemon library, or operator CLI packages.
// This gate makes that boundary structural rather than a convention.
//
// It is an ALLOWLIST, not a denylist, and that is deliberate (mirroring the
// proxy's Gate A, ADR-0033). A denylist of known persistence packages only
// catches a reintroduced store imported under those exact paths; a new embedded
// DB (go.etcd.io/bbolt, dgraph-io/badger, cockroachdb/pebble, …) would slip past.
// Persistence has no naming convention to key on, so the hook fails closed
// instead: any non-stdlib dependency not on this list trips the gate, including
// every DB driver and sdk/go/store / sdk/go/receipt / ar/daemon by construction.
// Adding a genuinely new dependency is then a deliberate, reviewed edit here.
//
// Crucially, only sdk/go/emitter is allowed from the SDK — not the whole sdk/go/
// tree — so if the emitter ever began pulling in sdk/go/receipt or sdk/go/store,
// that would surface here as an offender rather than slip in transitively.
var allowedNonStdlibDeps = []allowedDep{
	// The hook's own packages (cmd/...).
	{prefix: "github.com/agent-receipts/ar/hook/"},
	// The daemon emitter — the hook's one forwarding dependency (ADR-0010).
	{exact: "github.com/agent-receipts/ar/sdk/go/emitter"},
	{prefix: "github.com/agent-receipts/ar/sdk/go/emitter/"},
	// Session IDs (google/uuid), pulled in transitively by the emitter.
	{exact: "github.com/google/uuid"},
}

type allowedDep struct {
	exact  string
	prefix string
}

func (a allowedDep) matches(dep string) bool {
	if a.exact != "" && dep == a.exact {
		return true
	}
	return a.prefix != "" && strings.HasPrefix(dep, a.prefix)
}

// isStdlib reports whether an import path is a standard-library package. The
// standard heuristic: stdlib paths have no dot in their first segment
// (e.g. "fmt", "encoding/json", "vendor/golang.org/x/net/..."), whereas external
// modules start with a domain ("github.com/…", "gopkg.in/…").
func isStdlib(dep string) bool {
	first, _, _ := strings.Cut(dep, "/")
	return !strings.Contains(first, ".")
}

// TestImportGraphIsThinForwarder is Gate A (ADR-0036): obsigna-hook stays a thin
// forwarder. Its production import graph may contain only stdlib plus the
// allowlisted non-stdlib packages above; anything else — a receipt store, a
// SQLite or other embedded-DB driver, receipt signing, the daemon library, an
// operator CLI package, or any not-yet-reviewed dependency — fails the gate,
// because reaching it would mean the hook had grown writer responsibilities
// ADR-0010 reserves for the daemon.
//
// This is the source of truth for Gate A; the hook.yml import-graph job just runs
// this test so the rule lives in one place next to the code it guards.
func TestImportGraphIsThinForwarder(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps .: %v", err)
	}
	var offenders []string
	for _, dep := range strings.Fields(string(out)) {
		if isStdlib(dep) {
			continue
		}
		allowed := false
		for _, a := range allowedNonStdlibDeps {
			if a.matches(dep) {
				allowed = true
				break
			}
		}
		if !allowed {
			offenders = append(offenders, dep)
		}
	}
	if len(offenders) > 0 {
		t.Errorf("obsigna-hook's production graph reaches non-allowlisted package(s) %v; ADR-0036 keeps the hook a thin forwarder (the daemon is the sole receipt writer, ADR-0010). If this is a receipt store, a DB driver, receipt signing, or the daemon library, forward events via sdk/go/emitter instead. If it is a legitimate new dependency, add it to allowedNonStdlibDeps with review", offenders)
	}
}
