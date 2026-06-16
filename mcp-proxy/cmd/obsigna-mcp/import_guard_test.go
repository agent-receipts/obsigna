package main

import (
	"os/exec"
	"strings"
	"testing"
)

// allowedNonStdlibDeps is the fail-closed allowlist of non-stdlib packages
// obsigna-mcp's production graph may reach (ADR-0033's Gate A). ADR-0010 makes
// the daemon the sole receipt writer — it owns redaction, hashing, signing,
// chaining, and persistence — and the proxy is only a thin emitter that forwards
// completed events over a socket (sdk/go/emitter). This gate makes that boundary
// structural rather than a convention.
//
// It is an ALLOWLIST, not a denylist, and that is deliberate. A denylist of
// known persistence packages (sdk/go/store, a SQLite driver, …) only catches a
// reintroduced store imported under those exact paths; a new embedded DB
// (go.etcd.io/bbolt, dgraph-io/badger, cockroachdb/pebble, …) would slip past.
// The daemon's Gate A can key on the structural `cli` suffix to auto-catch new
// operator packages, but persistence has no such naming convention — so the proxy
// fails closed instead: any non-stdlib dependency that is not on this list trips
// the gate, including every DB driver and `sdk/go/store`/`sdk/go/receipt`/
// `ar/daemon` by construction. Adding a genuinely new dependency is then a
// deliberate, reviewed edit to this list.
//
// Crucially, only `sdk/go/emitter` is allowed from the SDK — not the whole
// `sdk/go/` tree — so if the emitter ever began pulling in `sdk/go/receipt` or
// `sdk/go/store`, that would surface here as an offender rather than slip in
// transitively.
var allowedNonStdlibDeps = []allowedDep{
	// The proxy's own packages (internal/{audit,host,policy,proxy} and cmd/...).
	{prefix: "github.com/agent-receipts/ar/mcp-proxy/"},
	// The daemon emitter — the proxy's one writer-side dependency (ADR-0010).
	{exact: "github.com/agent-receipts/ar/sdk/go/emitter"},
	{prefix: "github.com/agent-receipts/ar/sdk/go/emitter/"},
	// Session IDs (google/uuid) and policy-rule YAML (gopkg.in/yaml.v3).
	{exact: "github.com/google/uuid"},
	{exact: "gopkg.in/yaml.v3"},
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
// (e.g. "fmt", "encoding/json", "database/sql/driver"), whereas external modules
// start with a domain ("github.com/…", "gopkg.in/…").
func isStdlib(dep string) bool {
	first, _, _ := strings.Cut(dep, "/")
	return !strings.Contains(first, ".")
}

// TestImportGraphIsThinEmitter is Gate A (ADR-0033): obsigna-mcp stays a thin
// emitter. Its production import graph may contain only stdlib plus the
// allowlisted non-stdlib packages above; anything else — a receipt store, a
// SQLite or other embedded-DB driver, receipt signing, the daemon library, or
// any not-yet-reviewed dependency — fails the gate, because reaching it would
// mean the proxy had grown writer responsibilities ADR-0010 reserves for the
// daemon.
//
// This is the source of truth for Gate A; the mcp-proxy.yml import-graph job
// just runs this test so the rule lives in one place next to the code it guards.
func TestImportGraphIsThinEmitter(t *testing.T) {
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
		t.Errorf("obsigna-mcp's production graph reaches non-allowlisted package(s) %v; ADR-0033 keeps the proxy a thin emitter (the daemon is the sole receipt writer, ADR-0010). If this is a receipt store, a DB driver, receipt signing, or the daemon library, forward events via sdk/go/emitter instead. If it is a legitimate new dependency, add it to allowedNonStdlibDeps with review", offenders)
	}
}
