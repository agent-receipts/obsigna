package main

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// operatorCLIPattern matches the operator-facing read-side CLI packages
// (internal/*cli — verifycli, showcli, listcli, verifyeventcli, doctorcli,
// keyscli, disclosecli, and any future sibling). Keying on the "cli" suffix
// rather than an enumerated denylist means a newly added operator package is
// caught automatically, with no second place to remember to update.
var operatorCLIPattern = regexp.MustCompile(`^github\.com/agent-receipts/ar/daemon/internal/[a-z0-9]+cli$`)

// TestImportGraphExcludesOperatorSurface is Gate A (ADR-0031): the daemon must
// keep a lean import graph that never reaches the operator CLI surface. A
// dependency edge into internal/*cli would drag operator-only code into the
// long-running signing process and break the blast-radius claim the topology
// exists to make. The daemon legitimately shares crypto/store/canonicalization
// via internal/{anchor,chain,keysource,socket,pipeline} and sdk/go — none of
// which carry the "cli" suffix, so they are allowed.
//
// This is the source of truth for Gate A; the daemon.yml import-graph job just
// runs this test so the rule lives in one place next to the code it guards.
func TestImportGraphExcludesOperatorSurface(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps .: %v", err)
	}
	var offenders []string
	for _, dep := range strings.Fields(string(out)) {
		if operatorCLIPattern.MatchString(dep) {
			offenders = append(offenders, dep)
		}
	}
	if len(offenders) > 0 {
		t.Errorf("obsigna-daemon imports operator CLI package(s) %v; ADR-0031 requires a lean import graph — move shared code into internal/{anchor,chain,keysource,socket,pipeline} or sdk/go rather than depending on a *cli package", offenders)
	}
}
