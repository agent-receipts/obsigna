package taxonomy_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestTaxonomyDoesNotImportReceipt locks in the receipt-free invariant: the
// taxonomy package's production import graph must not transitively reach
// sdk/go/receipt. The risk/action-type primitives taxonomy needs live in the
// receipt-free leaf package sdk/go/risk, so a classifier (e.g. the thin MCP
// proxy, ADR-0033) can depend on taxonomy without pulling in the receipt writer
// surface ADR-0010 reserves for the daemon.
//
// `go list -deps` reports only the non-test (production) dependency graph, so a
// test-only import of receipt (in this package or any other) does not count.
func TestTaxonomyDoesNotImportReceipt(t *testing.T) {
	const receiptPkg = "obsigna.dev/sdk/go/receipt"

	out, err := exec.Command("go", "list", "-deps", "obsigna.dev/sdk/go/taxonomy").Output()
	if err != nil {
		t.Fatalf("go list -deps taxonomy: %v", err)
	}

	for _, dep := range strings.Fields(string(out)) {
		if dep == receiptPkg {
			t.Fatalf("taxonomy transitively imports %s; the risk/action-type primitives "+
				"must come from the receipt-free leaf sdk/go/risk so classifiers can depend "+
				"on taxonomy without the receipt writer surface (ADR-0010, ADR-0033)", receiptPkg)
		}
	}
}
