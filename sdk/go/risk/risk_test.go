package risk_test

import (
	"os/exec"
	"strings"
	"testing"

	"obsigna.dev/sdk/go/risk"
)

func TestLevelValues(t *testing.T) {
	cases := map[risk.Level]string{
		risk.Low:      "low",
		risk.Medium:   "medium",
		risk.High:     "high",
		risk.Critical: "critical",
	}
	for level, want := range cases {
		if string(level) != want {
			t.Errorf("risk.Level = %q, want %q", string(level), want)
		}
	}
}

func TestPTYActionTypes(t *testing.T) {
	if risk.ActionTypePTYOpen != "system.pty.open" {
		t.Errorf("ActionTypePTYOpen = %q, want system.pty.open", risk.ActionTypePTYOpen)
	}
	if risk.ActionTypePTYClose != "system.pty.close" {
		t.Errorf("ActionTypePTYClose = %q, want system.pty.close", risk.ActionTypePTYClose)
	}
}

// TestRiskIsLeaf asserts the risk package imports nothing from this module — it
// must stay a true leaf so receipt-free callers can depend on it.
func TestRiskIsLeaf(t *testing.T) {
	const modulePrefix = "obsigna.dev/"

	out, err := exec.Command("go", "list", "-deps", "obsigna.dev/sdk/go/risk").Output()
	if err != nil {
		t.Fatalf("go list -deps risk: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if dep == "obsigna.dev/sdk/go/risk" {
			continue
		}
		if strings.HasPrefix(dep, modulePrefix) {
			t.Errorf("risk must be a leaf but reaches in-module package %s", dep)
		}
	}
}
