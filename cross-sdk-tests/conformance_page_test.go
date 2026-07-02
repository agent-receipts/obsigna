//go:build integration

package crosssdk_test

// Reconciliation gate for the published Conformance page
// (site/src/content/docs/conformance.mdx).
//
// The page's results matrix carries a vector count per row, and the page
// claims those counts are "generated, not asserted". scripts/conformance_matrix/count.py
// is the generator — it reads the frozen vector files and emits the counts.
// Nothing, though, forced the page's numbers to equal count.py's output: the
// table cells and the prose figures were hand-typed, so a change to a vector
// file (or a typo in the page) could silently desync the two. On a page that is
// cited to a standards body as evidence, a stale number is worse than none.
//
// This test closes that gap. It runs count.py, parses the page, and asserts:
//   - every on-page vector set from count.py appears as a matrix row with the
//     exact count count.py computes (and no matrix row exists that count.py does
//     not know about), and
//   - the two exact prose figures in the honesty callout (the canonicalization
//     total and the MUST-reject case count) match count.py.
//
// It lives here, in cross-sdk-tests/, because cross-sdk-tests.yml re-runs on
// every change to the vector corpora (cross-sdk-tests/** and spec/**) — exactly
// the changes that move these counts. count.py is invoked as the single source
// of truth rather than re-deriving counts here, so the two cannot drift.

import (
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	countScriptPath = "../scripts/conformance_matrix/count.py"
	conformancePage = "../site/src/content/docs/conformance.mdx"
)

type countSet struct {
	Name   string `json:"name"`
	Count  int    `json:"count"`
	OnPage bool   `json:"onPage"`
}

type countPayload struct {
	Sets  []countSet `json:"sets"`
	Total int        `json:"total"`
}

// runCountScript executes count.py --format json and returns the parsed payload.
// If python3 is not on PATH (e.g. a bare local `go test` without Python), the
// test is skipped rather than failed — CI runners have python3, so the gate
// still fires where it matters.
func runCountScript(t *testing.T) countPayload {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("python3 not available, skipping conformance-page reconciliation: %v", err)
	}
	out, err := exec.Command(python, countScriptPath, "--format", "json").Output()
	if err != nil {
		t.Fatalf("run count.py: %v", err)
	}
	var payload countPayload
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("parse count.py JSON: %v", err)
	}
	if len(payload.Sets) == 0 {
		t.Fatal("count.py returned no vector sets")
	}
	return payload
}

// matrixRow matches a results-matrix data row: a table row whose first cell is a
// markdown link, e.g. `| [canonicalization](https://…) | … | 44 |`. The link
// text is the vector-set name; the final numeric cell is the count.
var matrixRowRe = regexp.MustCompile(`^\|\s*\[([^\]]+)\]\([^)]*\)\s*\|.*\|\s*([0-9]+)\s*\|\s*$`)

// parsePageMatrix extracts {name: count} for every results-matrix row on the page.
func parsePageMatrix(t *testing.T, page string) map[string]int {
	t.Helper()
	rows := map[string]int{}
	for _, line := range strings.Split(page, "\n") {
		m := matrixRowRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatalf("row %q: non-numeric count %q", m[1], m[2])
		}
		if _, dup := rows[m[1]]; dup {
			t.Fatalf("duplicate matrix row for %q", m[1])
		}
		rows[m[1]] = n
	}
	if len(rows) == 0 {
		t.Fatal("no matrix rows parsed from the conformance page")
	}
	return rows
}

func TestConformancePageMatrixReconciles(t *testing.T) {
	payload := runCountScript(t)
	pageBytes, err := os.ReadFile(conformancePage)
	if err != nil {
		t.Fatalf("read conformance page: %v", err)
	}
	page := string(pageBytes)
	pageRows := parsePageMatrix(t, page)

	// Every on-page set from count.py must appear with the exact computed count.
	expected := map[string]int{}
	for _, s := range payload.Sets {
		if !s.OnPage {
			// Off-page sets (reference fixtures) must NOT appear as matrix rows.
			if _, present := pageRows[s.Name]; present {
				t.Errorf("set %q is on_page=False in count.py but appears in the page matrix", s.Name)
			}
			continue
		}
		expected[s.Name] = s.Count
		got, present := pageRows[s.Name]
		if !present {
			t.Errorf("count.py set %q is missing from the page matrix", s.Name)
			continue
		}
		if got != s.Count {
			t.Errorf("count mismatch for %q: page=%d, count.py=%d", s.Name, got, s.Count)
		}
	}
	// No matrix row may exist that count.py does not account for.
	for name := range pageRows {
		if _, ok := expected[name]; !ok {
			t.Errorf("page matrix row %q has no corresponding on-page set in count.py", name)
		}
	}
}

// setCount returns the count.py count for a named set.
func setCount(t *testing.T, payload countPayload, name string) int {
	t.Helper()
	for _, s := range payload.Sets {
		if s.Name == name {
			return s.Count
		}
	}
	t.Fatalf("count.py has no set named %q", name)
	return 0
}

var (
	proseCanonRe     = regexp.MustCompile(`(\d+) canonicalization/receipt-hash vectors`)
	proseMalformedRe = regexp.MustCompile(`(\d+)-case MUST-reject corpus`)
)

// TestConformancePageProseFiguresReconcile pins the two exact numeric claims in
// the honesty callout to count.py, so the prose cannot drift from the matrix
// either.
func TestConformancePageProseFiguresReconcile(t *testing.T) {
	payload := runCountScript(t)
	pageBytes, err := os.ReadFile(conformancePage)
	if err != nil {
		t.Fatalf("read conformance page: %v", err)
	}
	page := string(pageBytes)

	checks := []struct {
		label   string
		re      *regexp.Regexp
		setName string
	}{
		{"canonicalization total", proseCanonRe, "canonicalization"},
		{"MUST-reject case count", proseMalformedRe, "malformed (MUST-reject)"},
	}
	for _, c := range checks {
		m := c.re.FindStringSubmatch(page)
		if m == nil {
			t.Errorf("%s: prose figure not found on the page (pattern %q)", c.label, c.re)
			continue
		}
		got, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("%s: non-numeric prose figure %q", c.label, m[1])
		}
		want := setCount(t, payload, c.setName)
		if got != want {
			t.Errorf("%s: prose says %d, count.py says %d", c.label, got, want)
		}
	}
}
