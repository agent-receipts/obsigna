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
// file could silently desync the two. On a page that is cited to a standards
// body as evidence, a stale number is worse than none.
//
// This test closes that gap. It runs count.py, parses the page, and asserts:
//   - every on-page vector set from count.py appears as a matrix row with the
//     exact count count.py computes (and no matrix row exists that count.py does
//     not know about), and
//   - the two exact prose figures in the honesty callout (the canonicalization
//     total and the MUST-reject case count) match count.py.
//
// It lives here, in cross-sdk-tests/, because cross-sdk-tests.yml re-runs on
// every change to the vector corpora (cross-sdk-tests/** and spec/**), to this
// page, and to count.py (scripts/conformance_matrix/**) — every input that can
// move or desync these counts. count.py is invoked as the single source of
// truth rather than re-deriving counts here, so the two cannot drift.

import (
	"bytes"
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

// reconcileInputs bundles the once-loaded count.py output and page text so the
// subtests share a single python3 invocation and a single page read.
type reconcileInputs struct {
	payload countPayload
	counts  map[string]int // set name -> count, for O(1) lookup
	page    string
}

// loadReconcileInputs runs count.py --format json and reads the page. If python3
// is not on PATH (e.g. a bare local `go test` without Python), the test is
// skipped rather than failed — CI runners have python3, so the gate still fires
// where it matters.
func loadReconcileInputs(t *testing.T) reconcileInputs {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("python3 not available, skipping conformance-page reconciliation: %v", err)
	}
	cmd := exec.Command(python, countScriptPath, "--format", "json")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		// count.py prints "error: could not count vectors: <detail>" to stderr;
		// surface it so a broken vector file is diagnosable from the CI log.
		t.Fatalf("run count.py: %v\nstderr: %s", err, strings.TrimSpace(stderr.String()))
	}
	var payload countPayload
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("parse count.py JSON: %v", err)
	}
	if len(payload.Sets) == 0 {
		t.Fatal("count.py returned no vector sets")
	}
	counts := make(map[string]int, len(payload.Sets))
	for _, s := range payload.Sets {
		counts[s.Name] = s.Count
	}
	pageBytes, err := os.ReadFile(conformancePage)
	if err != nil {
		t.Fatalf("read conformance page: %v", err)
	}
	return reconcileInputs{payload: payload, counts: counts, page: string(pageBytes)}
}

// section returns the slice of the page between the first line starting with
// startPrefix (exclusive) and the next line starting with endPrefix (exclusive).
// Scoping the regex scans to the intended block means an unrelated table or a
// stray prose figure elsewhere on the page cannot be misread as a matrix row or
// as a pinned count.
func section(t *testing.T, page, startPrefix, endPrefix string) string {
	t.Helper()
	lines := strings.Split(page, "\n")
	start := -1
	for i, line := range lines {
		if strings.HasPrefix(line, startPrefix) {
			start = i + 1
			break
		}
	}
	if start == -1 {
		t.Fatalf("section start %q not found on the page", startPrefix)
	}
	end := len(lines)
	for i := start; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], endPrefix) {
			end = i
			break
		}
	}
	if end <= start {
		t.Fatalf("section %q..%q is empty", startPrefix, endPrefix)
	}
	return strings.Join(lines[start:end], "\n")
}

// matrixRow matches a results-matrix data row: a table row whose first cell is a
// markdown link, e.g. `| [canonicalization](https://…) | … | 44 |`. The link
// text is the vector-set name; the final numeric cell is the count.
var matrixRowRe = regexp.MustCompile(`^\|\s*\[([^\]]+)\]\([^)]*\)\s*\|.*\|\s*([0-9]+)\s*\|\s*$`)

// parseMatrix extracts {name: count} for every matrix row in the given section.
func parseMatrix(t *testing.T, src string) map[string]int {
	t.Helper()
	rows := map[string]int{}
	for _, line := range strings.Split(src, "\n") {
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
		t.Fatal("no matrix rows parsed from the results-matrix section")
	}
	return rows
}

var (
	proseCanonRe     = regexp.MustCompile(`(\d+) canonicalization/receipt-hash vectors`)
	proseMalformedRe = regexp.MustCompile(`(\d+)-case MUST-reject corpus`)
)

func TestConformancePageReconciles(t *testing.T) {
	in := loadReconcileInputs(t)

	// The published matrix lives under "## Results matrix" and ends at the
	// "Each linked vector set…" sentence right after the table.
	t.Run("matrix", func(t *testing.T) {
		matrixSrc := section(t, in.page, "## Results matrix", "Each linked vector set")
		pageRows := parseMatrix(t, matrixSrc)

		expected := map[string]int{}
		for _, s := range in.payload.Sets {
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
	})

	// The two exact numeric claims in the honesty callout are pinned to count.py
	// too, scoped to that Aside so an earlier figure elsewhere cannot shadow them.
	t.Run("prose", func(t *testing.T) {
		callout := section(t, in.page, `<Aside type="caution" title="Honest coverage`, "</Aside>")
		checks := []struct {
			label   string
			re      *regexp.Regexp
			setName string
		}{
			{"canonicalization total", proseCanonRe, "canonicalization"},
			{"MUST-reject case count", proseMalformedRe, "malformed (MUST-reject)"},
		}
		for _, c := range checks {
			m := c.re.FindStringSubmatch(callout)
			if m == nil {
				t.Errorf("%s: prose figure not found in the honesty callout (pattern %q)", c.label, c.re)
				continue
			}
			got, err := strconv.Atoi(m[1])
			if err != nil {
				t.Fatalf("%s: non-numeric prose figure %q", c.label, m[1])
			}
			want, ok := in.counts[c.setName]
			if !ok {
				t.Fatalf("count.py has no set named %q", c.setName)
			}
			if got != want {
				t.Errorf("%s: prose says %d, count.py says %d", c.label, got, want)
			}
		}
	})
}
