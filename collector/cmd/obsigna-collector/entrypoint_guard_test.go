package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// goreleaserBuild is one entry under the goreleaser `builds:` list.
type goreleaserBuild struct {
	id, main, binary string
}

// parseGoreleaserBuilds extracts (id, main, binary) for each build by scanning
// the YAML lines. A tiny hand parser avoids pulling a YAML dependency into a
// guard test. A new build begins at each `  - ` list marker inside the `builds:`
// section; id/main/binary are captured in ANY order within a build, so
// reformatting that reorders fields cannot silently misassign them.
func parseGoreleaserBuilds(t *testing.T, yaml string) []goreleaserBuild {
	t.Helper()
	topKey := regexp.MustCompile(`^[a-z]`)
	itemRe := regexp.MustCompile(`^  - (\w[\w-]*):\s*(\S+)`)
	keyRe := regexp.MustCompile(`^\s+(\w[\w-]*):\s*(\S+)`)

	set := func(b *goreleaserBuild, key, val string) {
		switch key {
		case "id":
			b.id = val
		case "main":
			b.main = val
		case "binary":
			b.binary = val
		}
	}

	inBuilds := false
	var builds []goreleaserBuild
	for _, line := range strings.Split(yaml, "\n") {
		if topKey.MatchString(line) {
			inBuilds = strings.HasPrefix(line, "builds:")
			continue
		}
		if !inBuilds {
			continue
		}
		if m := itemRe.FindStringSubmatch(line); m != nil {
			builds = append(builds, goreleaserBuild{})
			set(&builds[len(builds)-1], m[1], m[2])
			continue
		}
		if len(builds) == 0 {
			continue
		}
		if m := keyRe.FindStringSubmatch(line); m != nil {
			set(&builds[len(builds)-1], m[1], m[2])
		}
	}
	return builds
}

// TestObsignaCollectorIsPrimaryEntrypoint is the anti-regression gate (ADR-0035):
// the collector must build from ./cmd/obsigna-collector as the `obsigna-collector`
// binary, and `collector` may appear ONLY as the deprecation shim
// (./cmd/collector). If someone reintroduces collector as a primary entrypoint —
// points the obsigna-collector source at a collector binary, or builds the
// collector binary from the real collector source — this fails.
func TestObsignaCollectorIsPrimaryEntrypoint(t *testing.T) {
	// The collector is built by the unified obsigna train (ADR-0034 PR 2): there is
	// no per-module collector/.goreleaser.yaml anymore, so this guard reads the
	// single GoReleaser config in the daemon module that owns the umbrella.
	yaml := readFile(t, "../../../daemon/.goreleaser.yaml")
	builds := parseGoreleaserBuilds(t, yaml)

	var primary *goreleaserBuild
	for i := range builds {
		if builds[i].main == "./cmd/obsigna-collector" {
			primary = &builds[i]
		}
		// No build may ship the obsigna-collector source under the collector name.
		if builds[i].main == "./cmd/obsigna-collector" && builds[i].binary == "collector" {
			t.Errorf("build %q ships ./cmd/obsigna-collector as binary collector; the primary collector must be 'obsigna-collector'", builds[i].id)
		}
		// Anything named collector must be the shim package.
		if builds[i].binary == "collector" && builds[i].main != "./cmd/collector" {
			t.Errorf("build %q ships binary collector from %q; only ./cmd/collector (the shim) may", builds[i].id, builds[i].main)
		}
	}
	if primary == nil {
		t.Fatal("no goreleaser build builds ./cmd/obsigna-collector — the primary collector is missing")
	}
	if primary.binary != "obsigna-collector" {
		t.Errorf("primary collector binary = %q, want \"obsigna-collector\"", primary.binary)
	}
}

// TestObsignaCollectorWiresCollectorLibrary is the converse: obsigna-collector is
// the real collector, so it must wire the collector server. Asserting it imports
// the collector library keeps the guard honest — the primary entrypoint carries
// the surface; the shim does not.
func TestObsignaCollectorWiresCollectorLibrary(t *testing.T) {
	src := readFile(t, "main.go")
	if !strings.Contains(src, `agent-receipts/ar/collector"`) {
		t.Error("cmd/obsigna-collector does not import the collector library; obsigna-collector must be the primary collector entrypoint")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
