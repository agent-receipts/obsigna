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
// guard test (the proxy already vendors gopkg.in/yaml.v3 for policy, but keeping
// the guard self-contained matches the daemon's equivalent test). A new build
// begins at each `  - ` list marker inside the `builds:` section; id/main/binary
// are captured in ANY order within a build, so reformatting that reorders fields
// cannot silently misassign them.
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

// TestObsignaMCPIsPrimaryEntrypoint is the anti-regression gate (ADR-0033): the
// proxy must build from ./cmd/obsigna-mcp as the `obsigna-mcp` binary, and
// `mcp-proxy` may appear ONLY as the deprecation shim (./cmd/mcp-proxy). If
// someone reintroduces mcp-proxy as a primary entrypoint — points the obsigna-mcp
// source at an mcp-proxy binary, or builds the mcp-proxy binary from the real
// proxy source — this fails.
func TestObsignaMCPIsPrimaryEntrypoint(t *testing.T) {
	// The proxy is built by the unified obsigna train (ADR-0034 PR 2): there is no
	// per-module mcp-proxy/.goreleaser.yaml anymore, so this guard reads the single
	// GoReleaser config in the daemon module that owns the umbrella.
	yaml := readFile(t, "../../../daemon/.goreleaser.yaml")
	builds := parseGoreleaserBuilds(t, yaml)

	var primary *goreleaserBuild
	for i := range builds {
		if builds[i].main == "./cmd/obsigna-mcp" {
			primary = &builds[i]
		}
		// No build may ship the obsigna-mcp source under the mcp-proxy name.
		if builds[i].main == "./cmd/obsigna-mcp" && builds[i].binary == "mcp-proxy" {
			t.Errorf("build %q ships ./cmd/obsigna-mcp as binary mcp-proxy; the primary proxy must be 'obsigna-mcp'", builds[i].id)
		}
		// Anything named mcp-proxy must be the shim package.
		if builds[i].binary == "mcp-proxy" && builds[i].main != "./cmd/mcp-proxy" {
			t.Errorf("build %q ships binary mcp-proxy from %q; only ./cmd/mcp-proxy (the shim) may", builds[i].id, builds[i].main)
		}
	}
	if primary == nil {
		t.Fatal("no goreleaser build builds ./cmd/obsigna-mcp — the primary proxy is missing")
	}
	if primary.binary != "obsigna-mcp" {
		t.Errorf("primary proxy binary = %q, want \"obsigna-mcp\"", primary.binary)
	}
}

// TestObsignaMCPWiresProxySurface is the converse: obsigna-mcp is the real proxy,
// so it must wire the proxy engine. Asserting it imports internal/proxy keeps the
// guard honest — the primary entrypoint carries the surface; the shim does not.
func TestObsignaMCPWiresProxySurface(t *testing.T) {
	src := readFile(t, "main.go")
	if !strings.Contains(src, "internal/proxy") {
		t.Error("cmd/obsigna-mcp does not import internal/proxy; obsigna-mcp must be the primary proxy entrypoint")
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
