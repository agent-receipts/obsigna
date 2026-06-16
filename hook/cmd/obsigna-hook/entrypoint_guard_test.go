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
// guard test (the hook has no other YAML need). A new build begins at each
// `  - ` list marker inside the `builds:` section; id/main/binary are captured in
// ANY order within a build, so reformatting that reorders fields cannot silently
// misassign them. Mirrors the equivalent guard in cmd/obsigna-mcp.
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

// TestObsignaHookIsPrimaryEntrypoint is the anti-regression gate (ADR-0036): the
// hook must build from ./cmd/obsigna-hook as the `obsigna-hook` binary, and
// `agent-receipts-hook` may appear ONLY as the deprecation shim
// (./cmd/agent-receipts-hook). If someone reintroduces agent-receipts-hook as a
// primary entrypoint — points the obsigna-hook source at an agent-receipts-hook
// binary, or builds the agent-receipts-hook binary from the real hook source —
// this fails.
func TestObsignaHookIsPrimaryEntrypoint(t *testing.T) {
	// The hook is built by the unified obsigna train (ADR-0034 PR 2): there is no
	// per-module hook/.goreleaser.yaml anymore, so this guard reads the single
	// GoReleaser config in the daemon module that owns the umbrella.
	yaml := readFile(t, "../../../daemon/.goreleaser.yaml")
	builds := parseGoreleaserBuilds(t, yaml)

	var primary *goreleaserBuild
	for i := range builds {
		if builds[i].main == "./cmd/obsigna-hook" {
			primary = &builds[i]
		}
		// No build may ship the obsigna-hook source under the agent-receipts-hook name.
		if builds[i].main == "./cmd/obsigna-hook" && builds[i].binary == "agent-receipts-hook" {
			t.Errorf("build %q ships ./cmd/obsigna-hook as binary agent-receipts-hook; the primary hook must be 'obsigna-hook'", builds[i].id)
		}
		// Anything named agent-receipts-hook must be the shim package.
		if builds[i].binary == "agent-receipts-hook" && builds[i].main != "./cmd/agent-receipts-hook" {
			t.Errorf("build %q ships binary agent-receipts-hook from %q; only ./cmd/agent-receipts-hook (the shim) may", builds[i].id, builds[i].main)
		}
	}
	if primary == nil {
		t.Fatal("no goreleaser build builds ./cmd/obsigna-hook — the primary hook is missing")
	}
	if primary.binary != "obsigna-hook" {
		t.Errorf("primary hook binary = %q, want \"obsigna-hook\"", primary.binary)
	}
}

// TestObsignaHookWiresEmitter is the converse: obsigna-hook is the real hook, so
// it must wire the emitter. Asserting it imports sdk/go/emitter keeps the guard
// honest — the primary entrypoint carries the surface; the shim does not.
func TestObsignaHookWiresEmitter(t *testing.T) {
	src := readFile(t, "main.go")
	if !strings.Contains(src, "sdk/go/emitter") {
		t.Error("cmd/obsigna-hook does not import sdk/go/emitter; obsigna-hook must be the primary hook entrypoint")
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
