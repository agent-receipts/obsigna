package main

import (
	"strings"
	"testing"
)

func discardEnv(string) string { return "" }

// TestResolveConfig_ProtocolVersionFlag pins that --protocol-version is parsed
// into the resolved action so main() can short-circuit and print the spoken
// range Gate #8 reads.
func TestResolveConfig_ProtocolVersionFlag(t *testing.T) {
	r, err := resolveConfig([]string{"--protocol-version"}, discardEnv, &strings.Builder{})
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if !r.showProtocol {
		t.Error("showProtocol = false, want true with --protocol-version")
	}
	if r.showVersion || r.initKeys || r.printConfig {
		t.Error("--protocol-version set an unrelated action flag")
	}
}

// TestResolveConfig_NoProtocolByDefault is the negative: absent the flag, the
// daemon starts normally rather than printing the protocol range.
func TestResolveConfig_NoProtocolByDefault(t *testing.T) {
	r, err := resolveConfig(nil, discardEnv, &strings.Builder{})
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if r.showProtocol {
		t.Error("showProtocol = true with no flags")
	}
}

// TestResolveVersion_PrefersLDFlagInjection pins the precedence the
// release pipeline relies on: a -ldflags "-X main.version=..." build
// wins over both Go's build info and the "dev" fallback.
func TestResolveVersion_PrefersLDFlagInjection(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	version = "v9.9.9-test"
	if got, want := resolveVersion(), "v9.9.9-test"; got != want {
		t.Errorf("resolveVersion() = %q, want %q", got, want)
	}
}

// TestResolveVersion_FallsBackToDevWhenUnset is the contract when neither
// the release pipeline injected a version nor `go install` produced a
// module version: --version must still print something useful instead of
// an empty string. "dev" matches mcp-proxy's behaviour.
func TestResolveVersion_FallsBackToDevWhenUnset(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	version = ""
	got := resolveVersion()
	// Under `go test`, debug.ReadBuildInfo() can return either an empty
	// or "(devel)" Main.Version depending on how the binary was invoked
	// — both branches must yield a non-empty, sensible string. We accept
	// either "dev" or any non-empty version-shaped value (anything that
	// isn't the empty string the operator would never want to see).
	if got == "" {
		t.Error("resolveVersion() returned empty string; --version output would be empty")
	}
}
