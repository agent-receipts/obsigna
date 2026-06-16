package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// noEnv is a getenv that reports every variable as unset, isolating tests from
// the real process environment.
func noEnv(string) string { return "" }

// envMap returns a getenv backed by a map for table-driven precedence tests.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "daemon.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestResolveConfig_FileLayer: with no env and no flags, file values are
// applied over the built-in defaults.
func TestResolveConfig_FileLayer(t *testing.T) {
	path := writeConfig(t, `
socket = "/run/agentreceipts/file.sock"
chain_id = "from-file"
shutdown_deadline = "750ms"
`)
	r, err := resolveConfig([]string{"--config", path}, noEnv, io.Discard)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if r.cfg.SocketPath != "/run/agentreceipts/file.sock" {
		t.Errorf("socket = %q, want file value", r.cfg.SocketPath)
	}
	if r.cfg.ChainID != "from-file" {
		t.Errorf("chain_id = %q, want file value", r.cfg.ChainID)
	}
	if r.cfg.ShutdownDeadline != 750*time.Millisecond {
		t.Errorf("shutdown_deadline = %v, want 750ms", r.cfg.ShutdownDeadline)
	}
}

// TestResolveConfig_EnvOverridesFile: an env var beats a file value (file is
// the lowest-priority layer).
func TestResolveConfig_EnvOverridesFile(t *testing.T) {
	path := writeConfig(t, `chain_id = "from-file"`+"\n")
	env := envMap(map[string]string{"AGENTRECEIPTS_CHAIN_ID": "from-env"})
	r, err := resolveConfig([]string{"--config", path}, env, io.Discard)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if r.cfg.ChainID != "from-env" {
		t.Errorf("chain_id = %q, want env to override file", r.cfg.ChainID)
	}
}

// TestResolveConfig_FlagOverridesEnvAndFile: an explicit flag beats both env
// and file. Verifies the full precedence chain file < env < flag on one key.
func TestResolveConfig_FlagOverridesEnvAndFile(t *testing.T) {
	path := writeConfig(t, `chain_id = "from-file"`+"\n")
	env := envMap(map[string]string{"AGENTRECEIPTS_CHAIN_ID": "from-env"})
	r, err := resolveConfig([]string{"--config", path, "--chain-id", "from-flag"}, env, io.Discard)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if r.cfg.ChainID != "from-flag" {
		t.Errorf("chain_id = %q, want flag to win", r.cfg.ChainID)
	}
}

// TestResolveConfig_AbsentFileKeyKeepsDefault: a key not present in the file
// must not clobber the built-in default.
func TestResolveConfig_AbsentFileKeyKeepsDefault(t *testing.T) {
	path := writeConfig(t, `chain_id = "from-file"`+"\n")
	r, err := resolveConfig([]string{"--config", path}, noEnv, io.Discard)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if r.cfg.IssuerID != "did:agent-receipts-daemon:local" {
		t.Errorf("issuer_id = %q, want default preserved when absent from file", r.cfg.IssuerID)
	}
}

// TestResolveConfig_BoolPrecedence covers the unsafe_socket_path boolean across
// all three layers.
func TestResolveConfig_BoolPrecedence(t *testing.T) {
	t.Run("file true", func(t *testing.T) {
		path := writeConfig(t, "unsafe_socket_path = true\n")
		r, err := resolveConfig([]string{"--config", path}, noEnv, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if !r.cfg.UnsafeSocketPath {
			t.Error("unsafe_socket_path from file = false, want true")
		}
	})
	t.Run("env true over file false", func(t *testing.T) {
		path := writeConfig(t, "unsafe_socket_path = false\n")
		env := envMap(map[string]string{"AGENTRECEIPTS_UNSAFE_SOCKET_PATH": "1"})
		r, err := resolveConfig([]string{"--config", path}, env, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if !r.cfg.UnsafeSocketPath {
			t.Error("env should enable unsafe_socket_path over file false")
		}
	})
	t.Run("flag true over file unset", func(t *testing.T) {
		path := writeConfig(t, "chain_id = \"x\"\n")
		r, err := resolveConfig([]string{"--config", path, "--unsafe-socket-path"}, noEnv, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if !r.cfg.UnsafeSocketPath {
			t.Error("flag should enable unsafe_socket_path")
		}
	})
	t.Run("flag false over file true", func(t *testing.T) {
		path := writeConfig(t, "unsafe_socket_path = true\n")
		r, err := resolveConfig([]string{"--config", path, "--unsafe-socket-path=false"}, noEnv, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if r.cfg.UnsafeSocketPath {
			t.Error("explicit --unsafe-socket-path=false should override file true")
		}
	})
	t.Run("env false over file true", func(t *testing.T) {
		path := writeConfig(t, "unsafe_socket_path = true\n")
		env := envMap(map[string]string{"AGENTRECEIPTS_UNSAFE_SOCKET_PATH": "0"})
		r, err := resolveConfig([]string{"--config", path}, env, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if r.cfg.UnsafeSocketPath {
			t.Error("AGENTRECEIPTS_UNSAFE_SOCKET_PATH=0 should override file true")
		}
	})
	t.Run("default false", func(t *testing.T) {
		path := writeConfig(t, "chain_id = \"x\"\n")
		r, err := resolveConfig([]string{"--config", path}, noEnv, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if r.cfg.UnsafeSocketPath {
			t.Error("unsafe_socket_path default = true, want false (safe)")
		}
	})
	t.Run("env true (word) over file false", func(t *testing.T) {
		// strconv.ParseBool accepts "true"/"yes"-style spellings beyond "1";
		// previously only "1" enabled it and any other value coerced to false.
		path := writeConfig(t, "unsafe_socket_path = false\n")
		env := envMap(map[string]string{"AGENTRECEIPTS_UNSAFE_SOCKET_PATH": "true"})
		r, err := resolveConfig([]string{"--config", path}, env, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if !r.cfg.UnsafeSocketPath {
			t.Error("AGENTRECEIPTS_UNSAFE_SOCKET_PATH=true should enable over file false")
		}
	})
	t.Run("malformed env rejected, not coerced to false over file true", func(t *testing.T) {
		path := writeConfig(t, "unsafe_socket_path = true\n")
		env := envMap(map[string]string{"AGENTRECEIPTS_UNSAFE_SOCKET_PATH": "banana"})
		if _, err := resolveConfig([]string{"--config", path}, env, io.Discard); err == nil {
			t.Fatal("expected error for malformed AGENTRECEIPTS_UNSAFE_SOCKET_PATH, got nil")
		}
	})
	t.Run("parameter-disclosure env is a free-form policy string", func(t *testing.T) {
		// As of the ADR-0012 envelope wiring, parameter_disclosure is no longer a
		// bool: it is a policy (false|true|high|<action-type list>). A non-keyword
		// value is a valid single-entry allowlist, so it is accepted here and
		// passed through verbatim; malformed policies (e.g. reserved keyword in a
		// list) are rejected later in daemon.Run via ParseDisclosurePolicy.
		path := writeConfig(t, "chain_id = \"x\"\n")
		env := envMap(map[string]string{"AGENTRECEIPTS_PARAMETER_DISCLOSURE": "filesystem.file.delete"})
		r, err := resolveConfig([]string{"--config", path}, env, io.Discard)
		if err != nil {
			t.Fatalf("resolveConfig: %v", err)
		}
		if r.cfg.ParameterDisclosure != "filesystem.file.delete" {
			t.Errorf("ParameterDisclosure = %q, want %q", r.cfg.ParameterDisclosure, "filesystem.file.delete")
		}
	})
}

// TestResolveConfig_BareConfigFlagIsError: --config with no value must be
// rejected rather than silently falling back to the default path.
func TestResolveConfig_BareConfigFlagIsError(t *testing.T) {
	if _, err := resolveConfig([]string{"--config"}, noEnv, io.Discard); err == nil {
		t.Fatal("expected error for bare --config with no path, got nil")
	}
}

// TestResolveConfig_DefaultPathLoaded: when no --config is given, the loader
// reads $XDG_DATA_HOME/agent-receipts/daemon.toml.
func TestResolveConfig_DefaultPathLoaded(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_DATA_HOME", xdg)
	dir := filepath.Join(xdg, "agent-receipts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "daemon.toml"), []byte("chain_id = \"default-path\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := resolveConfig(nil, os.Getenv, io.Discard)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if r.cfg.ChainID != "default-path" {
		t.Errorf("chain_id = %q, want value from default-path config", r.cfg.ChainID)
	}
}

// TestResolveConfig_MissingDefaultPathTolerated: with no config at the default
// path, the daemon resolves on defaults/env/flags without error.
func TestResolveConfig_MissingDefaultPathTolerated(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir()) // empty dir, no daemon.toml
	// Capture the date before and after resolveConfig to avoid a flake when
	// the call straddles a UTC midnight boundary.
	before := time.Now().UTC().Format("2006-01-02")
	r, err := resolveConfig(nil, os.Getenv, io.Discard)
	after := time.Now().UTC().Format("2006-01-02")
	if err != nil {
		t.Fatalf("resolveConfig with missing default config: %v", err)
	}
	if r.cfg.ChainID != before && r.cfg.ChainID != after {
		t.Errorf("chain_id = %q, want today's date (%q or %q)", r.cfg.ChainID, before, after)
	}
}

// TestResolveConfig_MissingExplicitConfigIsError: a --config naming a missing
// file is rejected (typo, not "no config").
func TestResolveConfig_MissingExplicitConfigIsError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.toml")
	if _, err := resolveConfig([]string{"--config", missing}, noEnv, io.Discard); err == nil {
		t.Fatal("expected error for a missing --config file, got nil")
	}
}

// TestResolveConfig_MalformedConfigIsError: a broken file surfaces an error
// rather than silently degrading.
func TestResolveConfig_MalformedConfigIsError(t *testing.T) {
	path := writeConfig(t, "socket = \n")
	if _, err := resolveConfig([]string{"--config", path}, noEnv, io.Discard); err == nil {
		t.Fatal("expected error for malformed config, got nil")
	}
}

// TestResolveConfig_EnvConfigPath: AGENTRECEIPTS_CONFIG points at the file when
// no --config flag is given, and a missing file at that path is an error
// (explicit, like --config).
func TestResolveConfig_EnvConfigPath(t *testing.T) {
	path := writeConfig(t, "chain_id = \"env-path\"\n")
	env := envMap(map[string]string{"AGENTRECEIPTS_CONFIG": path})
	r, err := resolveConfig(nil, env, io.Discard)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if r.cfg.ChainID != "env-path" {
		t.Errorf("chain_id = %q, want value from AGENTRECEIPTS_CONFIG path", r.cfg.ChainID)
	}
}

// TestResolveConfig_RepeatedConfigFlagLastWins: a repeated --config loads the
// LAST occurrence, matching Go's flag package (last-wins) so the file actually
// loaded agrees with what fs.Parse records for the registered --config flag.
func TestResolveConfig_RepeatedConfigFlagLastWins(t *testing.T) {
	first := writeConfig(t, `chain_id = "first"`+"\n")
	second := writeConfig(t, `chain_id = "second"`+"\n")
	r, err := resolveConfig([]string{"--config", first, "--config", second}, noEnv, io.Discard)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if r.cfg.ChainID != "second" {
		t.Errorf("chain_id = %q, want last --config (%q) to win", r.cfg.ChainID, "second")
	}
}

// TestPrintConfig_OutputShape: --print-config emits every key in config-file
// form so the output doubles as a starting daemon.toml, and reflects the merged
// values.
func TestPrintConfig_OutputShape(t *testing.T) {
	path := writeConfig(t, `
socket = "/run/agentreceipts/p.sock"
chain_id = "printed"
parameter_disclosure = "high"
`)
	r, err := resolveConfig([]string{"--config", path, "--print-config"}, noEnv, io.Discard)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if !r.printConfig {
		t.Fatal("printConfig flag not set")
	}
	var buf strings.Builder
	printConfig(&buf, r.cfg)
	out := buf.String()
	for _, want := range []string{
		`socket = "/run/agentreceipts/p.sock"`,
		`chain_id = "printed"`,
		`parameter_disclosure = "high"`,
		`db = `,
		`key = `,
		`shutdown_deadline = "200ms"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("print-config output missing %q\n--- output ---\n%s", want, out)
		}
	}
}
