package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDefaultConfigPath_XDGAligned pins that the default config lives next to
// receipts.db and the signing key under $XDG_DATA_HOME/agent-receipts, so an
// operator who set XDG_DATA_HOME finds all three in one place.
func TestDefaultConfigPath_XDGAligned(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir)

	got := DefaultConfigPath()
	want := filepath.Join(dir, "agent-receipts", "daemon.toml")
	if got != want {
		t.Errorf("DefaultConfigPath() = %q, want %q", got, want)
	}

	// Same base dir as receipts.db.
	if a, b := filepath.Dir(got), filepath.Dir(DefaultDBPath()); a != b {
		t.Errorf("config dir %q != db dir %q; expected co-location", a, b)
	}
}

// TestLoadConfigFile_FullFile decodes every supported key and confirms the
// pointer fields are populated (present, not nil) and the duration string is
// parsed via time.ParseDuration.
func TestLoadConfigFile_FullFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.toml")
	content := `
socket = "/run/agentreceipts/events.sock"
db = "/data/receipts.db"
key = "/data/signing.key"
public_key = "/data/signing.key.pub"
chain_id = "prod"
issuer_id = "did:agent-receipts-daemon:host"
verification_method = "did:agent-receipts-daemon:host#k1"
parameter_disclosure = "high"
response_disclosure = ["fs.read", "net.http"]
redact_patterns = "/etc/agent-receipts/redact.yaml"
unsafe_socket_path = true
shutdown_deadline = "500ms"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	fc, err := LoadConfigFile(path, true)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if fc == nil {
		t.Fatal("LoadConfigFile returned nil for a present file")
	}
	if fc.Socket == nil || *fc.Socket != "/run/agentreceipts/events.sock" {
		t.Errorf("socket = %v", fc.Socket)
	}
	if fc.DB == nil || *fc.DB != "/data/receipts.db" {
		t.Errorf("db = %v", fc.DB)
	}
	if fc.Key == nil || *fc.Key != "/data/signing.key" {
		t.Errorf("key = %v", fc.Key)
	}
	if fc.ChainID == nil || *fc.ChainID != "prod" {
		t.Errorf("chain_id = %v", fc.ChainID)
	}
	if fc.ParameterDisclosure == nil || fc.ParameterDisclosure.Value != "high" {
		t.Errorf("parameter_disclosure = %v", fc.ParameterDisclosure)
	}
	if fc.ResponseDisclosure == nil || fc.ResponseDisclosure.Value != "fs.read,net.http" {
		t.Errorf("response_disclosure = %v, want fs.read,net.http", fc.ResponseDisclosure)
	}
	if fc.UnsafeSocketPath == nil || !*fc.UnsafeSocketPath {
		t.Errorf("unsafe_socket_path = %v", fc.UnsafeSocketPath)
	}
	if fc.ShutdownDeadline == nil || fc.ShutdownDeadline.Duration != 500*time.Millisecond {
		t.Errorf("shutdown_deadline = %v", fc.ShutdownDeadline)
	}
}

// TestLoadConfigFile_AbsentKeysAreNil is the load-bearing precedence guarantee:
// a key omitted from the file must decode as nil so a lower-priority layer
// (default/env/flag) is never clobbered by the config file.
func TestLoadConfigFile_AbsentKeysAreNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.toml")
	if err := os.WriteFile(path, []byte("chain_id = \"only\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fc, err := LoadConfigFile(path, true)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if fc.ChainID == nil || *fc.ChainID != "only" {
		t.Errorf("chain_id = %v, want set", fc.ChainID)
	}
	if fc.Socket != nil {
		t.Errorf("socket = %v, want nil for an absent key", fc.Socket)
	}
	if fc.ParameterDisclosure != nil {
		t.Errorf("parameter_disclosure = %v, want nil for an absent key", fc.ParameterDisclosure)
	}
}

// TestLoadConfigFile_MissingDefaultIsTolerated: on the default path, a missing
// file is not an error — the daemon runs on flags/env alone.
func TestLoadConfigFile_MissingDefaultIsTolerated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.toml")
	fc, err := LoadConfigFile(path, false)
	if err != nil {
		t.Fatalf("LoadConfigFile(required=false) on missing file: %v", err)
	}
	if fc != nil {
		t.Errorf("expected nil FileConfig for a missing default-path file, got %+v", fc)
	}
}

// TestLoadConfigFile_MissingRequiredIsError: an explicit --config naming a
// nonexistent file is a typo, not "no config" — reject it.
func TestLoadConfigFile_MissingRequiredIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.toml")
	_, err := LoadConfigFile(path, true)
	if err == nil {
		t.Fatal("expected error for a missing --config file, got nil")
	}
}

// TestLoadConfigFile_MalformedTOMLRejected: a syntactically broken file must
// surface an error rather than silently degrading to defaults.
func TestLoadConfigFile_MalformedTOMLRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.toml")
	if err := os.WriteFile(path, []byte("socket = \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFile(path, false); err == nil {
		t.Fatal("expected parse error for malformed TOML, got nil")
	}
}

// TestLoadConfigFile_UnknownKeyRejected: a typo'd key (e.g. "sockett") would
// otherwise leave the daemon running with a config the operator didn't intend.
func TestLoadConfigFile_UnknownKeyRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.toml")
	if err := os.WriteFile(path, []byte("sockett = \"/tmp/x.sock\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfigFile(path, false)
	if err == nil {
		t.Fatal("expected error for an unknown key, got nil")
	}
}

// TestLoadConfigFile_BadDurationRejected: a non-parseable duration string must
// be rejected, not silently zeroed.
func TestLoadConfigFile_BadDurationRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.toml")
	if err := os.WriteFile(path, []byte("shutdown_deadline = \"soon\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFile(path, false); err == nil {
		t.Fatal("expected error for an invalid duration, got nil")
	}
}

// TestLoadConfigFile_EmptyPathIsError guards the contract that callers resolve
// a path before calling the loader; an empty path is a programming error, not
// a "no config" signal.
func TestLoadConfigFile_EmptyPathIsError(t *testing.T) {
	if _, err := LoadConfigFile("", false); err == nil {
		t.Fatal("expected error for an empty path, got nil")
	}
	if _, err := LoadConfigFile("", false); err != nil && errors.Is(err, os.ErrNotExist) {
		t.Fatal("empty-path error should not be a fs.ErrNotExist")
	}
}

// TestLoadConfigFile_ParameterDisclosureShapes verifies the parameter_disclosure
// key accepts a boolean (backwards compatibility with the pre-policy bool flag
// and the documented `= false` default), a string policy, and an array of
// action types (the natural TOML spelling of the allowlist) — all normalised to
// the policy string consumed by ParseDisclosurePolicy.
func TestLoadConfigFile_ParameterDisclosureShapes(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want string
	}{
		{"bool false (legacy default)", `parameter_disclosure = false`, "false"},
		{"bool true (legacy)", `parameter_disclosure = true`, "true"},
		{"string keyword", `parameter_disclosure = "high"`, "high"},
		{"string allowlist", `parameter_disclosure = "a.b,c.d"`, "a.b,c.d"},
		{"array allowlist", `parameter_disclosure = ["a.b", "c.d"]`, "a.b,c.d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "daemon.toml")
			if err := os.WriteFile(path, []byte(tc.toml+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			fc, err := LoadConfigFile(path, true)
			if err != nil {
				t.Fatalf("LoadConfigFile: %v", err)
			}
			if fc.ParameterDisclosure == nil {
				t.Fatal("parameter_disclosure decoded as nil")
			}
			if fc.ParameterDisclosure.Value != tc.want {
				t.Errorf("Value = %q, want %q", fc.ParameterDisclosure.Value, tc.want)
			}
		})
	}
}

// TestLoadConfigFile_ParameterDisclosureRejectsNonStringArray ensures a
// malformed array (non-string entries) is rejected rather than silently
// mishandled.
func TestLoadConfigFile_ParameterDisclosureRejectsNonStringArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.toml")
	if err := os.WriteFile(path, []byte("parameter_disclosure = [1, 2]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFile(path, true); err == nil {
		t.Fatal("expected error for non-string array entries")
	}
}
