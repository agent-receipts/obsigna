package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteStarterConfig_HappyPath proves the post-condition --init relies on:
// the scaffolded config is a 0o644 file whose forensic_public_key and
// parameter_disclosure round-trip back through LoadConfigFile with the values
// we wrote.
func TestWriteStarterConfig_HappyPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.toml")
	pubPath := "/data/agent-receipts/forensic.key.pub"

	wrote, err := WriteStarterConfig(path, pubPath, DefaultParameterDisclosure)
	if err != nil {
		t.Fatalf("WriteStarterConfig: %v", err)
	}
	if !wrote {
		t.Fatal("wrote = false on a fresh path, want true")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("config missing: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("config perm = %o, want 0644", got)
	}

	fc, err := LoadConfigFile(path, true)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if fc.ForensicPublicKey == nil || *fc.ForensicPublicKey != pubPath {
		t.Errorf("forensic_public_key = %v, want %q", fc.ForensicPublicKey, pubPath)
	}
	if fc.ParameterDisclosure == nil || fc.ParameterDisclosure.Value != DefaultParameterDisclosure {
		t.Errorf("parameter_disclosure = %v, want %q", fc.ParameterDisclosure, DefaultParameterDisclosure)
	}
}

// TestWriteStarterConfig_SkipsExistingConfig: a config already on disk must be
// left byte-for-byte untouched, and the call reports (false, nil) so --init can
// tell the operator it left their config alone rather than failing.
func TestWriteStarterConfig_SkipsExistingConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.toml")
	existing := []byte("# hand-edited\nparameter_disclosure = \"high\"\n")
	if err := os.WriteFile(path, existing, 0o644); err != nil {
		t.Fatal(err)
	}

	wrote, err := WriteStarterConfig(path, "/x.pub", DefaultParameterDisclosure)
	if err != nil {
		t.Fatalf("WriteStarterConfig: %v", err)
	}
	if wrote {
		t.Error("wrote = true over an existing config, want false (must not clobber)")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(existing) {
		t.Errorf("existing config was modified:\n%s", got)
	}
}

// TestWriteStarterConfig_CreatesParentDirs mirrors GenerateForensicKey: the
// per-user agent-receipts directory may not exist yet on a first run.
func TestWriteStarterConfig_CreatesParentDirs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "agent-receipts", "daemon.toml")
	if _, err := WriteStarterConfig(path, "/x.pub", DefaultParameterDisclosure); err != nil {
		t.Fatalf("WriteStarterConfig: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected config at %s: %v", path, err)
	}
}

func TestWriteStarterConfig_RejectsEmptyPath(t *testing.T) {
	if _, err := WriteStarterConfig("", "/x.pub", DefaultParameterDisclosure); err == nil {
		t.Fatal("expected error for empty path")
	}
}

// TestWriteStarterConfig_RefusesSymlink: like the key writers, the open must not
// follow a symlink planted at the target path.
func TestWriteStarterConfig_RefusesSymlink(t *testing.T) {
	if oNoFollow == 0 {
		t.Skip("O_NOFOLLOW is a no-op on this platform")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.toml")
	link := filepath.Join(dir, "daemon.toml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteStarterConfig(link, "/x.pub", DefaultParameterDisclosure); err == nil {
		t.Fatal("expected error: must not follow a symlink at the config path")
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("symlink target was written through")
	}
}
