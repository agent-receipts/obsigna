package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-receipts/ar/daemon"
)

// initResolved builds the resolved view --init runs from, with all key paths
// and the config path under the test's XDG_DATA_HOME so runInit writes into a
// temp tree.
func initResolved() resolved {
	return resolved{
		initKeys:        true,
		forensicKeyPath: daemon.DefaultForensicKeyPath(),
		configPath:      daemon.DefaultConfigPath(),
		cfg: daemon.Config{
			KeyPath: daemon.DefaultKeyPath(),
		},
	}
}

// TestRunInit_BundlesKeysAndConfig is the post-condition the bundled --init
// promises: one command leaves the operator with both key pairs and a config
// that turns disclosure on, so a subsequent bare daemon records recoverable
// parameters.
func TestRunInit_BundlesKeysAndConfig(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	var out strings.Builder
	if err := runInit(initResolved(), &out); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	for _, p := range []string{
		daemon.DefaultKeyPath(),
		daemon.DefaultPublicKeyPath(daemon.DefaultKeyPath()),
		daemon.DefaultForensicKeyPath(),
		daemon.DefaultForensicPublicKeyPath(daemon.DefaultForensicKeyPath()),
		daemon.DefaultConfigPath(),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s to exist: %v", p, err)
		}
	}

	// The scaffolded config must actually enable disclosure against the
	// generated forensic public key.
	fc, err := daemon.LoadConfigFile(daemon.DefaultConfigPath(), true)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if fc.ParameterDisclosure == nil || fc.ParameterDisclosure.Value != daemon.DefaultParameterDisclosure {
		t.Errorf("parameter_disclosure = %v, want %q", fc.ParameterDisclosure, daemon.DefaultParameterDisclosure)
	}
	wantPub := daemon.DefaultForensicPublicKeyPath(daemon.DefaultForensicKeyPath())
	if fc.ForensicPublicKey == nil || *fc.ForensicPublicKey != wantPub {
		t.Errorf("forensic_public_key = %v, want %q", fc.ForensicPublicKey, wantPub)
	}

	// The summary must warn that disclosure is on and that the private key is
	// the recovery secret — otherwise an operator could leak it unknowingly.
	got := out.String()
	for _, want := range []string{"disclosure is ON", "off-host", daemon.DefaultForensicKeyPath()} {
		if !strings.Contains(got, want) {
			t.Errorf("summary missing %q:\n%s", want, got)
		}
	}
}

// TestRunInit_RefusesSecondRun: re-running --init must not silently regenerate a
// signing key (that would orphan every receipt signed by the first key). The
// existing-key guard in GenerateKey surfaces as an error.
func TestRunInit_RefusesSecondRun(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	if err := runInit(initResolved(), &strings.Builder{}); err != nil {
		t.Fatalf("first runInit: %v", err)
	}
	if err := runInit(initResolved(), &strings.Builder{}); err == nil {
		t.Fatal("second runInit succeeded; want an error (signing key already exists)")
	}
}

// TestRunInit_PreservesExistingConfig: a hand-edited config must survive --init.
// The keys are fresh, so generation succeeds, but the config is left untouched
// and the summary says so.
func TestRunInit_PreservesExistingConfig(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	cfgPath := daemon.DefaultConfigPath()
	if err := os.MkdirAll(daemon.DefaultConfigPath()[:strings.LastIndex(cfgPath, "/")], 0o750); err != nil {
		t.Fatal(err)
	}
	existing := []byte("parameter_disclosure = false\n")
	if err := os.WriteFile(cfgPath, existing, 0o644); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	if err := runInit(initResolved(), &out); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(existing) {
		t.Errorf("existing config was modified:\n%s", got)
	}
	if !strings.Contains(out.String(), "left unchanged") {
		t.Errorf("summary did not report the config was preserved:\n%s", out.String())
	}
	// The preserved config has disclosure off, so the summary must NOT claim it
	// is on — runInit does not parse the existing config and must not assert a
	// policy it cannot see.
	if strings.Contains(out.String(), "disclosure is ON") {
		t.Errorf("summary falsely claims disclosure is ON over a disclosure=false config:\n%s", out.String())
	}
}

// TestRunInit_HonorsExplicitConfigPath: --init must write the starter config to
// the same file the daemon will load (r.configPath), not always the XDG default,
// or a `--config X --init` operator ends up with disclosure silently off.
func TestRunInit_HonorsExplicitConfigPath(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	custom := filepath.Join(t.TempDir(), "custom", "daemon.toml")
	r := initResolved()
	r.configPath = custom

	if err := runInit(r, &strings.Builder{}); err != nil {
		t.Fatalf("runInit: %v", err)
	}
	if _, err := os.Stat(custom); err != nil {
		t.Errorf("config was not written to the explicit path %s: %v", custom, err)
	}
	// It must NOT have fallen back to the XDG default path.
	if _, err := os.Stat(daemon.DefaultConfigPath()); err == nil {
		t.Errorf("config was written to the default path despite an explicit --config")
	}
	fc, err := daemon.LoadConfigFile(custom, true)
	if err != nil {
		t.Fatalf("LoadConfigFile(%s): %v", custom, err)
	}
	if fc.ParameterDisclosure == nil || fc.ParameterDisclosure.Value != daemon.DefaultParameterDisclosure {
		t.Errorf("parameter_disclosure = %v, want %q", fc.ParameterDisclosure, daemon.DefaultParameterDisclosure)
	}
}

// TestRunInit_BootstrapsMissingExplicitConfig drives the whole chain through
// resolveConfig (not just runInit) to prove `--init --config <missing>` works:
// loadConfigLayer must tolerate the not-yet-existing file for --init, and
// runInit must then create it. A normal run with a missing --config still errors
// (asserted separately below).
func TestRunInit_BootstrapsMissingExplicitConfig(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	custom := filepath.Join(t.TempDir(), "etc", "daemon.toml")

	r, err := resolveConfig([]string{"--init", "--config", custom}, discardEnv, &strings.Builder{})
	if err != nil {
		t.Fatalf("resolveConfig(--init --config <missing>): %v", err)
	}
	if r.configPath != custom {
		t.Fatalf("resolved configPath = %q, want %q", r.configPath, custom)
	}
	if err := runInit(r, &strings.Builder{}); err != nil {
		t.Fatalf("runInit: %v", err)
	}
	if _, err := os.Stat(custom); err != nil {
		t.Errorf("config was not created at the explicit path %s: %v", custom, err)
	}
}

// TestResolveConfig_MissingExplicitConfigErrorsForNormalRun pins that the --init
// tolerance does not leak: a plain daemon run with a missing --config is still
// an error.
func TestResolveConfig_MissingExplicitConfigErrorsForNormalRun(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.toml")
	if _, err := resolveConfig([]string{"--config", missing}, discardEnv, &strings.Builder{}); err == nil {
		t.Fatal("resolveConfig(--config <missing>) succeeded; want an error for a normal run")
	}
}

// TestRunInit_PreflightRefusesPartialInstall: when a forensic key already exists
// but no signing key does, --init must refuse before generating anything — it
// must not leave a fresh signing key behind (the half-initialised state that
// would then wedge every subsequent --init at the signing-key guard).
func TestRunInit_PreflightRefusesPartialInstall(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	// Pre-create only the forensic private key.
	if _, err := daemon.GenerateForensicKey(daemon.DefaultForensicKeyPath(), ""); err != nil {
		t.Fatal(err)
	}

	if err := runInit(initResolved(), &strings.Builder{}); err == nil {
		t.Fatal("runInit succeeded; want a preflight error (forensic key already exists)")
	}
	// The signing key must not have been created.
	if _, err := os.Stat(daemon.DefaultKeyPath()); err == nil {
		t.Error("signing key was created despite the preflight failure (partial install)")
	}
}
