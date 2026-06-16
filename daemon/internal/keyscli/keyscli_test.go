package keyscli

import (
	"bytes"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// isolate points the per-user default paths (config, key, db, socket) at a fresh
// temp dir so a test never reads or writes the host's real signing key or
// daemon.toml. Returns the temp dir.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir)
	// Clear every AGENTRECEIPTS_* variable keyscli reads so each test starts from
	// the defaults it sets explicitly — a host value (especially ANCHOR_LOG, which
	// would write to an unintended path, or ISSUER_ID, which would fail the
	// identity-default assertions) must not leak in.
	for _, k := range []string{
		"AGENTRECEIPTS_CONFIG", "AGENTRECEIPTS_KEY", "AGENTRECEIPTS_PUBLIC_KEY",
		"AGENTRECEIPTS_DB", "AGENTRECEIPTS_CHAIN_ID", "AGENTRECEIPTS_SOCKET",
		"AGENTRECEIPTS_ISSUER_ID", "AGENTRECEIPTS_VERIFICATION_METHOD", "AGENTRECEIPTS_ANCHOR_LOG",
	} {
		t.Setenv(k, "")
	}
	return dir
}

func TestRunGenerateThenPubkey(t *testing.T) {
	dir := isolate(t)
	keyPath := filepath.Join(dir, "signing.key")
	pubPath := keyPath + ".pub"
	t.Setenv("AGENTRECEIPTS_KEY", keyPath)

	var out, errOut bytes.Buffer
	if code := RunGenerate(nil, &out, &errOut, nil); code != ExitOK {
		t.Fatalf("generate exit = %d, want %d (stderr=%s)", code, ExitOK, errOut.String())
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("private key not written: %v", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Fatalf("public key not written: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "generated signing key: "+keyPath) ||
		!strings.Contains(got, "public key: "+pubPath) {
		t.Fatalf("generate stdout = %q, want it to name both paths", got)
	}

	// pubkey must reproduce the published key. Compare DER bytes so a benign
	// PEM whitespace difference doesn't fail the test.
	var pout, perr bytes.Buffer
	if code := RunPubkey(nil, &pout, &perr, nil); code != ExitOK {
		t.Fatalf("pubkey exit = %d, want %d (stderr=%s)", code, ExitOK, perr.String())
	}
	derived, _ := pem.Decode(pout.Bytes())
	if derived == nil || derived.Type != "PUBLIC KEY" {
		t.Fatalf("pubkey stdout is not a PUBLIC KEY PEM block: %q", pout.String())
	}
	published, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read published pub: %v", err)
	}
	pubBlock, _ := pem.Decode(published)
	if pubBlock == nil || !bytes.Equal(pubBlock.Bytes, derived.Bytes) {
		t.Fatalf("pubkey output does not match the published .pub key")
	}
}

func TestRunGenerateRefusesOverwrite(t *testing.T) {
	dir := isolate(t)
	t.Setenv("AGENTRECEIPTS_KEY", filepath.Join(dir, "signing.key"))

	if code := RunGenerate(nil, io.Discard, io.Discard, nil); code != ExitOK {
		t.Fatalf("first generate exit = %d, want %d", code, ExitOK)
	}
	var errOut bytes.Buffer
	if code := RunGenerate(nil, io.Discard, &errOut, nil); code != ExitError {
		t.Fatalf("second generate exit = %d, want %d (refuse overwrite)", code, ExitError)
	}
}

func TestRunPubkeyMissingKey(t *testing.T) {
	dir := isolate(t)
	t.Setenv("AGENTRECEIPTS_KEY", filepath.Join(dir, "absent.key"))

	var errOut bytes.Buffer
	if code := RunPubkey(nil, io.Discard, &errOut, nil); code != ExitError {
		t.Fatalf("pubkey on missing key exit = %d, want %d", code, ExitError)
	}
}

func TestRunRotate(t *testing.T) {
	dir := isolate(t)
	t.Setenv("AGENTRECEIPTS_KEY", filepath.Join(dir, "signing.key"))
	t.Setenv("AGENTRECEIPTS_DB", filepath.Join(dir, "receipts.db"))
	t.Setenv("AGENTRECEIPTS_CHAIN_ID", "test-chain")
	// Point the running-daemon guard at a socket that does not exist.
	t.Setenv("AGENTRECEIPTS_SOCKET", filepath.Join(dir, "absent.sock"))

	if code := RunGenerate(nil, io.Discard, io.Discard, nil); code != ExitOK {
		t.Fatalf("generate exit = %d, want %d", code, ExitOK)
	}

	var out, errOut bytes.Buffer
	if code := RunRotate(nil, &out, &errOut, nil); code != ExitOK {
		t.Fatalf("rotate exit = %d, want %d (stderr=%s)", code, ExitOK, errOut.String())
	}
	got := out.String()
	if !strings.Contains(got, "rotated signing key on chain test-chain") {
		t.Fatalf("rotate stdout = %q, want chain summary", got)
	}
	// The post-rotation hint must reference the new canonical command, never
	// the deprecated binary name.
	if !strings.Contains(got, "obsigna verify") {
		t.Fatalf("rotate stdout = %q, want it to mention `obsigna verify`", got)
	}
	if strings.Contains(got, "agent-receipts verify") {
		t.Fatalf("rotate stdout still references the deprecated `agent-receipts verify`: %q", got)
	}

	// The rotation receipt must carry the SAME issuer the daemon defaults to, so
	// a chain rotated via `obsigna keys rotate` and one rotated via the daemon
	// share one identity. This guards against keyscli drifting from
	// daemon.DefaultIssuerID.
	st, err := store.OpenReadOnly(filepath.Join(dir, "receipts.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	chain, err := st.GetChain("test-chain")
	if err != nil {
		t.Fatalf("get chain: %v", err)
	}
	if len(chain) == 0 {
		t.Fatal("rotation wrote no receipt to the chain")
	}
	if iss := chain[0].Issuer.ID; iss != daemon.DefaultIssuerID {
		t.Errorf("rotation receipt issuer = %q, want daemon default %q", iss, daemon.DefaultIssuerID)
	}
}

func TestRotateMissingRequiredPathsAreUsageErrors(t *testing.T) {
	dir := isolate(t)
	db := filepath.Join(dir, "receipts.db")
	cases := map[string][]string{
		"empty key": {"--key", "", "--db", db},
		"empty db":  {"--key", filepath.Join(dir, "signing.key"), "--db", ""},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var errOut bytes.Buffer
			if code := RunRotate(args, io.Discard, &errOut, nil); code != ExitUsageError {
				t.Errorf("rotate with %s exit = %d, want %d (usage error, not operational)", name, code, ExitUsageError)
			}
		})
	}
}

func TestHelpWorksWithBrokenConfig(t *testing.T) {
	dir := isolate(t)
	// Point AGENTRECEIPTS_CONFIG at a file that does not exist — baseConfig will
	// error, but --help must still succeed for every verb.
	t.Setenv("AGENTRECEIPTS_CONFIG", filepath.Join(dir, "missing.toml"))

	verbs := map[string]func([]string, io.Writer, io.Writer, func(string) string) int{
		"generate": RunGenerate,
		"pubkey":   RunPubkey,
		"rotate":   RunRotate,
	}
	for name, run := range verbs {
		t.Run(name+"/help-ok", func(t *testing.T) {
			if code := run([]string{"--help"}, io.Discard, io.Discard, nil); code != ExitOK {
				t.Errorf("%s --help exit = %d, want %d (broken config must not block help)", name, code, ExitOK)
			}
		})
		t.Run(name+"/exec-reports-config-error", func(t *testing.T) {
			var errOut bytes.Buffer
			if code := run(nil, io.Discard, &errOut, nil); code != ExitUsageError {
				t.Errorf("%s exec exit = %d, want %d (config error surfaced on execute)", name, code, ExitUsageError)
			}
		})
	}
}

func TestBaseConfigUsesDaemonIdentityDefaults(t *testing.T) {
	isolate(t)
	base, err := baseConfig(func(string) string { return "" })
	if err != nil {
		t.Fatalf("baseConfig: %v", err)
	}
	if base.IssuerID != daemon.DefaultIssuerID {
		t.Errorf("default issuer = %q, want %q", base.IssuerID, daemon.DefaultIssuerID)
	}
	if base.VerificationMethodID != daemon.DefaultVerificationMethodID {
		t.Errorf("default verification method = %q, want %q", base.VerificationMethodID, daemon.DefaultVerificationMethodID)
	}
}

// TestConfigPrecedence checks the defaults < file < env ordering keyscli relies
// on: a key path set only in the TOML config file is honoured, and an env var
// overrides the file.
func TestConfigPrecedence(t *testing.T) {
	dir := isolate(t)
	fileKey := filepath.Join(dir, "from-file.key")
	cfgPath := filepath.Join(dir, "daemon.toml")
	if err := os.WriteFile(cfgPath, []byte("key = \""+fileKey+"\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("AGENTRECEIPTS_CONFIG", cfgPath)

	// No AGENTRECEIPTS_KEY: the file value wins over the default.
	if code := RunGenerate(nil, io.Discard, io.Discard, nil); code != ExitOK {
		t.Fatalf("generate (file key) exit = %d, want %d", code, ExitOK)
	}
	if _, err := os.Stat(fileKey); err != nil {
		t.Fatalf("config-file key path not used: %v", err)
	}

	// Env overrides the file.
	envKey := filepath.Join(dir, "from-env.key")
	t.Setenv("AGENTRECEIPTS_KEY", envKey)
	if code := RunGenerate(nil, io.Discard, io.Discard, nil); code != ExitOK {
		t.Fatalf("generate (env key) exit = %d, want %d", code, ExitOK)
	}
	if _, err := os.Stat(envKey); err != nil {
		t.Fatalf("env key path did not override the config file: %v", err)
	}
}
