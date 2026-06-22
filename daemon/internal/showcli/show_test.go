package showcli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"obsigna.dev/sdk/go/receipt"
	"obsigna.dev/sdk/go/store"
)

// fixtureDB writes a DB at dir/receipts.db with `count` receipts on each of the
// given chain ids. Every chain is signed with the same fresh key. The receipt
// at sequence 2 of each chain carries a synthetic events_dropped drop count so
// tests can assert the action-specific payload renders.
func fixtureDB(t *testing.T, dir string, count int, chainIDs ...string) string {
	t.Helper()

	dbPath := filepath.Join(dir, "receipts.db")

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for _, chainID := range chainIDs {
		var prevHash *string
		for i := 1; i <= count; i++ {
			action := receipt.Action{
				Type:      "filesystem.file.read",
				ToolName:  "Read",
				RiskLevel: receipt.RiskLow,
				Timestamp: fmt.Sprintf("2024-01-01T%02d:00:00Z", i),
			}
			if i == 2 {
				action.Type = "agent_receipts.events_dropped"
				action.ToolName = ""
				action.EmitterMetadata = &receipt.EmitterMetadata{DropCount: 7}
			}
			unsigned := receipt.Create(receipt.CreateInput{
				Issuer:    receipt.Issuer{ID: "did:test"},
				Principal: receipt.Principal{ID: "did:user:test"},
				Action:    action,
				Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
				Chain:     receipt.Chain{Sequence: i, PreviousReceiptHash: prevHash, ChainID: chainID},
			})
			signed, err := receipt.Sign(unsigned, privPEM, "did:test#k1")
			if err != nil {
				t.Fatal(err)
			}
			h, err := receipt.HashReceipt(signed)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Insert(signed, h); err != nil {
				t.Fatal(err)
			}
			prevHash = &h
		}
	}
	return dbPath
}

func runOnce(t *testing.T, args []string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Run(args, &out, &errb, func(string) string { return "" })
	return code, out.String(), errb.String()
}

func TestRun_ReceiptFoundHumanOutput(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 3, "chain-1")

	code, stdout, stderr := runOnce(t, []string{"--db", dbPath, "1"})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	for _, want := range []string{"Sequence:", "Action type:", "Issuer:", "Signature:", "chain-1"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q\n%s", want, stdout)
		}
	}
}

func TestRun_EventsDroppedShowsDropCount(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 3, "chain-1")

	code, stdout, stderr := runOnce(t, []string{"--db", dbPath, "2"})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	if !strings.Contains(stdout, "Dropped count:") || !strings.Contains(stdout, "7") {
		t.Errorf("stdout should report dropped count 7\n%s", stdout)
	}
}

func TestRun_JSONOutputIsSingleReceipt(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 3, "chain-1")

	code, stdout, stderr := runOnce(t, []string{"--db", dbPath, "--json", "3"})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	var r receipt.AgentReceipt
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("JSON output not parseable as a single receipt: %v (stdout=%q)", err, stdout)
	}
	if r.CredentialSubject.Chain.Sequence != 3 {
		t.Errorf("got sequence %d, want 3", r.CredentialSubject.Chain.Sequence)
	}
}

func TestRun_FlagsAfterSeqAreParsed(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 3, "chain-a", "chain-b")

	// Flags placed after the positional <seq> (the documented ordering) must
	// still be honoured: --json controls output and --chain-id disambiguates.
	code, stdout, stderr := runOnce(t, []string{"--db", dbPath, "3", "--json", "--chain-id", "chain-b"})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	var r receipt.AgentReceipt
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("expected JSON output (--json after <seq> not parsed?): %v (stdout=%q)", err, stdout)
	}
	if r.CredentialSubject.Chain.Sequence != 3 {
		t.Errorf("got sequence %d, want 3", r.CredentialSubject.Chain.Sequence)
	}
	if r.CredentialSubject.Chain.ChainID != "chain-b" {
		t.Errorf("got chain %q, want chain-b (--chain-id after <seq> not parsed?)", r.CredentialSubject.Chain.ChainID)
	}
}

func TestRun_ReceiptNotFound(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 2, "chain-1")

	code, _, stderr := runOnce(t, []string{"--db", dbPath, "99"})
	if code != ExitNotFound {
		t.Fatalf("exit = %d, want %d", code, ExitNotFound)
	}
	if !strings.Contains(stderr, "no receipt at sequence 99") {
		t.Errorf("stderr = %q, expected not-found diagnostic", stderr)
	}
}

func TestRun_SingleChainAutoDetected(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 3, "only-chain")

	// No --chain-id: the sole chain should be used silently.
	code, stdout, stderr := runOnce(t, []string{"--db", dbPath, "1"})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	if !strings.Contains(stdout, "only-chain") {
		t.Errorf("stdout should reference the auto-detected chain\n%s", stdout)
	}
}

func TestRun_MultipleChainsWithoutChainID(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 2, "chain-a", "chain-b")

	code, _, stderr := runOnce(t, []string{"--db", dbPath, "1"})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitUsageError, stderr)
	}
	if !strings.Contains(stderr, "--chain-id") {
		t.Errorf("stderr should tell the user to pass --chain-id\n%s", stderr)
	}
	if !strings.Contains(stderr, "chain-a") || !strings.Contains(stderr, "chain-b") {
		t.Errorf("stderr should list available chain ids\n%s", stderr)
	}
}

func TestRun_ChainIDSelectsAmongMany(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 2, "chain-a", "chain-b")

	code, stdout, stderr := runOnce(t, []string{"--db", dbPath, "--chain-id", "chain-b", "1"})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	if !strings.Contains(stdout, "chain-b") {
		t.Errorf("stdout should be the chain-b receipt\n%s", stdout)
	}
}

func TestRun_MissingSeqArgIsUsageError(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 1, "chain-1")

	code, _, stderr := runOnce(t, []string{"--db", dbPath})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "missing <seq>") {
		t.Errorf("stderr = %q, expected missing-seq diagnostic", stderr)
	}
}

func TestRun_NonIntegerSeqIsUsageError(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 1, "chain-1")

	code, _, stderr := runOnce(t, []string{"--db", dbPath, "abc"})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "positive integer") {
		t.Errorf("stderr = %q, expected integer diagnostic", stderr)
	}
}

func TestRun_ZeroSeqIsUsageError(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 1, "chain-1")

	code, _, _ := runOnce(t, []string{"--db", dbPath, "0"})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
}

func TestRun_ExtraPositionalIsUsageError(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 2, "chain-1")

	code, _, stderr := runOnce(t, []string{"--db", dbPath, "1", "2"})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "unexpected positional") {
		t.Errorf("stderr = %q, expected extra-positional diagnostic", stderr)
	}
}

func TestRun_MissingDBIsUsageError(t *testing.T) {
	dir := t.TempDir()

	code, _, stderr := runOnce(t, []string{"--db", filepath.Join(dir, "no-such.db"), "1"})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "open store") {
		t.Errorf("stderr = %q, expected 'open store' diagnostic", stderr)
	}
}

func TestRun_EmptyStoreIsNotFound(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 0, "chain-1")

	code, _, stderr := runOnce(t, []string{"--db", dbPath, "1"})
	if code != ExitNotFound {
		t.Fatalf("exit = %d, want %d", code, ExitNotFound)
	}
	if !strings.Contains(stderr, "no receipts") {
		t.Errorf("stderr = %q, expected empty-store diagnostic", stderr)
	}
}

func TestRun_BadFlagIsUsageError(t *testing.T) {
	code, _, _ := runOnce(t, []string{"--bogus", "1"})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
}

func TestRun_HelpFlagExitsCleanly(t *testing.T) {
	code, _, stderr := runOnce(t, []string{"-h"})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (asking for help is not an error)", code, ExitOK)
	}
	if !strings.Contains(stderr, "--db") && !strings.Contains(stderr, "-db") {
		t.Errorf("stderr should mention --db; got %q", stderr)
	}
}

func TestRun_EnvVarDBPath(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 2, "chain-1")

	var out, errb bytes.Buffer
	// No --db flag: the path comes from AGENTRECEIPTS_DB.
	code := Run([]string{"--json", "1"}, &out, &errb, func(key string) string {
		if key == "AGENTRECEIPTS_DB" {
			return dbPath
		}
		return ""
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, errb.String())
	}
	var r receipt.AgentReceipt
	if err := json.Unmarshal([]byte(out.String()), &r); err != nil {
		t.Fatalf("JSON output not parseable: %v", err)
	}
	if r.CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("got sequence %d, want 1", r.CredentialSubject.Chain.Sequence)
	}
}

func TestRun_FlagDBOverridesEnv(t *testing.T) {
	realDir := t.TempDir()
	realDB := fixtureDB(t, realDir, 2, "real-chain")
	bogusDB := filepath.Join(t.TempDir(), "no-such.db")

	var out, errb bytes.Buffer
	// --db must win over AGENTRECEIPTS_DB; pointing the env at a missing file
	// proves the flag value is the one actually opened.
	code := Run([]string{"--db", realDB, "1"}, &out, &errb, func(key string) string {
		if key == "AGENTRECEIPTS_DB" {
			return bogusDB
		}
		return ""
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, errb.String())
	}
	if !strings.Contains(out.String(), "real-chain") {
		t.Errorf("--db should override the env path\n%s", out.String())
	}
}

func TestRun_EnvVarChainID(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, 2, "chain-a", "chain-b")

	var out, errb bytes.Buffer
	code := Run([]string{"--db", dbPath, "1"}, &out, &errb, func(key string) string {
		if key == "AGENTRECEIPTS_CHAIN_ID" {
			return "chain-a"
		}
		return ""
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, errb.String())
	}
	if !strings.Contains(out.String(), "chain-a") {
		t.Errorf("env chain id should select chain-a\n%s", out.String())
	}
}
