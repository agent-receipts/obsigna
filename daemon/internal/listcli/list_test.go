package listcli

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

// fixtureDB writes a DB at dir/receipts.db with `count` receipts on chainID.
func fixtureDB(t *testing.T, dir, chainID string, count int) string {
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

	var prevHash *string
	for i := 1; i <= count; i++ {
		unsigned := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: "did:test"},
			Principal: receipt.Principal{ID: "did:user:test"},
			Action: receipt.Action{
				Type:      "filesystem.file.read",
				ToolName:  "Read",
				RiskLevel: receipt.RiskLow,
				// Explicit strictly-increasing timestamps avoid non-deterministic
				// ordering when multiple receipts share the same wall-clock second.
				Timestamp: fmt.Sprintf("2024-01-01T%02d:00:00Z", i),
			},
			Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
			Chain:   receipt.Chain{Sequence: i, PreviousReceiptHash: prevHash, ChainID: chainID},
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
	return dbPath
}

func runOnce(t *testing.T, args []string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Run(args, &out, &errb, func(string) string { return "" })
	return code, out.String(), errb.String()
}

func TestRun_TabularOutputShowsReceipts(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, "chain-1", 3)

	code, stdout, stderr := runOnce(t, []string{"--db", dbPath})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	if !strings.Contains(stdout, "Read") {
		t.Errorf("stdout = %q, expected tool name 'Read'", stdout)
	}
	if !strings.Contains(stdout, "SEQ") {
		t.Errorf("stdout = %q, expected header with SEQ", stdout)
	}
}

func TestRun_JSONOutputIsValidArray(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, "chain-1", 2)

	code, stdout, stderr := runOnce(t, []string{"--db", dbPath, "--json"})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	var receipts []receipt.AgentReceipt
	if err := json.Unmarshal([]byte(stdout), &receipts); err != nil {
		t.Fatalf("JSON output not parseable: %v (stdout=%q)", err, stdout)
	}
	if len(receipts) != 2 {
		t.Errorf("got %d receipts, want 2", len(receipts))
	}
}

func TestRun_LimitCapsResults(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, "chain-1", 5)

	code, stdout, stderr := runOnce(t, []string{"--db", dbPath, "--json", "--limit", "2"})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	var receipts []receipt.AgentReceipt
	if err := json.Unmarshal([]byte(stdout), &receipts); err != nil {
		t.Fatalf("JSON output not parseable: %v", err)
	}
	if len(receipts) != 2 {
		t.Errorf("got %d receipts, want 2", len(receipts))
	}
}

func TestRun_NewestFirstOrdering(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, "chain-1", 3)

	code, stdout, stderr := runOnce(t, []string{"--db", dbPath, "--json"})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	var receipts []receipt.AgentReceipt
	if err := json.Unmarshal([]byte(stdout), &receipts); err != nil {
		t.Fatalf("JSON output not parseable: %v", err)
	}
	for i := 1; i < len(receipts); i++ {
		prev := receipts[i-1].CredentialSubject.Chain.Sequence
		curr := receipts[i].CredentialSubject.Chain.Sequence
		if prev < curr {
			t.Errorf("receipts[%d].Sequence=%d < receipts[%d].Sequence=%d — not newest-first", i-1, prev, i, curr)
		}
	}
}

func TestRun_EmptyStoreProducesEmptyJSON(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, "chain-1", 0)

	code, stdout, stderr := runOnce(t, []string{"--db", dbPath, "--json"})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	if strings.TrimSpace(stdout) != "[]" {
		t.Errorf("stdout = %q, want []", stdout)
	}
}

func TestRun_EmptyStoreTabularSaysNoReceipts(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, "chain-1", 0)

	code, stdout, stderr := runOnce(t, []string{"--db", dbPath})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	if !strings.Contains(stdout, "no receipts") {
		t.Errorf("stdout = %q, expected 'no receipts'", stdout)
	}
}

func TestRun_MissingDBIsUsageError(t *testing.T) {
	dir := t.TempDir()

	code, _, stderr := runOnce(t, []string{"--db", filepath.Join(dir, "no-such.db")})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "open store") {
		t.Errorf("stderr = %q, expected 'open store' diagnostic", stderr)
	}
}

func TestRun_BadFlagIsUsageError(t *testing.T) {
	code, _, _ := runOnce(t, []string{"--bogus"})
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

func TestRun_InvalidLimitIsUsageError(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, "chain-1", 1)

	code, _, stderr := runOnce(t, []string{"--db", dbPath, "--limit", "0"})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "--limit") {
		t.Errorf("stderr = %q, expected '--limit' diagnostic", stderr)
	}
}

func TestRun_EnvVarDBPath(t *testing.T) {
	dir := t.TempDir()
	dbPath := fixtureDB(t, dir, "chain-1", 1)

	var out, errb bytes.Buffer
	code := Run([]string{"--json"}, &out, &errb, func(key string) string {
		if key == "AGENTRECEIPTS_DB" {
			return dbPath
		}
		return ""
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, errb.String())
	}
	var receipts []receipt.AgentReceipt
	if err := json.Unmarshal([]byte(out.String()), &receipts); err != nil {
		t.Fatalf("JSON output not parseable: %v", err)
	}
	if len(receipts) != 1 {
		t.Errorf("got %d receipts, want 1", len(receipts))
	}
}
