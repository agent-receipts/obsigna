package disclosecli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// fixtureDB builds a test store with `count` receipts on the given chain.
// Odd-numbered receipts carry an encrypted parameters_disclosure (file path
// in params); even-numbered receipts have no disclosure so we can test both
// code paths. Returns the db path and the forensic private key bytes.
func fixtureDB(t *testing.T, dir string, count int) (dbPath string, forensicPriv []byte) {
	t.Helper()

	_, sigPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(sigPriv)
	if err != nil {
		t.Fatal(err)
	}
	sigPrivPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))

	forensicKP, err := receipt.GenerateForensicKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := receipt.ForensicPublicFromPrivate(forensicKP.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := receipt.ForensicKeyFingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}

	dbPath = filepath.Join(dir, "receipts.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var prevHash *string
	for i := 1; i <= count; i++ {
		action := receipt.Action{
			Type:      "claude-code.Read",
			ToolName:  "Read",
			RiskLevel: receipt.RiskMedium,
			Timestamp: fmt.Sprintf("2024-01-01T%02d:00:00Z", i),
		}

		// Odd sequences get an encrypted disclosure; even ones do not.
		if i%2 == 1 {
			params := map[string]any{
				"file_path": fmt.Sprintf("/tmp/file%d.txt", i),
			}
			env, err := receipt.EncryptDisclosure(params, forensicKP.PublicKey, kid)
			if err != nil {
				t.Fatal(err)
			}
			action.ParametersDisclosure = env
		}

		unsigned := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: "did:test"},
			Principal: receipt.Principal{ID: "did:user:test"},
			Action:    action,
			Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
			Chain:     receipt.Chain{Sequence: i, PreviousReceiptHash: prevHash, ChainID: "test-chain"},
		})
		signed, err := receipt.Sign(unsigned, sigPrivPEM, "did:test#k1")
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

	return dbPath, forensicKP.PrivateKey
}

func writeKeyFile(t *testing.T, dir string, key []byte) string {
	t.Helper()
	p := filepath.Join(dir, "forensic.key")
	if err := os.WriteFile(p, key, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func env(db, chainID, key string) func(string) string {
	return func(k string) string {
		switch k {
		case "AGENTRECEIPTS_DB":
			return db
		case "AGENTRECEIPTS_CHAIN_ID":
			return chainID
		case "AGENTRECEIPTS_FORENSIC_KEY":
			return key
		}
		return ""
	}
}

func TestDisclose_HumanReadable(t *testing.T) {
	dir := t.TempDir()
	dbPath, priv := fixtureDB(t, dir, 3)
	keyPath := writeKeyFile(t, dir, priv)

	var out, errOut bytes.Buffer
	code := Run([]string{"1", "--chain-id", "test-chain"},
		&out, &errOut, env(dbPath, "", keyPath))

	if code != ExitOK {
		t.Fatalf("want ExitOK, got %d; stderr: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "file_path") {
		t.Errorf("expected file_path in output, got: %s", out.String())
	}
	if !strings.Contains(out.String(), "/tmp/file1.txt") {
		t.Errorf("expected /tmp/file1.txt in output, got: %s", out.String())
	}
}

func TestDisclose_JSON(t *testing.T) {
	dir := t.TempDir()
	dbPath, priv := fixtureDB(t, dir, 3)
	keyPath := writeKeyFile(t, dir, priv)

	var out, errOut bytes.Buffer
	code := Run([]string{"1", "--json", "--chain-id", "test-chain"},
		&out, &errOut, env(dbPath, "", keyPath))

	if code != ExitOK {
		t.Fatalf("want ExitOK, got %d; stderr: %s", code, errOut.String())
	}
	var params map[string]any
	if err := json.Unmarshal(out.Bytes(), &params); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if params["file_path"] != "/tmp/file1.txt" {
		t.Errorf("wrong file_path: %v", params["file_path"])
	}
}

func TestDisclose_NoDisclosure(t *testing.T) {
	dir := t.TempDir()
	dbPath, priv := fixtureDB(t, dir, 3)
	keyPath := writeKeyFile(t, dir, priv)

	var out, errOut bytes.Buffer
	// Sequence 2 has no disclosure (even-numbered).
	code := Run([]string{"2", "--chain-id", "test-chain"},
		&out, &errOut, env(dbPath, "", keyPath))

	if code != ExitOK {
		t.Fatalf("want ExitOK, got %d; stderr: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "no parameters_disclosure") {
		t.Errorf("expected 'no parameters_disclosure' message, got stderr: %s", errOut.String())
	}
}

func TestDisclose_WrongKey(t *testing.T) {
	dir := t.TempDir()
	dbPath, _ := fixtureDB(t, dir, 1)

	// Generate a different key and write it.
	wrongKP, err := receipt.GenerateForensicKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writeKeyFile(t, dir, wrongKP.PrivateKey)

	var out, errOut bytes.Buffer
	code := Run([]string{"1", "--chain-id", "test-chain"},
		&out, &errOut, env(dbPath, "", keyPath))

	if code != ExitDecryptError {
		t.Fatalf("want ExitDecryptError, got %d; stderr: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "does not match") {
		t.Errorf("expected mismatch message, got: %s", errOut.String())
	}
}

func TestDisclose_NotFound(t *testing.T) {
	dir := t.TempDir()
	dbPath, priv := fixtureDB(t, dir, 2)
	keyPath := writeKeyFile(t, dir, priv)

	var out, errOut bytes.Buffer
	code := Run([]string{"99", "--chain-id", "test-chain"},
		&out, &errOut, env(dbPath, "", keyPath))

	if code != ExitNotFound {
		t.Fatalf("want ExitNotFound, got %d", code)
	}
}

func TestDisclose_MissingSeq(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(nil, &out, &errOut, func(string) string { return "" })
	if code != ExitUsageError {
		t.Fatalf("want ExitUsageError, got %d", code)
	}
}

func TestDisclose_AutoChain(t *testing.T) {
	dir := t.TempDir()
	dbPath, priv := fixtureDB(t, dir, 1)
	keyPath := writeKeyFile(t, dir, priv)

	// Do not pass --chain-id; store has exactly one chain so it should auto-resolve.
	var out, errOut bytes.Buffer
	code := Run([]string{"1"}, &out, &errOut, env(dbPath, "", keyPath))

	if code != ExitOK {
		t.Fatalf("want ExitOK, got %d; stderr: %s", code, errOut.String())
	}
}

func TestParseForensicPrivateKey_Formats(t *testing.T) {
	kp, err := receipt.GenerateForensicKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw := kp.PrivateKey

	// hex
	hexKey := fmt.Sprintf("%x", raw)
	got, err := parseForensicPrivateKey([]byte(hexKey))
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("hex: mismatch")
	}

	// base64 standard padded
	import64 := encodeBase64Std(raw)
	got, err = parseForensicPrivateKey([]byte(import64))
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("base64: mismatch")
	}

	// raw with trailing newline
	withNL := append(append([]byte(nil), raw...), '\n')
	got, err = parseForensicPrivateKey(withNL)
	if err != nil {
		t.Fatalf("raw+newline: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("raw+newline: mismatch")
	}
}

func encodeBase64Std(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var buf strings.Builder
	for i := 0; i < len(b); i += 3 {
		remaining := len(b) - i
		var b0, b1, b2 byte
		b0 = b[i]
		if remaining > 1 {
			b1 = b[i+1]
		}
		if remaining > 2 {
			b2 = b[i+2]
		}
		buf.WriteByte(alphabet[b0>>2])
		buf.WriteByte(alphabet[((b0&0x3)<<4)|(b1>>4)])
		if remaining > 1 {
			buf.WriteByte(alphabet[((b1&0xf)<<2)|(b2>>6)])
		} else {
			buf.WriteByte('=')
		}
		if remaining > 2 {
			buf.WriteByte(alphabet[b2&0x3f])
		} else {
			buf.WriteByte('=')
		}
	}
	return buf.String()
}
