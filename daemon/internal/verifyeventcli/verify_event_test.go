package verifyeventcli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"obsigna.dev/sdk/go/receipt"
	"obsigna.dev/sdk/go/store"
)

func u32(v uint32) *uint32 { return &v }

// linuxPeer is a well-formed daemon-captured peer credential for an emitter at
// the given exe_path.
func linuxPeer(exePath string) *receipt.PeerCredential {
	return &receipt.PeerCredential{
		Platform: "linux",
		PID:      4242,
		UID:      u32(1000),
		GID:      u32(1000),
		ExePath:  exePath,
	}
}

// recSpec describes one receipt to lay down in a fixture chain.
type recSpec struct {
	peer          *receipt.PeerCredential // nil = no peer credential (legacy receipt)
	breakPrevHash bool                    // stamp a bogus previous_receipt_hash to break linkage at this receipt
	version       string                  // override the schema version ("" = SDK default)
	terminal      bool                    // mark this receipt chain.terminal: true
}

// buildStore writes a daemon-shaped DB containing a signed chain built from
// specs (1-indexed sequence), and returns the db path, the matching public-key
// path, and the receipt ids in chain order.
func buildStore(t *testing.T, dir, chainID string, specs []recSpec) (dbPath, pubKeyPath string, ids []string) {
	t.Helper()

	dbPath = filepath.Join(dir, "receipts.db")
	pubKeyPath = filepath.Join(dir, "signing.key.pub")

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubKeyPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var prevHash *string
	for i, spec := range specs {
		seq := i + 1
		linkHash := prevHash
		if spec.breakPrevHash {
			bogus := "0000000000000000000000000000000000000000000000000000000000000000"
			linkHash = &bogus
		}
		unsigned := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: "did:test"},
			Principal: receipt.Principal{ID: "did:user:test"},
			Action: receipt.Action{
				Type:           "filesystem.file.read",
				RiskLevel:      receipt.RiskLow,
				PeerCredential: spec.peer,
			},
			Outcome:  receipt.Outcome{Status: receipt.StatusSuccess},
			Chain:    receipt.Chain{Sequence: seq, PreviousReceiptHash: linkHash, ChainID: chainID},
			Terminal: spec.terminal,
		})
		if spec.version != "" {
			unsigned.Version = spec.version
		}
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
		ids = append(ids, signed.ID)
		// The next receipt links to the actual hash of this one, so a
		// breakPrevHash break is isolated to the receipt that carries it.
		prevHash = &h
	}
	return dbPath, pubKeyPath, ids
}

func runOnce(t *testing.T, args []string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	// Empty env so the test never inherits real AGENTRECEIPTS_* values.
	code = Run(args, &out, &errb, func(string) string { return "" })
	return code, out.String(), errb.String()
}

// findCheck returns the named check from a result's check slice.
func findCheck(t *testing.T, r eventResult, name string) check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q check in result for %s", name, r.ReceiptID)
	return check{}
}

func decodeJSON(t *testing.T, s string) jsonOutput {
	t.Helper()
	var out jsonOutput
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("decode JSON output: %v\noutput was:\n%s", err, s)
	}
	return out
}

// Well-formed receipt with full peer credential, emitter on the allowlist:
// VERIFIED with pipeline-provenance confirmed.
func TestVerifyEvent_FullPeerCred_ProvenanceConfirmed(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath, ids := buildStore(t, dir, "chain-1", []recSpec{
		{peer: linuxPeer("/usr/bin/mcp-proxy")},
		{peer: linuxPeer("/usr/bin/mcp-proxy")},
	})

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--id", ids[1],
		"--emitter-allowlist", "/usr/bin/mcp-proxy",
		"--json",
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	out := decodeJSON(t, stdout)
	if len(out.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(out.Results))
	}
	r := out.Results[0]
	if r.Verdict != verdictConfirmed {
		t.Errorf("verdict = %q, want %q", r.Verdict, verdictConfirmed)
	}
	for _, name := range []string{"signature", "hash linkage", "peer credential", "schema version", "chain context"} {
		if c := findCheck(t, r, name); c.Status != statusPass {
			t.Errorf("check %q = %q, want pass (%s)", name, c.Status, c.Detail)
		}
	}
	if c := findCheck(t, r, "emitter identity"); c.Status != statusPass {
		t.Errorf("emitter identity = %q, want pass (%s)", c.Status, c.Detail)
	}
}

// Receipt without peer credential (predates peer-cred capture): verifies
// cryptographically but is flagged as lacking pipeline-provenance evidence.
func TestVerifyEvent_NoPeerCred_NoProvenanceEvidence(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath, ids := buildStore(t, dir, "chain-1", []recSpec{
		{peer: nil},
	})

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--id", ids[0],
	})
	if code != ExitNoProvenance {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitNoProvenance, stderr)
	}
	if !strings.Contains(stdout, "no pipeline-provenance evidence") {
		t.Errorf("stdout = %q, expected the no-provenance verdict line", stdout)
	}
	if !strings.Contains(stdout, "predates peer-credential evidence") {
		t.Errorf("stdout = %q, expected the legacy peer-credential explanation", stdout)
	}
}

// Receipt whose captured exe_path is not on the operator allowlist: a warning,
// not a failure — provenance is still confirmed.
func TestVerifyEvent_MismatchedExePath_WarnsNotFails(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath, ids := buildStore(t, dir, "chain-1", []recSpec{
		{peer: linuxPeer("/tmp/rogue-writer")},
	})

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--id", ids[0],
		"--emitter-allowlist", "/usr/bin/mcp-proxy,/usr/bin/openclaw",
		"--json",
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d — exe_path mismatch must not fail (stderr=%s)", code, ExitOK, stderr)
	}
	r := decodeJSON(t, stdout).Results[0]
	if r.Verdict != verdictConfirmed {
		t.Errorf("verdict = %q, want %q (mismatch is operator policy, not a failure)", r.Verdict, verdictConfirmed)
	}
	if c := findCheck(t, r, "emitter identity"); c.Status != statusWarn {
		t.Errorf("emitter identity = %q, want warn (%s)", c.Status, c.Detail)
	}
}

// Receipt in a chain with broken hash linkage: FAILED — suspect.
func TestVerifyEvent_BrokenLinkage_Fails(t *testing.T) {
	dir := t.TempDir()
	// Receipt 2 carries a bogus previous_receipt_hash, breaking linkage there.
	dbPath, pubKeyPath, ids := buildStore(t, dir, "chain-1", []recSpec{
		{peer: linuxPeer("/usr/bin/mcp-proxy")},
		{peer: linuxPeer("/usr/bin/mcp-proxy"), breakPrevHash: true},
		{peer: linuxPeer("/usr/bin/mcp-proxy")},
	})

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--id", ids[1],
		"--json",
	})
	if code != ExitVerifyFailed {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitVerifyFailed, stderr)
	}
	r := decodeJSON(t, stdout).Results[0]
	if r.Verdict != verdictFailed {
		t.Errorf("verdict = %q, want %q", r.Verdict, verdictFailed)
	}
	if c := findCheck(t, r, "hash linkage"); c.Status != statusFail {
		t.Errorf("hash linkage = %q, want fail (%s)", c.Status, c.Detail)
	}
}

// A break downstream of the target still fails the target: it is no longer
// reachable from a trustworthy chain head.
func TestVerifyEvent_DownstreamBreak_FailsTarget(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath, ids := buildStore(t, dir, "chain-1", []recSpec{
		{peer: linuxPeer("/usr/bin/mcp-proxy")},
		{peer: linuxPeer("/usr/bin/mcp-proxy")},
		{peer: linuxPeer("/usr/bin/mcp-proxy"), breakPrevHash: true},
	})

	code, _, _ := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--id", ids[0],
	})
	if code != ExitVerifyFailed {
		t.Fatalf("exit = %d, want %d (a downstream break must taint the head's reachability)", code, ExitVerifyFailed)
	}
}

// Receipt whose schema version the verifier does not understand: FAILED.
func TestVerifyEvent_UnknownSchemaVersion_Fails(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath, ids := buildStore(t, dir, "chain-1", []recSpec{
		{peer: linuxPeer("/usr/bin/mcp-proxy"), version: "99.0.0"},
	})

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--id", ids[0],
		"--json",
	})
	if code != ExitVerifyFailed {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitVerifyFailed, stderr)
	}
	r := decodeJSON(t, stdout).Results[0]
	if c := findCheck(t, r, "schema version"); c.Status != statusFail {
		t.Errorf("schema version = %q, want fail (%s)", c.Status, c.Detail)
	}
}

// A schema version without a dotted form ("0") is malformed, not a compatible
// bare major: it must fail explicitly as unparseable.
func TestVerifyEvent_MalformedSchemaVersion_Fails(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath, ids := buildStore(t, dir, "chain-1", []recSpec{
		{peer: linuxPeer("/usr/bin/mcp-proxy"), version: "0"},
	})

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--id", ids[0],
		"--json",
	})
	if code != ExitVerifyFailed {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitVerifyFailed, stderr)
	}
	c := findCheck(t, decodeJSON(t, stdout).Results[0], "schema version")
	if c.Status != statusFail || !strings.Contains(c.Detail, "unparseable") {
		t.Errorf("schema version = %q (%s), want fail/unparseable", c.Status, c.Detail)
	}
}

// A receipt-after-terminal violation makes VerifyChain reject the whole chain
// without tripping any per-receipt signature/hash/sequence boolean. verify-event
// must still fail it (via chain context) rather than confirming provenance.
func TestVerifyEvent_ReceiptAfterTerminal_Fails(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath, ids := buildStore(t, dir, "chain-1", []recSpec{
		{peer: linuxPeer("/usr/bin/mcp-proxy"), terminal: true},
		{peer: linuxPeer("/usr/bin/mcp-proxy")}, // follows a terminal receipt — spec §7.3.2 violation
	})

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--id", ids[0],
		"--json",
	})
	if code != ExitVerifyFailed {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitVerifyFailed, stderr)
	}
	r := decodeJSON(t, stdout).Results[0]
	if r.Verdict != verdictFailed {
		t.Errorf("verdict = %q, want %q", r.Verdict, verdictFailed)
	}
	c := findCheck(t, r, "chain context")
	if c.Status != statusFail || !strings.Contains(c.Detail, "chain integrity violation") {
		t.Errorf("chain context = %q (%s), want fail with chain-integrity detail", c.Status, c.Detail)
	}
}

// A peer credential with an unrecognized platform can't be interpreted, so it is
// reported n/a (no provenance evidence) rather than confirmed.
func TestVerifyEvent_UnknownPeerPlatform_NoProvenance(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath, ids := buildStore(t, dir, "chain-1", []recSpec{
		{peer: &receipt.PeerCredential{Platform: "plan9", PID: 7}},
	})

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--id", ids[0],
		"--json",
	})
	if code != ExitNoProvenance {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitNoProvenance, stderr)
	}
	r := decodeJSON(t, stdout).Results[0]
	if r.Verdict != verdictNoProvenance {
		t.Errorf("verdict = %q, want %q", r.Verdict, verdictNoProvenance)
	}
	c := findCheck(t, r, "peer credential")
	if c.Status != statusNA || !strings.Contains(c.Detail, "unrecognized peer platform") {
		t.Errorf("peer credential = %q (%s), want n/a with unrecognized-platform detail", c.Status, c.Detail)
	}
}

// --chain-head selects the most recent receipt; with one chain present no
// --chain-id is needed.
func TestVerifyEvent_ChainHeadSelector(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath, ids := buildStore(t, dir, "chain-1", []recSpec{
		{peer: linuxPeer("/usr/bin/mcp-proxy")},
		{peer: linuxPeer("/usr/bin/mcp-proxy")},
		{peer: linuxPeer("/usr/bin/mcp-proxy")},
	})

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--chain-head",
		"--json",
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	r := decodeJSON(t, stdout).Results[0]
	if r.ReceiptID != ids[2] {
		t.Errorf("chain-head selected %s, want the tail %s", r.ReceiptID, ids[2])
	}
}

// --since verifies every receipt in the trailing window; a mix of confirmed and
// legacy receipts yields the worst-case exit code (no-provenance here).
func TestVerifyEvent_SinceSelector_WorstCaseExit(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath, _ := buildStore(t, dir, "chain-1", []recSpec{
		{peer: linuxPeer("/usr/bin/mcp-proxy")},
		{peer: nil}, // legacy: no provenance evidence
	})

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--since", "24h",
		"--json",
	})
	if code != ExitNoProvenance {
		t.Fatalf("exit = %d, want %d (worst case across the window; stderr=%s)", code, ExitNoProvenance, stderr)
	}
	out := decodeJSON(t, stdout)
	if len(out.Results) != 2 {
		t.Fatalf("got %d results, want 2 (whole window)", len(out.Results))
	}
}

func TestVerifyEvent_NoSelectorIsUsageError(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath, _ := buildStore(t, dir, "chain-1", []recSpec{{peer: linuxPeer("/usr/bin/mcp-proxy")}})

	code, _, stderr := runOnce(t, []string{"--db", dbPath, "--public-key", pubKeyPath})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "selector is required") {
		t.Errorf("stderr = %q, expected a 'selector is required' diagnostic", stderr)
	}
}

func TestVerifyEvent_MultipleSelectorsIsUsageError(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath, ids := buildStore(t, dir, "chain-1", []recSpec{{peer: linuxPeer("/usr/bin/mcp-proxy")}})

	code, _, stderr := runOnce(t, []string{
		"--db", dbPath, "--public-key", pubKeyPath,
		"--id", ids[0], "--chain-head",
	})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "mutually exclusive") {
		t.Errorf("stderr = %q, expected a mutual-exclusion diagnostic", stderr)
	}
}

func TestVerifyEvent_UnknownIDIsUsageError(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath, _ := buildStore(t, dir, "chain-1", []recSpec{{peer: linuxPeer("/usr/bin/mcp-proxy")}})

	code, _, stderr := runOnce(t, []string{
		"--db", dbPath, "--public-key", pubKeyPath,
		"--id", "urn:receipt:does-not-exist",
	})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "no receipt with id") {
		t.Errorf("stderr = %q, expected a not-found diagnostic", stderr)
	}
}

func TestVerifyEvent_MalformedPublicKeyIsUsageError(t *testing.T) {
	dir := t.TempDir()
	dbPath, _, ids := buildStore(t, dir, "chain-1", []recSpec{{peer: linuxPeer("/usr/bin/mcp-proxy")}})
	badKey := filepath.Join(dir, "garbage.pub")
	if err := os.WriteFile(badKey, []byte("not a pem block"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runOnce(t, []string{
		"--db", dbPath, "--public-key", badKey, "--id", ids[0],
	})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d (malformed key is a usage error, not a verdict)", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "invalid public key") {
		t.Errorf("stderr = %q, expected an 'invalid public key' diagnostic", stderr)
	}
}

func TestVerifyEvent_AmbiguousChainIsUsageError(t *testing.T) {
	dir := t.TempDir()
	// Two chains in one store; --chain-head with no --chain-id is ambiguous.
	dbPath, pubKeyPath, _ := buildStore(t, dir, "chain-1", []recSpec{{peer: linuxPeer("/usr/bin/mcp-proxy")}})
	// Append a second chain to the same DB.
	appendChain(t, dbPath, "chain-2")

	code, _, stderr := runOnce(t, []string{
		"--db", dbPath, "--public-key", pubKeyPath, "--chain-head",
	})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "pass --chain-id") {
		t.Errorf("stderr = %q, expected a chain-disambiguation diagnostic", stderr)
	}
}

// appendChain adds a second single-receipt chain to an existing DB so the store
// holds more than one chain. It signs with a throwaway key because the
// ambiguity check that consumes this fixture fires during chain resolution,
// before any signature is verified.
func appendChain(t *testing.T, dbPath, chainID string) {
	t.Helper()
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
	unsigned := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: "did:test"},
		Principal: receipt.Principal{ID: "did:user:test"},
		Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
		Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
		Chain:     receipt.Chain{Sequence: 1, ChainID: chainID},
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
}

func TestVerifyEvent_HelpExitsCleanly(t *testing.T) {
	code, _, stderr := runOnce(t, []string{"-h"})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (help is not an error)", code, ExitOK)
	}
	if !strings.Contains(stderr, "verify-event") {
		t.Errorf("stderr = %q, expected usage text", stderr)
	}
}
