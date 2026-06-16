package doctorcli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// genKeyPEM returns a fresh Ed25519 keypair as PEM strings.
func genKeyPEM(t *testing.T) (privPEM string, pubPEM []byte) {
	t.Helper()
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
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privPEM, pubPEM
}

// fixtureChain writes a daemon-shaped DB with `count` signed receipts on
// chainID and returns the DB path and a public-key path. When mismatchKey is
// true the published public key belongs to a different keypair, so the stored
// signatures fail verification.
func fixtureChain(t *testing.T, dir, chainID string, count int, mismatchKey bool) (dbPath, pubKeyPath string) {
	t.Helper()
	dbPath = filepath.Join(dir, "receipts.db")
	pubKeyPath = filepath.Join(dir, "signing.key.pub")

	privPEM, pubPEM := genKeyPEM(t)
	publishPEM := pubPEM
	if mismatchKey {
		_, publishPEM = genKeyPEM(t) // publish a key that did not sign the chain
	}
	if err := os.WriteFile(pubKeyPath, publishPEM, 0o644); err != nil {
		t.Fatal(err)
	}

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
			Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
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
	// The daemon tightens the DB to 0640 on startup (tightenDBFiles); match
	// that so the db-permissions check sees a daemon-shaped fixture.
	if err := os.Chmod(dbPath, 0o640); err != nil {
		t.Fatal(err)
	}
	return dbPath, pubKeyPath
}

// listeningSocket creates a Unix-domain socket that accepts and immediately
// closes connections, returning its path. Uses a short /tmp dir to stay within
// the AF_UNIX sun_path limit.
func listeningSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "doctor")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return path
}

func TestCheckDaemonProcess(t *testing.T) {
	t.Run("reachable", func(t *testing.T) {
		path := listeningSocket(t)
		r := checkDaemonProcess(path)
		if r.Status != StatusOK {
			t.Fatalf("got %s (%s), want ok", r.Status, r.Reason)
		}
	})
	t.Run("no daemon", func(t *testing.T) {
		dir := t.TempDir()
		r := checkDaemonProcess(filepath.Join(dir, "missing.sock"))
		if r.Status != StatusFail {
			t.Fatalf("got %s, want fail", r.Status)
		}
		if r.Fix == "" {
			t.Error("expected a fix hint for an unreachable daemon")
		}
	})
}

func TestCheckSocket(t *testing.T) {
	t.Run("healthy 0660", func(t *testing.T) {
		path := listeningSocket(t)
		r := checkSocket(path)
		if r.Status != StatusOK {
			t.Fatalf("got %s (%s), want ok", r.Status, r.Reason)
		}
	})
	t.Run("missing", func(t *testing.T) {
		r := checkSocket(filepath.Join(t.TempDir(), "nope.sock"))
		if r.Status != StatusFail {
			t.Fatalf("got %s, want fail", r.Status)
		}
	})
	t.Run("not a socket", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "regular")
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		r := checkSocket(p)
		if r.Status != StatusFail {
			t.Fatalf("got %s, want fail", r.Status)
		}
	})
	t.Run("world-accessible warns", func(t *testing.T) {
		path := listeningSocket(t)
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		r := checkSocket(path)
		if r.Status != StatusWarn {
			t.Fatalf("got %s (%s), want warn", r.Status, r.Reason)
		}
	})
}

func TestCheckEmitterDialPath(t *testing.T) {
	t.Run("agree", func(t *testing.T) {
		env := func(k string) string {
			if k == "AGENTRECEIPTS_SOCKET" {
				return "/run/agentreceipts/events.sock"
			}
			return ""
		}
		r := checkEmitterDialPath("/run/agentreceipts/events.sock", env)
		if r.Status != StatusOK {
			t.Fatalf("got %s (%s), want ok", r.Status, r.Reason)
		}
	})
	t.Run("drift warns", func(t *testing.T) {
		env := func(k string) string {
			if k == "AGENTRECEIPTS_SOCKET" {
				return "/run/agentreceipts/events.sock"
			}
			return ""
		}
		r := checkEmitterDialPath("/tmp/other.sock", env)
		if r.Status != StatusWarn {
			t.Fatalf("got %s (%s), want warn", r.Status, r.Reason)
		}
	})
}

func TestCheckDBPermissions(t *testing.T) {
	t.Run("0640 ok", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "receipts.db")
		if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o640); err != nil {
			t.Fatal(err)
		}
		r := checkDBPermissions(p)
		if r.Status != StatusOK {
			t.Fatalf("got %s (%s), want ok", r.Status, r.Reason)
		}
	})
	t.Run("world-readable fails", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "receipts.db")
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
		r := checkDBPermissions(p)
		if r.Status != StatusFail {
			t.Fatalf("got %s (%s), want fail", r.Status, r.Reason)
		}
		if r.Fix == "" {
			t.Error("expected a chmod fix hint")
		}
	})
	t.Run("missing fails", func(t *testing.T) {
		r := checkDBPermissions(filepath.Join(t.TempDir(), "nope.db"))
		if r.Status != StatusFail {
			t.Fatalf("got %s, want fail", r.Status)
		}
	})
}

func TestCheckSchema(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		dir := t.TempDir()
		dbPath, pubKeyPath := fixtureChain(t, dir, "default", 2, false)
		r := checkSchema(dbPath, pubKeyPath)
		if r.Status != StatusOK {
			t.Fatalf("got %s (%s), want ok", r.Status, r.Reason)
		}
		if !strings.Contains(r.Reason, "sha256:") {
			t.Errorf("expected key fingerprint in reason, got %q", r.Reason)
		}
	})
	t.Run("bad public key fails", func(t *testing.T) {
		dir := t.TempDir()
		dbPath, _ := fixtureChain(t, dir, "default", 1, false)
		badKey := filepath.Join(dir, "bad.pub")
		if err := os.WriteFile(badKey, []byte("not a pem"), 0o644); err != nil {
			t.Fatal(err)
		}
		r := checkSchema(dbPath, badKey)
		if r.Status != StatusFail {
			t.Fatalf("got %s (%s), want fail", r.Status, r.Reason)
		}
	})
	t.Run("missing db fails", func(t *testing.T) {
		dir := t.TempDir()
		_, pubKeyPath := fixtureChain(t, dir, "default", 1, false)
		r := checkSchema(filepath.Join(dir, "nope.db"), pubKeyPath)
		if r.Status != StatusFail {
			t.Fatalf("got %s, want fail", r.Status)
		}
	})
}

func TestCheckPeerCredCapture(t *testing.T) {
	// On the linux/darwin hosts CI runs, this must report ok.
	r := checkPeerCredCapture()
	if r.Status != StatusOK {
		t.Fatalf("got %s (%s), want ok on a supported platform", r.Status, r.Reason)
	}
}

func TestCheckChainHead(t *testing.T) {
	t.Run("valid chain ok-or-warn", func(t *testing.T) {
		dir := t.TempDir()
		dbPath, pubKeyPath := fixtureChain(t, dir, "default", 3, false)
		r := checkChainHead(dbPath, pubKeyPath, "default")
		// A non-terminated chain verifies but its head is "unknown" → warn.
		if r.Status == StatusFail {
			t.Fatalf("got fail (%s), want ok/warn for a valid chain", r.Reason)
		}
	})
	t.Run("broken chain fails", func(t *testing.T) {
		dir := t.TempDir()
		dbPath, pubKeyPath := fixtureChain(t, dir, "default", 3, true) // mismatched key
		r := checkChainHead(dbPath, pubKeyPath, "default")
		if r.Status != StatusFail {
			t.Fatalf("got %s (%s), want fail for a chain that does not verify", r.Status, r.Reason)
		}
	})
	t.Run("empty chain warns", func(t *testing.T) {
		dir := t.TempDir()
		dbPath, pubKeyPath := fixtureChain(t, dir, "default", 1, false)
		r := checkChainHead(dbPath, pubKeyPath, "no-such-chain")
		if r.Status != StatusWarn {
			t.Fatalf("got %s (%s), want warn for an empty chain", r.Status, r.Reason)
		}
	})
}

func TestCheckRoundtripNoDaemon(t *testing.T) {
	dir := t.TempDir()
	dbPath, _ := fixtureChain(t, dir, "default", 1, false)
	r := checkRoundtrip(filepath.Join(dir, "missing.sock"), dbPath, "default", 200_000_000)
	if r.Status != StatusFail {
		t.Fatalf("got %s (%s), want fail when the daemon is unreachable", r.Status, r.Reason)
	}
}

func TestEvalRoundtripPeer(t *testing.T) {
	uid := func(v uint32) *uint32 { return &v }
	const wantPID = int32(4242)
	const wantUID = uint32(1000)
	const wantExe = "/usr/local/bin/agent-receipts"

	t.Run("happy path ok", func(t *testing.T) {
		pc := &receipt.PeerCredential{PID: wantPID, UID: uid(wantUID), ExePath: wantExe}
		if r := evalRoundtripPeer("linux", pc, 7, wantPID, wantUID, wantExe); r.Status != StatusOK {
			t.Fatalf("got %s (%s), want ok", r.Status, r.Reason)
		}
	})
	t.Run("nil peer cred fails", func(t *testing.T) {
		if r := evalRoundtripPeer("linux", nil, 7, wantPID, wantUID, wantExe); r.Status != StatusFail {
			t.Fatalf("got %s, want fail", r.Status)
		}
	})
	t.Run("darwin pid=0 with uid match warns", func(t *testing.T) {
		pc := &receipt.PeerCredential{PID: 0, UID: uid(wantUID)}
		r := evalRoundtripPeer("darwin", pc, 7, wantPID, wantUID, wantExe)
		if r.Status != StatusWarn {
			t.Fatalf("got %s (%s), want warn for the macOS LOCAL_PEEREPID race", r.Status, r.Reason)
		}
		if !strings.Contains(r.Reason, "pid=0") {
			t.Errorf("reason should explain the pid=0 race, got %q", r.Reason)
		}
	})
	t.Run("darwin pid=0 with uid MISMATCH still fails", func(t *testing.T) {
		pc := &receipt.PeerCredential{PID: 0, UID: uid(wantUID + 1)}
		if r := evalRoundtripPeer("darwin", pc, 7, wantPID, wantUID, wantExe); r.Status != StatusFail {
			t.Fatalf("got %s (%s), want fail when the uid does not match", r.Status, r.Reason)
		}
	})
	t.Run("linux pid=0 fails (no such race on linux)", func(t *testing.T) {
		pc := &receipt.PeerCredential{PID: 0, UID: uid(wantUID)}
		if r := evalRoundtripPeer("linux", pc, 7, wantPID, wantUID, wantExe); r.Status != StatusFail {
			t.Fatalf("got %s (%s), want fail; SO_PEERCRED does not lose the pid", r.Status, r.Reason)
		}
	})
	t.Run("uid mismatch fails", func(t *testing.T) {
		pc := &receipt.PeerCredential{PID: wantPID, UID: uid(wantUID + 1)}
		if r := evalRoundtripPeer("linux", pc, 7, wantPID, wantUID, wantExe); r.Status != StatusFail {
			t.Fatalf("got %s, want fail", r.Status)
		}
	})
	t.Run("exe mismatch warns", func(t *testing.T) {
		pc := &receipt.PeerCredential{PID: wantPID, UID: uid(wantUID), ExePath: "/some/other/binary"}
		if r := evalRoundtripPeer("linux", pc, 7, wantPID, wantUID, wantExe); r.Status != StatusWarn {
			t.Fatalf("got %s (%s), want warn", r.Status, r.Reason)
		}
	})
}

func TestHasFailures(t *testing.T) {
	warnOnly := []Result{{Status: StatusOK}, {Status: StatusWarn}}
	if hasFailures(warnOnly, false) {
		t.Error("warnings alone should not fail without --warn-as-error")
	}
	if !hasFailures(warnOnly, true) {
		t.Error("warnings should fail under --warn-as-error")
	}
	withFail := []Result{{Status: StatusOK}, {Status: StatusFail}}
	if !hasFailures(withFail, false) {
		t.Error("a failure should always count")
	}
}

func TestPublicKeyFingerprint(t *testing.T) {
	dir := t.TempDir()
	_, pubPEM := genKeyPEM(t)
	p := filepath.Join(dir, "k.pub")
	if err := os.WriteFile(p, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	fp, err := publicKeyFingerprint(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("got %q, want sha256: prefix", fp)
	}
}

func TestPublicKeyFingerprintRejectsNonEd25519(t *testing.T) {
	dir := t.TempDir()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "ecdsa.pub")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publicKeyFingerprint(p); err == nil {
		t.Fatal("expected an error for a non-Ed25519 public key, got nil")
	}
}

func TestCheckDBPermissionsWALSibling(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "receipts.db")
	if err := os.WriteFile(db, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(db, 0o640); err != nil {
		t.Fatal(err)
	}
	// A world-readable WAL sibling must fail even when the main DB is 0640.
	wal := db + "-wal"
	if err := os.WriteFile(wal, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wal, 0o644); err != nil {
		t.Fatal(err)
	}
	r := checkDBPermissions(db)
	if r.Status != StatusFail {
		t.Fatalf("got %s (%s), want fail for a world-readable -wal sibling", r.Status, r.Reason)
	}
	if !strings.Contains(r.Reason, "-wal") {
		t.Errorf("reason should name the -wal sibling, got %q", r.Reason)
	}
}

// TestRunJSONOutput drives the full Run with --json against a fixture, with the
// daemon down (round-trip + daemon checks fail) and confirms the report parses
// and the exit code is non-zero.
func TestRunJSONOutput(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath := fixtureChain(t, dir, "default", 2, false)
	env := func(k string) string {
		switch k {
		case "AGENTRECEIPTS_DB":
			return dbPath
		case "AGENTRECEIPTS_PUBLIC_KEY":
			return pubKeyPath
		case "AGENTRECEIPTS_SOCKET":
			return filepath.Join(dir, "missing.sock")
		}
		return ""
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "--chain-id", "default"}, &stdout, &stderr, env)
	if code != ExitUnhealthy {
		t.Fatalf("got exit %d, want %d (daemon down)\nstderr: %s", code, ExitUnhealthy, stderr.String())
	}
	var report Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("parse JSON report: %v\noutput: %s", err, stdout.String())
	}
	if report.OK {
		t.Error("report.OK should be false when the daemon is down")
	}
	if len(report.Checks) != 8 {
		t.Errorf("got %d checks, want 8", len(report.Checks))
	}
	// DB-permission and schema checks should still pass against the fixture.
	byName := map[string]Result{}
	for _, c := range report.Checks {
		byName[c.Check] = c
	}
	if byName["db permissions"].Status != StatusOK {
		t.Errorf("db permissions: got %s (%s), want ok", byName["db permissions"].Status, byName["db permissions"].Reason)
	}
	if byName["schema/version"].Status != StatusOK {
		t.Errorf("schema/version: got %s (%s), want ok", byName["schema/version"].Status, byName["schema/version"].Reason)
	}
}

func TestRunNoRoundtripFlag(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath := fixtureChain(t, dir, "default", 1, false)
	env := func(k string) string {
		switch k {
		case "AGENTRECEIPTS_DB":
			return dbPath
		case "AGENTRECEIPTS_PUBLIC_KEY":
			return pubKeyPath
		case "AGENTRECEIPTS_SOCKET":
			return filepath.Join(dir, "missing.sock")
		}
		return ""
	}
	var stdout, stderr bytes.Buffer
	Run([]string{"--json", "--no-roundtrip"}, &stdout, &stderr, env)
	var report Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	for _, c := range report.Checks {
		if c.Check == "round-trip" {
			if c.Status != StatusWarn || !strings.Contains(c.Reason, "skipped") {
				t.Errorf("round-trip: got %s (%s), want warn/skipped", c.Status, c.Reason)
			}
			return
		}
	}
	t.Error("round-trip check missing from report")
}

// seedChain appends count signed receipts on chainID to the store at dbPath,
// signed with privPEM. Unlike fixtureChain it does not create the public-key
// file and can be called repeatedly to build a multi-chain store.
func seedChain(t *testing.T, dbPath, privPEM, chainID string, count int) {
	t.Helper()
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
			Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
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

func TestDetectActiveRootChain(t *testing.T) {
	t.Run("empty store returns empty", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "receipts.db")
		s, err := store.Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
		if got := detectActiveRootChain(dbPath); got != "" {
			t.Fatalf("got %q, want empty for an empty store", got)
		}
	})

	t.Run("unreadable store returns empty", func(t *testing.T) {
		if got := detectActiveRootChain(filepath.Join(t.TempDir(), "nope.db")); got != "" {
			t.Fatalf("got %q, want empty for a missing store", got)
		}
	})

	t.Run("picks newest root chain", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "receipts.db")
		privPEM, _ := genKeyPEM(t)
		seedChain(t, dbPath, privPEM, "2026-06-03", 3)
		seedChain(t, dbPath, privPEM, "2026-06-03-8", 2) // inserted last → newest
		if got := detectActiveRootChain(dbPath); got != "2026-06-03-8" {
			t.Fatalf("got %q, want the most recently appended root chain", got)
		}
	})

	t.Run("skips agent sub-chains", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "receipts.db")
		privPEM, _ := genKeyPEM(t)
		seedChain(t, dbPath, privPEM, "2026-06-03-8", 2)
		// An agent sub-chain receipt is newer (inserted last) but must be
		// skipped: doctor's round-trip lands on the root chain, not here.
		seedChain(t, dbPath, privPEM, "2026-06-03-8/agent/abc123", 1)
		if got := detectActiveRootChain(dbPath); got != "2026-06-03-8" {
			t.Fatalf("got %q, want the root chain (agent sub-chain must be skipped)", got)
		}
	})
}

func TestResolveChainID(t *testing.T) {
	t.Run("detected chain wins over date fallback", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "receipts.db")
		privPEM, _ := genKeyPEM(t)
		seedChain(t, dbPath, privPEM, "2026-06-03-8", 1)
		if got := resolveChainID(dbPath); got != "2026-06-03-8" {
			t.Fatalf("got %q, want the detected active chain", got)
		}
	})

	t.Run("empty store falls back to UTC date", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "receipts.db")
		s, err := store.Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
		got := resolveChainID(dbPath)
		if _, err := time.Parse("2006-01-02", got); err != nil {
			t.Fatalf("got %q, want a YYYY-MM-DD date fallback: %v", got, err)
		}
	})
}
