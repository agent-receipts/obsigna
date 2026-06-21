//go:build integration && (linux || darwin)

// Integration tests that exercise the daemon end-to-end: real Unix socket,
// real SQLite store, real signing key, and real OS peer-credential capture.
// Run with `go test -tags=integration ./...`.
//
// The build tag also gates on linux || darwin: the daemon's runtime gate
// rejects other OSes, and the test fixtures use unix-only APIs (os.Getuid,
// AF_UNIX sockets). Including (linux || darwin) keeps `go test -tags=integration`
// portable on Windows-builders that may run package-level vet/build.
package daemon_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"obsigna.dev/daemon"
	"obsigna.dev/daemon/internal/pipeline"
	"obsigna.dev/daemon/internal/socket"
	"obsigna.dev/daemon/internal/sockettest"
	"obsigna.dev/daemon/internal/verifycli"
	"obsigna.dev/sdk/go/receipt"
	"obsigna.dev/sdk/go/store"
)

// emitterHelperGuardVar is the explicit "this binary was re-exec'd as the
// subprocess emitter helper" sentinel. TestMain only enters helper mode when
// it is set to "1" AND emitterHelperEnvVar is also set. A single-var design
// risked silent false-greens if a developer or CI environment happened to
// have AR_TEST_EMITTER_SOCKET exported for unrelated reasons — the suite
// would have skipped m.Run() and exited 0 with zero tests run. The guard +
// socket pair makes accidental collision effectively impossible and fails
// loudly when the guard is set without the socket path.
const emitterHelperGuardVar = "AR_TEST_EMITTER_HELPER"

// emitterHelperEnvVar carries the daemon socket path the helper should
// connect to. Set together with emitterHelperGuardVar by the parent test
// (TestPeerCredFromSubprocess); see that function for why we need a
// separate-process emitter rather than dialling from the listener's own
// goroutine.
const emitterHelperEnvVar = "AR_TEST_EMITTER_SOCKET"

// TestMain handles the subprocess-emitter dispatch. When the guard env var
// is set to "1", the binary runs runEmitterHelper (connect, write one
// length-prefix frame, exit) and never calls m.Run(). When the guard is
// unset (normal go test invocation), the suite runs as usual. The guard is
// checked before the socket var so a stray emitterHelperEnvVar export does
// not silently swallow the suite; if the guard is set without the socket,
// we log.Fatalf rather than exit 0 to make the misconfiguration loud.
func TestMain(m *testing.M) {
	if os.Getenv(emitterHelperGuardVar) == "1" {
		sock := os.Getenv(emitterHelperEnvVar)
		if sock == "" {
			log.Fatalf("emitter helper: %s=1 set but %s is empty; refusing to silently exit 0 with no tests run", emitterHelperGuardVar, emitterHelperEnvVar)
		}
		runEmitterHelper(sock)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runEmitterHelper connects to sock and writes one length-prefix-framed
// emitter frame, then returns so TestMain can exit cleanly. Errors are
// fatal so the parent's CombinedOutput surfaces them in the test failure.
func runEmitterHelper(sock string) {
	conn, err := net.Dial("unix", sock)
	if err != nil {
		log.Fatalf("emitter helper: dial %s: %v", sock, err)
	}
	defer conn.Close()
	body, err := json.Marshal(pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: "subprocess-helper",
		Channel:   "sdk",
		Tool:      pipeline.EmitterTool{Name: "subprocess-emitter"},
		Decision:  "allowed",
	})
	if err != nil {
		log.Fatalf("emitter helper: marshal frame: %v", err)
	}
	if err := socket.WriteFrame(conn, body); err != nil {
		log.Fatalf("emitter helper: write frame: %v", err)
	}
	syncWithDaemon(conn)
}

func writeTestKey(t *testing.T, path string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
}

func startDaemon(t *testing.T) (cfg daemon.Config, pubPEM string, cancel func()) {
	t.Helper()
	sockDir := sockettest.ShortSocketDir(t)
	dataDir := t.TempDir()
	cfg = daemon.Config{
		SocketPath: filepath.Join(sockDir, "events.sock"),
		DBPath:     filepath.Join(dataDir, "receipts.db"),
		KeyPath:    filepath.Join(dataDir, "signing.key"),
		// ShortSocketDir lives under /tmp to stay within the 104-byte
		// AF_UNIX sun_path limit on macOS — outside the per-platform safe
		// set, so opt into the documented escape hatch (issue #538).
		UnsafeSocketPath:     true,
		PublicKeyPath:        filepath.Join(dataDir, "signing.key.pub"),
		ChainID:              "it-chain",
		IssuerID:             "did:agent-receipts-daemon:integration",
		VerificationMethodID: "did:agent-receipts-daemon:integration#k1",
		Logger:               log.New(io.Discard, "", 0),
	}
	pubPEM = writeTestKey(t, cfg.KeyPath)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx, cfg) }()

	// Wait for the socket to appear (the daemon does some setup before Listen).
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("socket %s did not appear within 2s", cfg.SocketPath)
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Logf("daemon Run returned: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("daemon did not shut down within 3s")
		}
	})
	return cfg, pubPEM, cancel
}

func emitFrame(t *testing.T, socketPath string, frame pipeline.EmitterFrame) {
	t.Helper()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial %s: %v", socketPath, err)
	}
	defer conn.Close()
	body, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := socket.WriteFrame(conn, body); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	syncWithDaemon(conn)
}

// syncWithDaemon half-closes the write side of conn and blocks reading
// until the daemon closes its end. This guarantees the daemon has finished
// processing the frame — and, crucially, has already called
// getsockopt(LOCAL_PEEREPID) at accept time — before the emitter's deferred
// Close() removes the peer's socket state. Without this synchronization,
// rapid connect→write→close races the daemon's accept-loop getsockopt on
// macOS: the kernel reaps the peer pcb and LOCAL_PEEREPID returns ENOTCONN.
// peercred_darwin.go tolerates that by recording pid=0, but the integration
// test still wants to assert the happy path (peer.pid == os.Getpid()), so
// the emitter does the synchronizing rather than the assertion relaxing.
func syncWithDaemon(conn net.Conn) {
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	_, _ = io.Copy(io.Discard, conn)
}

func waitForReceiptCount(t *testing.T, dbPath, chainID string, want int, timeout time.Duration) []receipt.AgentReceipt {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		s, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		got, err := s.GetChain(chainID)
		s.Close()
		if err == nil && len(got) >= want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d receipts in chain %s; got %d (err=%v)", want, chainID, len(got), err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestConcurrentEmittersSingleChain is the regression test for issue #236
// comment 2: two emitters firing concurrently must produce one monotonic
// chain with no gaps, no duplicate sequences, and no UNIQUE-index conflicts.
// The in-process design this replaces could not pass this test.
func TestConcurrentEmittersSingleChain(t *testing.T) {
	cfg, pubPEM, _ := startDaemon(t)

	const emitters = 4
	const perEmitter = 50
	total := emitters * perEmitter

	var wg sync.WaitGroup
	wg.Add(emitters)
	for e := 0; e < emitters; e++ {
		go func(emitterIdx int) {
			defer wg.Done()
			for i := 0; i < perEmitter; i++ {
				emitFrame(t, cfg.SocketPath, pipeline.EmitterFrame{
					Version:   "1",
					TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
					SessionID: fmt.Sprintf("sess-%d", emitterIdx),
					Channel:   "mcp_proxy",
					Tool:      pipeline.EmitterTool{Server: "fixture", Name: "ping"},
					Decision:  "allowed",
				})
			}
		}(e)
	}
	wg.Wait()

	receipts := waitForReceiptCount(t, cfg.DBPath, cfg.ChainID, total, 10*time.Second)

	if len(receipts) != total {
		t.Fatalf("got %d receipts, want %d", len(receipts), total)
	}

	seen := make(map[int]bool, total)
	for i, r := range receipts {
		seq := r.CredentialSubject.Chain.Sequence
		if seq != i+1 {
			t.Errorf("receipt %d: seq = %d, want %d (gap or out-of-order)", i, seq, i+1)
		}
		if seen[seq] {
			t.Errorf("seq %d allocated twice", seq)
		}
		seen[seq] = true

		if i == 0 {
			if r.CredentialSubject.Chain.PreviousReceiptHash != nil {
				t.Errorf("first receipt prev_hash = %v, want nil", r.CredentialSubject.Chain.PreviousReceiptHash)
			}
		} else {
			want, err := receipt.HashReceipt(receipts[i-1])
			if err != nil {
				t.Fatal(err)
			}
			got := r.CredentialSubject.Chain.PreviousReceiptHash
			if got == nil || *got != want {
				t.Errorf("receipt %d: prev_hash = %v, want %s", i, got, want)
			}
		}

		ok, err := receipt.Verify(r, pubPEM)
		if err != nil || !ok {
			t.Errorf("receipt %d: verify ok=%v err=%v", i, ok, err)
		}
	}
}

// TestPeerCredCaptured verifies the daemon records the connecting process's
// OS-attested pid/uid in the receipt's peer-attestation slot. The agent's
// self-asserted identity is not consulted; this is the audit guarantee.
func TestPeerCredCaptured(t *testing.T) {
	cfg, _, _ := startDaemon(t)

	emitFrame(t, cfg.SocketPath, pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: "peer-fixture",
		Channel:   "sdk",
		Tool:      pipeline.EmitterTool{Name: "noop"},
		Decision:  "allowed",
	})

	receipts := waitForReceiptCount(t, cfg.DBPath, cfg.ChainID, 1, 5*time.Second)
	pc := receipts[0].CredentialSubject.Action.PeerCredential
	if pc == nil {
		t.Fatal("PeerCredential nil; daemon must record OS-attested peer cred")
	}

	wantPID := int32(os.Getpid())
	if pc.PID != wantPID {
		t.Errorf("peer_credential.pid = %d, want %d (OS-attested pid of test process)", pc.PID, wantPID)
	}
	wantUID := uint32(os.Geteuid())
	if pc.UID == nil || *pc.UID != wantUID {
		t.Errorf("peer_credential.uid = %v, want %d", pc.UID, wantUID)
	}
	wantGID := uint32(os.Getegid())
	if pc.GID == nil || *pc.GID != wantGID {
		t.Errorf("peer_credential.gid = %v, want %d", pc.GID, wantGID)
	}

	switch pc.Platform {
	case "linux":
		if pc.ExePath == "" {
			t.Error("Linux daemon should populate peer_credential.exe_path from /proc/<pid>/exe")
		}
	case "darwin":
		if pc.ExePath == "" {
			// SYS_PROC_INFO may be restricted in sandboxed CI environments; the
			// daemon degrades gracefully (pid/uid/gid still recorded). Log only.
			t.Log("darwin: peer_credential.exe_path empty; SYS_PROC_INFO may be restricted in this environment")
		}
	default:
		t.Errorf("unexpected peer_credential.platform = %q", pc.Platform)
	}

	// peer_credential.exe_path non-empty is too weak alone: a regression that
	// records the wrong process's path (the daemon's own binary instead of the
	// connecting client's) still produces a valid absolute path. The test
	// process is the daemon's connecting peer here, so exe_path must refer to
	// the same file as os.Executable. os.SameFile tolerates path
	// canonicalisation (e.g. macOS's /var → /private/var symlink) and any
	// /proc-style resolution difference.
	if got := pc.ExePath; got != "" {
		want, err := os.Executable()
		if err != nil {
			t.Fatalf("os.Executable: %v", err)
		}
		gotInfo, err := os.Stat(got)
		if err != nil {
			t.Fatalf("os.Stat(peer_credential.exe_path %q): %v", got, err)
		}
		wantInfo, err := os.Stat(want)
		if err != nil {
			t.Fatalf("os.Stat(os.Executable %q): %v", want, err)
		}
		if !os.SameFile(gotInfo, wantInfo) {
			t.Errorf("peer_credential.exe_path = %q is not the same file as os.Executable = %q (the test process is the daemon's connecting peer)", got, want)
		}
	}
}

// TestPeerCredFromSubprocess verifies the daemon reads peer credentials
// from the connecting process, not the listener's own process state.
// TestPeerCredCaptured runs daemon.Run in a goroutine inside this test
// process, so its captured pid/exe_path cannot distinguish "client" from
// "server" — both are the same OS process. This test re-execs the test
// binary as a subprocess (dispatched by TestMain via emitterHelperEnvVar),
// so the daemon's peer-cred capture runs against a process with a
// different pid. A regression that recorded the listener's pid instead of
// the connecting peer's would pass TestPeerCredCaptured but fail this.
func TestPeerCredFromSubprocess(t *testing.T) {
	cfg, _, _ := startDaemon(t)

	// -test.run=^$ matches no test function, so even if TestMain ever falls
	// through to m.Run() (it shouldn't, runEmitterHelper exits via os.Exit),
	// no tests would re-execute and create overlapping fixtures.
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		emitterHelperGuardVar+"=1",
		emitterHelperEnvVar+"="+cfg.SocketPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("subprocess emitter: %v (output: %s)", err, out)
	}

	receipts := waitForReceiptCount(t, cfg.DBPath, cfg.ChainID, 1, 5*time.Second)
	pc := receipts[0].CredentialSubject.Action.PeerCredential
	if pc == nil {
		t.Fatal("PeerCredential nil; daemon must record OS-attested peer cred for subprocess connection")
	}

	// peer_credential.pid must NOT be the test process's pid: the daemon must
	// have captured the subprocess's pid via the connected-socket primitive
	// (SO_PEERCRED on Linux, LOCAL_PEEREPID on macOS).
	if pc.PID == int32(os.Getpid()) {
		t.Errorf("peer_credential.pid = %d (= os.Getpid()); daemon recorded the listener's own pid instead of the connecting subprocess's", pc.PID)
	}
	if pc.PID == 0 {
		t.Errorf("peer_credential.pid is 0 — peer-cred capture failed for subprocess connection")
	}

	// peer_credential.exe_path: subprocess is the same binary, so SameFile
	// against os.Executable() still holds. Catches a regression that records a
	// hardcoded or constant path.
	if got := pc.ExePath; got != "" {
		want, err := os.Executable()
		if err != nil {
			t.Fatalf("os.Executable: %v", err)
		}
		gotInfo, err := os.Stat(got)
		if err != nil {
			t.Fatalf("os.Stat(peer_credential.exe_path %q): %v", got, err)
		}
		wantInfo, err := os.Stat(want)
		if err != nil {
			t.Fatalf("os.Stat(os.Executable %q): %v", want, err)
		}
		if !os.SameFile(gotInfo, wantInfo) {
			t.Errorf("peer_credential.exe_path = %q is not the same file as os.Executable = %q (subprocess is the same binary as parent)", got, want)
		}
	}
}

// TestShutdownWithIdleClient confirms the daemon shuts down promptly even
// when a client is connected and not sending anything. A misbehaving emitter
// that connects and idles MUST NOT prevent graceful shutdown. The test's
// connection is intentionally left open across the cancel — the test's own
// defer would otherwise close it and mask the bug.
func TestShutdownWithIdleClient(t *testing.T) {
	sockDir := sockettest.ShortSocketDir(t)
	dataDir := t.TempDir()
	cfg := daemon.Config{
		SocketPath:           filepath.Join(sockDir, "events.sock"),
		UnsafeSocketPath:     true, // /tmp ShortSocketDir is outside the safe set (issue #538)
		DBPath:               filepath.Join(dataDir, "receipts.db"),
		KeyPath:              filepath.Join(dataDir, "signing.key"),
		ChainID:              "idle",
		IssuerID:             "did:t",
		VerificationMethodID: "did:t#k1",
		Logger:               log.New(io.Discard, "", 0),
	}
	writeTestKey(t, cfg.KeyPath)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx, cfg) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := net.Dial("unix", cfg.SocketPath)
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	// Deliberately do NOT close conn. We're proving the daemon can shut down
	// while an idle peer is still connected.

	// Sleep long enough that the daemon's per-conn goroutine has definitely
	// entered io.ReadFull before we cancel — otherwise the goroutine would
	// observe ctx.Done() at the top of its loop and exit early, masking the
	// bug we're testing for.
	time.Sleep(100 * time.Millisecond)

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("daemon Run returned: %v", err)
		}
	case <-time.After(3 * time.Second):
		conn.Close() // cleanup so the goroutine doesn't outlive the test
		t.Fatal("daemon did not shut down within 3s with an idle client connected (per-conn readers must observe context cancellation)")
	}
	conn.Close()
}

// TestResumesChainAfterRestart confirms GetChainTail wires through Run: a
// daemon started against an existing DB picks up the highest-sequence receipt
// and continues from there, rather than restarting at 1.
func TestResumesChainAfterRestart(t *testing.T) {
	sockDir := sockettest.ShortSocketDir(t)
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "receipts.db")
	keyPath := filepath.Join(dataDir, "signing.key")
	socketPath := filepath.Join(sockDir, "events.sock")

	writeTestKey(t, keyPath)

	mkCfg := func() daemon.Config {
		return daemon.Config{
			SocketPath:           socketPath,
			UnsafeSocketPath:     true, // /tmp ShortSocketDir is outside the safe set (issue #538)
			DBPath:               dbPath,
			KeyPath:              keyPath,
			ChainID:              "resume-chain",
			IssuerID:             "did:agent-receipts-daemon:integration",
			VerificationMethodID: "did:agent-receipts-daemon:integration#k1",
			Logger:               log.New(io.Discard, "", 0),
			ShutdownDeadline:     time.Nanosecond, // crash mode — no terminator written between runs
		}
	}

	// runOnce starts the daemon, emits `frames` new receipts, waits for the
	// chain to reach `expectedTotal` (so the second run cannot finish before
	// its emits are processed by polling against a stale baseline), then
	// shuts the daemon down cleanly.
	runOnce := func(t *testing.T, frames, expectedTotal int) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- daemon.Run(ctx, mkCfg()) }()

		deadline := time.Now().Add(2 * time.Second)
		for {
			if _, err := os.Stat(socketPath); err == nil {
				break
			}
			if time.Now().After(deadline) {
				cancel()
				t.Fatal("socket did not appear")
			}
			time.Sleep(10 * time.Millisecond)
		}

		for i := 0; i < frames; i++ {
			emitFrame(t, socketPath, pipeline.EmitterFrame{
				Version: "1", TsEmit: "2026-05-03T00:00:00Z",
				SessionID: "s", Channel: "sdk",
				Tool: pipeline.EmitterTool{Name: "noop"}, Decision: "allowed",
			})
		}
		_ = waitForReceiptCount(t, dbPath, "resume-chain", expectedTotal, 5*time.Second)
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Logf("Run returned: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("daemon did not shut down")
		}
	}

	runOnce(t, 3, 3)

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	tailSeq, _, _, err := s.GetChainTail("resume-chain")
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	// No terminator (crash mode), so tail stays at seq=3.
	if tailSeq != 3 {
		t.Fatalf("after first run, tail seq = %d, want 3", tailSeq)
	}

	// Second run: 3 more frames land at seq=4..6. No terminator between runs, so 3+3=6.
	runOnce(t, 3, 6)

	// Wait for all 6 receipts.
	receipts := waitForReceiptCount(t, dbPath, "resume-chain", 6, 5*time.Second)
	for i, r := range receipts {
		if r.CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("receipt %d: seq = %d, want %d", i, r.CredentialSubject.Chain.Sequence, i+1)
		}
	}
}

// TestPublishedPublicKeyHasMode0644 confirms the daemon writes the public-key
// sibling file at the documented mode on every startup. The verify CLI relies
// on this file being world-readable so a non-daemon-user verifier (operator,
// CI runner, audit script) can load it without elevated access.
func TestPublishedPublicKeyHasMode0644(t *testing.T) {
	cfg, _, _ := startDaemon(t)

	info, err := os.Stat(cfg.PublicKeyPath)
	if err != nil {
		t.Fatalf("daemon did not publish public key at %s: %v", cfg.PublicKeyPath, err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("public key perm = %o, want 0644", perm)
	}
}

// TestVerifyCLIWhileDaemonRunning is the read-side counterpart to the chain-
// integrity test: with the daemon actively writing, agent-receipts verify
// must succeed using the published public-key file and the OpenReadOnly DB
// path. This is the "must not collide with the daemon's exclusive ownership
// of the write side" half of the acceptance criterion.
func TestVerifyCLIWhileDaemonRunning(t *testing.T) {
	cfg, _, _ := startDaemon(t)

	const frames = 5
	for i := 0; i < frames; i++ {
		emitFrame(t, cfg.SocketPath, pipeline.EmitterFrame{
			Version:   "1",
			TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
			SessionID: "verify-while-running",
			Channel:   "sdk",
			Tool:      pipeline.EmitterTool{Name: "noop"},
			Decision:  "allowed",
		})
	}
	_ = waitForReceiptCount(t, cfg.DBPath, cfg.ChainID, frames, 5*time.Second)

	var stdout, stderr bytes.Buffer
	code := verifycli.Run(
		[]string{"--db", cfg.DBPath, "--public-key", cfg.PublicKeyPath, "--chain-id", cfg.ChainID},
		&stdout, &stderr,
		func(string) string { return "" },
	)
	if code != verifycli.ExitOK {
		t.Fatalf("verify exit = %d, want %d (stdout=%q stderr=%q)", code, verifycli.ExitOK, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), fmt.Sprintf("Chain %s: VALID", cfg.ChainID)) {
		t.Errorf("stdout = %q, expected VALID line", stdout.String())
	}
}

// TestVerifyCLIWithDaemonStopped is the "Independent verifiability is not
// gated on daemon availability" acceptance criterion. Start the daemon, emit
// some receipts, shut the daemon down, then run agent-receipts verify against
// the on-disk DB and the published public key. Must succeed.
func TestVerifyCLIWithDaemonStopped(t *testing.T) {
	sockDir := sockettest.ShortSocketDir(t)
	dataDir := t.TempDir()
	cfg := daemon.Config{
		SocketPath:           filepath.Join(sockDir, "events.sock"),
		UnsafeSocketPath:     true, // /tmp ShortSocketDir is outside the safe set (issue #538)
		DBPath:               filepath.Join(dataDir, "receipts.db"),
		KeyPath:              filepath.Join(dataDir, "signing.key"),
		PublicKeyPath:        filepath.Join(dataDir, "signing.key.pub"),
		ChainID:              "stopped-chain",
		IssuerID:             "did:agent-receipts-daemon:integration",
		VerificationMethodID: "did:agent-receipts-daemon:integration#k1",
		Logger:               log.New(io.Discard, "", 0),
	}
	writeTestKey(t, cfg.KeyPath)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx, cfg) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}

	const frames = 3
	for i := 0; i < frames; i++ {
		emitFrame(t, cfg.SocketPath, pipeline.EmitterFrame{
			Version:   "1",
			TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
			SessionID: "verify-after-stop",
			Channel:   "sdk",
			Tool:      pipeline.EmitterTool{Name: "noop"},
			Decision:  "allowed",
		})
	}
	_ = waitForReceiptCount(t, cfg.DBPath, cfg.ChainID, frames, 5*time.Second)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Logf("daemon Run returned: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not shut down within 3s")
	}

	// Sanity-check the daemon really is gone before running verify; otherwise
	// a passing test wouldn't actually demonstrate the daemon-down property.
	if conn, err := net.Dial("unix", cfg.SocketPath); err == nil {
		conn.Close()
		t.Fatal("socket still accepting connections after cancel — daemon did not stop")
	}

	var stdout, stderr bytes.Buffer
	code := verifycli.Run(
		[]string{"--db", cfg.DBPath, "--public-key", cfg.PublicKeyPath, "--chain-id", cfg.ChainID},
		&stdout, &stderr,
		func(string) string { return "" },
	)
	if code != verifycli.ExitOK {
		t.Fatalf("verify with daemon stopped: exit = %d, want %d (stdout=%q stderr=%q)", code, verifycli.ExitOK, stdout.String(), stderr.String())
	}
	// Shutdown emits an interrupted terminator, so the chain has frames+1 receipts.
	if !strings.Contains(stdout.String(), fmt.Sprintf("Chain %s: VALID (%d receipts)", cfg.ChainID, frames+1)) {
		t.Errorf("stdout = %q, expected VALID + count line", stdout.String())
	}
}
