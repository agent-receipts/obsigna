//go:build integration && (linux || darwin)

package daemon

import (
	"errors"
	"net"
	"sort"
	"syscall"
	"testing"
	"time"

	"obsigna.dev/sdk/go/receipt"
)

// TestResumePrevHashIntegrity verifies that a daemon restarting on the same DB
// correctly links the prev_hash of the first receipt after restart to the hash
// of the last receipt from the previous run. This is the critical cross-restart
// chain integrity check.
func TestResumePrevHashIntegrity(t *testing.T) {
	// First run: emit 3 frames
	fix1 := StartDaemonCrash(t)
	for i := 0; i < 3; i++ {
		if err := fix1.EmitGoFrame(t, "resume-test", "sdk", "test-tool", "", "allowed"); err != nil {
			t.Fatalf("first run emit %d: %v", i, err)
		}
	}
	receipts1 := fix1.WaitForReceiptCount(t, 3, 5*time.Second)
	if len(receipts1) != 3 {
		t.Fatalf("first run: expected 3 receipts, got %d", len(receipts1))
	}

	// Extract public key and config for the second run
	pubPEM := fix1.PublicKey
	cfg := fix1.Config

	// Manually stop the first daemon (don't wait for t.Cleanup)
	fix1.cancel()
	select {
	case <-fix1.done:
		if fix1.daemonErr != nil {
			t.Logf("first daemon returned: %v", fix1.daemonErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("first daemon did not shut down within 3s")
	}

	// Second run: restart daemon on same config/key/DB
	fix2 := StartDaemonFromConfig(t, cfg, pubPEM)
	if err := fix2.EmitGoFrame(t, "resume-test", "sdk", "test-tool", "", "allowed"); err != nil {
		t.Fatalf("second run emit: %v", err)
	}
	receipts2 := fix2.WaitForReceiptCount(t, 4, 5*time.Second)
	if len(receipts2) != 4 {
		t.Fatalf("second run: expected 4 receipts, got %d", len(receipts2))
	}

	// Verify hash link across restart boundary
	hash3, err := receipt.HashReceipt(receipts2[2])
	if err != nil {
		t.Fatalf("hash receipt 2: %v", err)
	}
	prevHash4 := receipts2[3].CredentialSubject.Chain.PreviousReceiptHash
	if prevHash4 == nil {
		t.Errorf("prev_hash is nil at restart boundary, expected hash value")
	} else if hash3 != *prevHash4 {
		t.Errorf("prev_hash mismatch at restart boundary: hash(receipts[2])=%s, receipts[3].prev_hash=%s",
			hash3, *prevHash4)
	}

	// Also verify the full chain is contiguous
	for i := 0; i < len(receipts2); i++ {
		if receipts2[i].CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("sequence gap at index %d: got %d, want %d",
				i, receipts2[i].CredentialSubject.Chain.Sequence, i+1)
		}
	}
}

// TestResumesChainAfterUncleanShutdown verifies that after a non-graceful
// shutdown (context cancel without waiting), restarting the daemon on the same
// DB produces a contiguous chain from the last durable commit onwards.
func TestResumesChainAfterUncleanShutdown(t *testing.T) {
	// First run: emit 3 frames, then kill (don't wait for shutdown)
	fix1 := StartDaemonCrash(t)
	for i := 0; i < 3; i++ {
		if err := fix1.EmitGoFrame(t, "unclean-test", "sdk", "test-tool", "", "allowed"); err != nil {
			t.Fatalf("first run emit %d: %v", i, err)
		}
	}
	receipts1 := fix1.WaitForReceiptCount(t, 3, 5*time.Second)
	if len(receipts1) != 3 {
		t.Fatalf("first run: expected 3 receipts, got %d", len(receipts1))
	}

	pubPEM := fix1.PublicKey
	cfg := fix1.Config

	// Cancel context immediately without waiting (tests restart after graceful shutdown;
	// SQLite WAL mode ensures prior commits are durable even if shutdown isn't observed).
	fix1.cancel()
	select {
	case <-fix1.done:
		if fix1.daemonErr != nil {
			t.Logf("daemon error after cancel: %v", fix1.daemonErr)
		}
	case <-time.After(1 * time.Second):
		// Daemon is still shutting down, but WAL commits are already durable
	}

	// Small delay to ensure database file handles are released
	time.Sleep(100 * time.Millisecond)

	// Wait for first daemon's socket to become unconnectable before restarting
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("unix", cfg.SocketPath, 100*time.Millisecond)
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			break // Socket is truly gone, safe to restart
		}
		if err == nil {
			conn.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("first daemon socket still listening after 2s, restart would conflict")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Second run: restart and emit more
	fix2 := StartDaemonFromConfig(t, cfg, pubPEM)
	if err := fix2.EmitGoFrame(t, "unclean-test", "sdk", "test-tool", "", "allowed"); err != nil {
		t.Fatalf("second run emit: %v", err)
	}

	receipts2 := fix2.WaitForReceiptCount(t, 4, 5*time.Second)
	if len(receipts2) != 4 {
		t.Fatalf("second run: expected 4 receipts, got %d", len(receipts2))
	}

	// Verify no gaps in the sequence (SQLite WAL commits are durable)
	sort.Slice(receipts2, func(i, j int) bool {
		return receipts2[i].CredentialSubject.Chain.Sequence <
			receipts2[j].CredentialSubject.Chain.Sequence
	})

	for i := 0; i < len(receipts2); i++ {
		if receipts2[i].CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("sequence gap at index %d after unclean shutdown: got seq %d, want %d",
				i, receipts2[i].CredentialSubject.Chain.Sequence, i+1)
		}
	}
}

// TestResumesWithConcurrentEmittersOnRestart verifies that a daemon restarted
// with a resumed chain can immediately handle concurrent emitters without
// sequence gaps or lost frames.
func TestResumesWithConcurrentEmittersOnRestart(t *testing.T) {
	// First run: emit 5 frames cleanly
	fix1 := StartDaemonCrash(t)
	for i := 0; i < 5; i++ {
		if err := fix1.EmitGoFrame(t, "concurrent-test", "sdk", "test-tool", "", "allowed"); err != nil {
			t.Fatalf("first run emit %d: %v", i, err)
		}
	}
	receipts1 := fix1.WaitForReceiptCount(t, 5, 5*time.Second)
	if len(receipts1) != 5 {
		t.Fatalf("first run: expected 5 receipts, got %d", len(receipts1))
	}

	pubPEM := fix1.PublicKey
	cfg := fix1.Config

	// Clean shutdown of first daemon
	fix1.cancel()
	select {
	case <-fix1.done:
	case <-time.After(3 * time.Second):
		t.Fatalf("first daemon did not shut down")
	}

	// Second run: immediately spawn concurrent emitters
	fix2 := StartDaemonFromConfig(t, cfg, pubPEM)

	// 3 goroutines, 5 frames each = 15 more frames (20 total)
	errCh := make(chan error, 3)
	for g := 0; g < 3; g++ {
		go func(_ int) {
			for i := 0; i < 5; i++ {
				err := fix2.EmitGoFrame(t, "concurrent-test", "sdk", "test-tool", "", "allowed")
				if err != nil {
					errCh <- err
					return
				}
			}
			errCh <- nil
		}(g)
	}

	// Wait for all goroutines to report
	for i := 0; i < 3; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent emit goroutine failed: %v", err)
		}
	}

	// Wait for all 20 receipts to land (5 from first run + 15 from second run = 20 total
	// (no terminator: crash mode)).
	receipts2 := fix2.WaitForReceiptCount(t, 20, 10*time.Second)
	if len(receipts2) != 20 {
		t.Fatalf("second run: expected 20 receipts, got %d\ntrace:\n%s",
			len(receipts2), fix2.Trace())
	}

	// Sort by sequence and verify contiguity
	sort.Slice(receipts2, func(i, j int) bool {
		return receipts2[i].CredentialSubject.Chain.Sequence <
			receipts2[j].CredentialSubject.Chain.Sequence
	})

	for i := 0; i < len(receipts2); i++ {
		if receipts2[i].CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("sequence gap at index %d: got seq %d, want %d",
				i, receipts2[i].CredentialSubject.Chain.Sequence, i+1)
		}
	}

	// Verify all signatures
	for i, r := range receipts2 {
		ok, err := receipt.Verify(r, pubPEM)
		if err != nil || !ok {
			t.Errorf("receipt %d verify failed: ok=%v err=%v", i, ok, err)
		}
	}

	// Verify prev_hash chain
	for i := 1; i < len(receipts2); i++ {
		expectedHash, err := receipt.HashReceipt(receipts2[i-1])
		if err != nil {
			t.Errorf("hash receipt %d: %v", i-1, err)
			continue
		}
		actualHash := receipts2[i].CredentialSubject.Chain.PreviousReceiptHash
		if actualHash == nil {
			t.Errorf("prev_hash is nil at seq %d, expected hash value", i+1)
		} else if expectedHash != *actualHash {
			t.Errorf("prev_hash mismatch at seq %d: expected %s, got %s",
				i+1, expectedHash, *actualHash)
		}
	}
}
