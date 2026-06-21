//go:build integration && (linux || darwin)

package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"obsigna.dev/daemon/internal/checkpoint"
	"obsigna.dev/sdk/go/store"
)

// TestCheckpointAnchorEndToEnd exercises the full daemon wiring: a Config with
// a checkpoint anchor sink starts the daemon, real emitter frames flow over the
// socket, the daemon signs a checkpoint per receipt to the out-of-band anchor,
// and after a graceful shutdown (which flushes the final HEAD) the anchored
// head is a verifiable checkpoint that matches the store HEAD. This is the
// Config→Run→OpenSinks→emitter→FlushCheckpoints→Close path the deterministic
// pipeline-level gate (tests_checkpoint_truncation_test.go) does not cover.
func TestCheckpointAnchorEndToEnd(t *testing.T) {
	cfg, pubPEM := newDaemonConfig(t, 0)
	anchorPath := filepath.Join(t.TempDir(), "anchor.ndjson")
	cfg.CheckpointAnchors = []string{"file:" + anchorPath}
	cfg.CheckpointCadence = 1

	fix := StartDaemonFromConfig(t, cfg, pubPEM)

	const n = 3
	for i := 0; i < n; i++ {
		if err := fix.EmitGoFrame(t, "sess-cp", "mcp_proxy", "list_repos", "github", "allowed"); err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
	}
	fix.WaitForReceiptCount(t, n, 2*time.Second)

	// Graceful shutdown: drains the listener, emits the interrupted-chain
	// terminator, flushes a final checkpoint for the terminal head, and closes
	// the sinks.
	fix.Stop(t)

	cps, err := checkpoint.ReadVerifiedCheckpoints(anchorPath, cfg.ChainID, pubPEM)
	if err != nil {
		t.Fatalf("read anchor: %v", err)
	}
	if len(cps) == 0 {
		t.Fatal("no verified checkpoints in the anchor — the daemon did not anchor anything")
	}

	// The latest checkpoint must match the store HEAD after a clean shutdown
	// (the flush anchors the terminal receipt).
	latest := cps[len(cps)-1]
	s, err := store.OpenReadOnly(cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s.Close() }()
	seq, hash, found, err := s.GetChainTail(cfg.ChainID)
	if err != nil {
		t.Fatalf("get chain tail: %v", err)
	}
	if !found {
		t.Fatal("store has no receipts")
	}
	if latest.Sequence != seq {
		t.Errorf("latest checkpoint seq = %d, store head seq = %d", latest.Sequence, seq)
	}
	if latest.ReceiptHash != hash {
		t.Errorf("latest checkpoint hash = %s, store head hash = %s", latest.ReceiptHash, hash)
	}
}

// TestCheckpointAnchorAbruptShutdownNoDuplicate is the regression for the
// shutdown-flush double-emit bug. With a 1ns shutdown deadline the
// interrupted-chain terminator is skipped, so the chain tail stays at the last
// live receipt — the head the per-receipt Observe already anchored. The
// shutdown FlushCheckpoints must NOT re-anchor that head: a duplicate checkpoint
// at the same sequence makes `verify --against-anchor` read the log as
// non-strictly-increasing and fail a perfectly healthy chain.
func TestCheckpointAnchorAbruptShutdownNoDuplicate(t *testing.T) {
	cfg, pubPEM := newDaemonConfig(t, time.Nanosecond) // crash-grade deadline → terminator skipped
	anchorPath := filepath.Join(t.TempDir(), "anchor.ndjson")
	cfg.CheckpointAnchors = []string{"file:" + anchorPath}
	cfg.CheckpointCadence = 1

	fix := StartDaemonFromConfig(t, cfg, pubPEM)
	const n = 3
	for i := 0; i < n; i++ {
		if err := fix.EmitGoFrame(t, "sess-cp", "mcp_proxy", "list_repos", "github", "allowed"); err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
	}
	fix.WaitForReceiptCount(t, n, 2*time.Second)
	fix.Stop(t)

	cps, err := checkpoint.ReadVerifiedCheckpoints(anchorPath, cfg.ChainID, pubPEM)
	if err != nil {
		t.Fatalf("read anchor: %v", err)
	}
	for i := 1; i < len(cps); i++ {
		if cps[i].Sequence <= cps[i-1].Sequence {
			t.Fatalf("duplicate/out-of-order checkpoint after abrupt shutdown: seq %d follows seq %d (all: %+v)",
				cps[i].Sequence, cps[i-1].Sequence, cps)
		}
	}
}
