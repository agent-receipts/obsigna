//go:build integration && (linux || darwin)

package daemon

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/anchor"
	"github.com/agent-receipts/ar/daemon/internal/checkpoint"
	"github.com/agent-receipts/ar/sdk/go/store"
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

	cps := readVerifiedCheckpoints(t, anchorPath, cfg.ChainID, pubPEM)
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

// readVerifiedCheckpoints reads the anchor file and returns the checkpoints for
// chainID whose signatures verify against pubPEM, in file order. A signature
// that does not verify fails the test — the daemon must sign with its own key.
func readVerifiedCheckpoints(t *testing.T, path, chainID, pubPEM string) []checkpoint.Checkpoint {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open anchor: %v", err)
	}
	defer func() { _ = f.Close() }()

	var out []checkpoint.Checkpoint
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var rec anchor.Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("anchor line not a Record: %v", err)
		}
		if rec.EventType != anchor.EventTypeCheckpoint {
			continue
		}
		var signed checkpoint.Signed
		if err := json.Unmarshal(rec.Payload, &signed); err != nil {
			t.Fatalf("checkpoint payload: %v", err)
		}
		if signed.ChainID != chainID {
			continue
		}
		ok, err := checkpoint.Verify(signed, pubPEM)
		if err != nil || !ok {
			t.Fatalf("checkpoint (seq %d) failed verification: ok=%v err=%v", signed.Sequence, ok, err)
		}
		out = append(out, signed.Checkpoint)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan anchor: %v", err)
	}
	return out
}
