package checkpoint

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"obsigna.dev/daemon/internal/anchor"
)

// writeAnchorFile creates a real anchor file signed by signer and returns the
// path. Duplicates the setup helper in anchor_test.go for self-containedness
// inside the checkpoint package.
func writeAnchorFile(t *testing.T, signer Signer, cps ...Checkpoint) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "anchor.ndjson")
	log, err := anchor.OpenFileLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	for _, cp := range cps {
		signed, err := Sign(cp, signer)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		if err := log.Write(anchor.EventTypeCheckpoint, payload); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// TestReadLatestVerifiedCheckpoint_Basic verifies that only the latest
// checkpoint per chain is returned on a short log.
func TestReadLatestVerifiedCheckpoint_Basic(t *testing.T) {
	signer, pubPEM := newTestSigner(t)
	path := writeAnchorFile(t, signer,
		Checkpoint{ChainID: "c", Sequence: 1, ReceiptHash: "sha256:a", Timestamp: "2026-01-01T00:00:00Z"},
		Checkpoint{ChainID: "c", Sequence: 2, ReceiptHash: "sha256:b", Timestamp: "2026-01-01T00:00:01Z"},
		Checkpoint{ChainID: "c", Sequence: 3, ReceiptHash: "sha256:c", Timestamp: "2026-01-01T00:00:02Z"},
	)

	got, err := ReadLatestVerifiedCheckpoint(path, "c", pubPEM)
	if err != nil {
		t.Fatalf("ReadLatestVerifiedCheckpoint: %v", err)
	}
	if got == nil {
		t.Fatal("expected a checkpoint, got nil")
	}
	if got.Sequence != 3 {
		t.Errorf("expected seq 3 (latest), got seq %d", got.Sequence)
	}
	if got.ReceiptHash != "sha256:c" {
		t.Errorf("expected hash sha256:c, got %s", got.ReceiptHash)
	}
}

// TestReadLatestVerifiedCheckpoint_MultiChain verifies that only checkpoints
// for the requested chain are returned, even when other chains are interleaved.
func TestReadLatestVerifiedCheckpoint_MultiChain(t *testing.T) {
	signer, pubPEM := newTestSigner(t)
	// Interleave two chains in the same anchor log.
	path := writeAnchorFile(t, signer,
		Checkpoint{ChainID: "chain-a", Sequence: 1, ReceiptHash: "sha256:a1", Timestamp: "T"},
		Checkpoint{ChainID: "chain-b", Sequence: 1, ReceiptHash: "sha256:b1", Timestamp: "T"},
		Checkpoint{ChainID: "chain-a", Sequence: 2, ReceiptHash: "sha256:a2", Timestamp: "T"},
		Checkpoint{ChainID: "chain-b", Sequence: 5, ReceiptHash: "sha256:b5", Timestamp: "T"},
	)

	gotA, err := ReadLatestVerifiedCheckpoint(path, "chain-a", pubPEM)
	if err != nil {
		t.Fatalf("ReadLatestVerifiedCheckpoint(chain-a): %v", err)
	}
	if gotA == nil || gotA.Sequence != 2 {
		t.Errorf("chain-a: expected seq 2, got %v", gotA)
	}

	gotB, err := ReadLatestVerifiedCheckpoint(path, "chain-b", pubPEM)
	if err != nil {
		t.Fatalf("ReadLatestVerifiedCheckpoint(chain-b): %v", err)
	}
	if gotB == nil || gotB.Sequence != 5 {
		t.Errorf("chain-b: expected seq 5, got %v", gotB)
	}
}

// TestReadLatestVerifiedCheckpoint_NoCheckpointForChain verifies nil is
// returned (no error) when the anchor log has no checkpoints for the chain.
func TestReadLatestVerifiedCheckpoint_NoCheckpointForChain(t *testing.T) {
	signer, pubPEM := newTestSigner(t)
	path := writeAnchorFile(t, signer,
		Checkpoint{ChainID: "other", Sequence: 1, ReceiptHash: "sha256:x", Timestamp: "T"},
	)

	got, err := ReadLatestVerifiedCheckpoint(path, "wanted-chain", pubPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for unknown chain, got %+v", got)
	}
}

// TestReadLatestVerifiedCheckpoint_WrongKeyRejects verifies that a checkpoint
// signed with a different key returns an error rather than silently passing.
func TestReadLatestVerifiedCheckpoint_WrongKeyRejects(t *testing.T) {
	signer, _ := newTestSigner(t)
	_, wrongPubPEM := newTestSigner(t)
	path := writeAnchorFile(t, signer,
		Checkpoint{ChainID: "c", Sequence: 1, ReceiptHash: "sha256:a", Timestamp: "T"},
	)

	_, err := ReadLatestVerifiedCheckpoint(path, "c", wrongPubPEM)
	if err == nil {
		t.Fatal("expected error when verifying with wrong key, got nil")
	}
}

// TestReadLatestVerifiedCheckpoint_LargeLog verifies that only the last
// checkpoint is returned without error for a longer anchor log. This is the
// efficiency-motivation case: in production the log could hold thousands of
// entries; verifyAgainstAnchor only needs the final one.
func TestReadLatestVerifiedCheckpoint_LargeLog(t *testing.T) {
	signer, pubPEM := newTestSigner(t)

	const n = 200
	cps := make([]Checkpoint, n)
	for i := range cps {
		cps[i] = Checkpoint{
			ChainID:     "c",
			Sequence:    int64(i + 1),
			ReceiptHash: "sha256:h",
			Timestamp:   "T",
		}
	}
	path := writeAnchorFile(t, signer, cps...)

	got, err := ReadLatestVerifiedCheckpoint(path, "c", pubPEM)
	if err != nil {
		t.Fatalf("ReadLatestVerifiedCheckpoint: %v", err)
	}
	if got == nil {
		t.Fatal("expected checkpoint, got nil")
	}
	if got.Sequence != n {
		t.Errorf("expected seq %d (last), got %d", n, got.Sequence)
	}
}

// TestReadLatestVerifiedCheckpoint_EmptyFile verifies nil is returned for an
// anchor file with no records.
func TestReadLatestVerifiedCheckpoint_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.ndjson")
	log, err := anchor.OpenFileLog(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = log.Close()

	signer, pubPEM := newTestSigner(t)
	_ = signer
	got, err := ReadLatestVerifiedCheckpoint(path, "c", pubPEM)
	if err != nil {
		t.Fatalf("unexpected error on empty file: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for empty anchor file, got %+v", got)
	}
}

// TestReadLatestVerifiedCheckpoint_NonMonotonicReturnsError verifies that a
// checkpoint log with out-of-order or duplicate sequences returns an error
// rather than silently accepting the last (possibly lower) record as latest.
func TestReadLatestVerifiedCheckpoint_NonMonotonicReturnsError(t *testing.T) {
	signer, pubPEM := newTestSigner(t)

	t.Run("duplicate_seq", func(t *testing.T) {
		path := writeAnchorFile(t, signer,
			Checkpoint{ChainID: "c", Sequence: 1, ReceiptHash: "sha256:a", Timestamp: "T"},
			Checkpoint{ChainID: "c", Sequence: 1, ReceiptHash: "sha256:dup", Timestamp: "T"},
		)
		_, err := ReadLatestVerifiedCheckpoint(path, "c", pubPEM)
		if err == nil {
			t.Fatal("expected error for duplicate sequence, got nil")
		}
	})

	t.Run("out_of_order", func(t *testing.T) {
		path := writeAnchorFile(t, signer,
			Checkpoint{ChainID: "c", Sequence: 2, ReceiptHash: "sha256:2", Timestamp: "T"},
			Checkpoint{ChainID: "c", Sequence: 1, ReceiptHash: "sha256:1", Timestamp: "T"},
		)
		_, err := ReadLatestVerifiedCheckpoint(path, "c", pubPEM)
		if err == nil {
			t.Fatal("expected error for out-of-order sequence, got nil")
		}
	})
}
