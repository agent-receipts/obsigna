package verifycli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/agent-receipts/ar/daemon/internal/anchor"
	"github.com/agent-receipts/ar/daemon/internal/checkpoint"
)

// anchorResult is the structured outcome of an --against-anchor check. Reason
// is human-readable and empty on success; Truncated marks the specific failure
// the CI verification-contract gate asserts ("no tail truncation"), so a test
// (or a script) can distinguish a truncation from other anchor failures.
type anchorResult struct {
	OK        bool
	Truncated bool
	Reason    string
	Checked   int // number of verified checkpoints for the chain
}

// verifyAgainstAnchor checks the receipt chain HEAD against the out-of-band
// signed checkpoints in the anchor at anchorPath (ADR-0008 follow-through).
//
// It performs, in order:
//   - read every anchor record, keep the "checkpoint" events for chainID, and
//     verify each one's Ed25519 signature against the published key (pubPEM);
//   - assert the checkpoint log is strictly increasing in sequence (an interior
//     duplicate/decrease means a corrupted or tampered anchor);
//   - assert the latest checkpoint's sequence matches the store HEAD's: a
//     checkpoint AHEAD of the store is exactly tail truncation — the anchor
//     witnessed receipts the store no longer has (Truncated=true);
//   - assert the latest checkpoint's receipt_hash matches the store HEAD's hash
//     at that sequence (content tamper at the head).
//
// The caller supplies the store HEAD (seq/hash/found) it already loaded, so the
// anchor check never re-opens the store.
func verifyAgainstAnchor(anchorPath, chainID, pubPEM string, headSeq int64, headHash string, headFound bool) anchorResult {
	cps, err := loadCheckpoints(anchorPath, chainID, pubPEM)
	if err != nil {
		return anchorResult{Reason: err.Error()}
	}
	if len(cps) == 0 {
		return anchorResult{Reason: fmt.Sprintf("no verified checkpoint found for chain %s in anchor %s", chainID, anchorPath)}
	}

	sort.Slice(cps, func(i, j int) bool { return cps[i].Sequence < cps[j].Sequence })
	for i := 1; i < len(cps); i++ {
		if cps[i].Sequence <= cps[i-1].Sequence {
			return anchorResult{
				Checked: len(cps),
				Reason:  fmt.Sprintf("checkpoint log is not strictly increasing: seq %d follows seq %d", cps[i].Sequence, cps[i-1].Sequence),
			}
		}
	}
	latest := cps[len(cps)-1]

	if !headFound {
		// The anchor witnessed checkpoints but the store has no receipts for the
		// chain — the whole tail (everything up to the anchored head) is gone.
		return anchorResult{
			Checked:   len(cps),
			Truncated: true,
			Reason:    fmt.Sprintf("anchor records head at seq %d but the store has no receipts for chain %s: chain truncated", latest.Sequence, chainID),
		}
	}

	switch {
	case latest.Sequence > headSeq:
		return anchorResult{
			Checked:   len(cps),
			Truncated: true,
			Reason: fmt.Sprintf("anchor records head at seq %d (%s) but store head is seq %d: receipts %d..%d truncated",
				latest.Sequence, latest.ReceiptHash, headSeq, headSeq+1, latest.Sequence),
		}
	case latest.Sequence < headSeq:
		return anchorResult{
			Checked: len(cps),
			Reason: fmt.Sprintf("store head seq %d is ahead of the latest checkpoint seq %d: checkpoint(s) missing or the store was extended after anchoring",
				headSeq, latest.Sequence),
		}
	case latest.ReceiptHash != headHash:
		return anchorResult{
			Checked: len(cps),
			Reason: fmt.Sprintf("head receipt hash mismatch at seq %d: anchor has %s, store has %s",
				headSeq, latest.ReceiptHash, headHash),
		}
	}

	return anchorResult{OK: true, Checked: len(cps)}
}

// loadCheckpoints reads anchorPath, returning the verified checkpoints for
// chainID. A checkpoint whose signature does not verify against pubPEM is a
// hard error — a forged or wrong-key anchor must not be silently skipped.
func loadCheckpoints(anchorPath, chainID, pubPEM string) ([]checkpoint.Checkpoint, error) {
	f, err := os.Open(anchorPath)
	if err != nil {
		return nil, fmt.Errorf("open anchor %s: %w", anchorPath, err)
	}
	defer func() { _ = f.Close() }()

	var out []checkpoint.Checkpoint
	sc := bufio.NewScanner(f)
	// Anchor records can be large (a checkpoint payload plus envelope); lift the
	// scanner's line cap well above the default 64 KiB so a long line is not
	// silently split into a parse error.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var rec anchor.Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("anchor %s line %d: not a JSON record: %w", anchorPath, line, err)
		}
		if rec.EventType != anchor.EventTypeCheckpoint {
			continue
		}
		var signed checkpoint.Signed
		if err := json.Unmarshal(rec.Payload, &signed); err != nil {
			return nil, fmt.Errorf("anchor %s line %d: checkpoint payload: %w", anchorPath, line, err)
		}
		if signed.ChainID != chainID {
			continue
		}
		ok, err := checkpoint.Verify(signed, pubPEM)
		if err != nil {
			return nil, fmt.Errorf("anchor %s line %d: verify checkpoint (seq %d): %w", anchorPath, line, signed.Sequence, err)
		}
		if !ok {
			return nil, fmt.Errorf("anchor %s line %d: checkpoint signature invalid (seq %d)", anchorPath, line, signed.Sequence)
		}
		out = append(out, signed.Checkpoint)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read anchor %s: %w", anchorPath, err)
	}
	return out, nil
}
