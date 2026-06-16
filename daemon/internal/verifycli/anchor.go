package verifycli

import (
	"fmt"

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
	cps, err := checkpoint.ReadVerifiedCheckpoints(anchorPath, chainID, pubPEM)
	if err != nil {
		return anchorResult{Reason: err.Error()}
	}
	if len(cps) == 0 {
		return anchorResult{Reason: fmt.Sprintf("no verified checkpoint found for chain %s in anchor %s", chainID, anchorPath)}
	}

	// Validate strict monotonicity in ANCHOR FILE ORDER, never after a re-sort.
	// The daemon appends a chain's checkpoints in strictly increasing sequence by
	// construction (the emitter only writes a head past the highest it already
	// anchored), so an out-of-order or duplicate record in the file is itself the
	// tamper/corruption signal. Sorting first would launder "seq 2 then seq 1"
	// into "1, 2" and pass — so the last record in file order is also the genuine
	// latest head, not a max() that hides reordering.
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
