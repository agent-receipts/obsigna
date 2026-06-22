package verifycli

import (
	"fmt"

	"obsigna.dev/daemon/internal/checkpoint"
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
//   - read the anchor log and retrieve the latest verified checkpoint for
//     chainID (signature-checked against the published key, pubPEM); the
//     monotonicity invariant the emitter guarantees means the last record in
//     file order IS the latest head, so a single forward scan suffices;
//   - assert the latest checkpoint's sequence matches the store HEAD's: a
//     checkpoint AHEAD of the store is exactly tail truncation — the anchor
//     witnessed receipts the store no longer has (Truncated=true);
//   - assert the latest checkpoint's receipt_hash matches the store HEAD's hash
//     at that sequence (content tamper at the head).
//
// The caller supplies the store HEAD (seq/hash/found) it already loaded, so the
// anchor check never re-opens the store.
func verifyAgainstAnchor(anchorPath, chainID, pubPEM string, headSeq int64, headHash string, headFound bool) anchorResult {
	latest, err := checkpoint.ReadLatestVerifiedCheckpoint(anchorPath, chainID, pubPEM)
	if err != nil {
		return anchorResult{Reason: err.Error()}
	}
	if latest == nil {
		return anchorResult{Reason: fmt.Sprintf("no verified checkpoint found for chain %s in anchor %s", chainID, anchorPath)}
	}

	if !headFound {
		// The anchor witnessed checkpoints but the store has no receipts for the
		// chain — the whole tail (everything up to the anchored head) is gone.
		return anchorResult{
			Checked:   1,
			Truncated: true,
			Reason:    fmt.Sprintf("anchor records head at seq %d but the store has no receipts for chain %s: chain truncated", latest.Sequence, chainID),
		}
	}

	switch {
	case latest.Sequence > headSeq:
		return anchorResult{
			Checked:   1,
			Truncated: true,
			Reason: fmt.Sprintf("anchor records head at seq %d (%s) but store head is seq %d: receipts %d..%d truncated",
				latest.Sequence, latest.ReceiptHash, headSeq, headSeq+1, latest.Sequence),
		}
	case latest.Sequence < headSeq:
		return anchorResult{
			Checked: 1,
			Reason: fmt.Sprintf("store head seq %d is ahead of the latest checkpoint seq %d: checkpoint(s) missing or the store was extended after anchoring",
				headSeq, latest.Sequence),
		}
	case latest.ReceiptHash != headHash:
		return anchorResult{
			Checked: 1,
			Reason: fmt.Sprintf("head receipt hash mismatch at seq %d: anchor has %s, store has %s",
				headSeq, latest.ReceiptHash, headHash),
		}
	}

	return anchorResult{OK: true, Checked: 1}
}
