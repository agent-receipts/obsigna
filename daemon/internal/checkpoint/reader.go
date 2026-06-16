package checkpoint

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/agent-receipts/ar/daemon/internal/anchor"
)

// ReadVerifiedCheckpoints reads an anchor log at path and returns the
// checkpoints recorded for chainID whose signatures verify against the
// PEM/SPKI public key publicKeyPEM, in file order. Records for other event
// types or other chains are skipped. A checkpoint whose signature does NOT
// verify is a hard error — a forged or wrong-key anchor must not be silently
// dropped. This is the single anchor reader shared by `verify --against-anchor`
// and the daemon's end-to-end test, so both parse the anchor identically.
func ReadVerifiedCheckpoints(path, chainID string, publicKeyPEM string) ([]Checkpoint, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open anchor %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var out []Checkpoint
	sc := bufio.NewScanner(f)
	// Anchor records can be large (a checkpoint payload plus envelope); lift the
	// scanner's line cap well above the default 64 KiB so a long line is not
	// silently split into a parse error.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var rec anchor.Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("anchor %s line %d: not a JSON record: %w", path, lineNo, err)
		}
		if rec.EventType != anchor.EventTypeCheckpoint {
			continue
		}
		var signed Signed
		if err := json.Unmarshal(rec.Payload, &signed); err != nil {
			return nil, fmt.Errorf("anchor %s line %d: checkpoint payload: %w", path, lineNo, err)
		}
		if signed.ChainID != chainID {
			continue
		}
		ok, err := Verify(signed, publicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("anchor %s line %d: verify checkpoint (seq %d): %w", path, lineNo, signed.Sequence, err)
		}
		if !ok {
			return nil, fmt.Errorf("anchor %s line %d: checkpoint signature invalid (seq %d)", path, lineNo, signed.Sequence)
		}
		out = append(out, signed.Checkpoint)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read anchor %s: %w", path, err)
	}
	return out, nil
}
