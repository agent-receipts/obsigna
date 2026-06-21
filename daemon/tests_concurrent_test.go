//go:build integration && (linux || darwin)

package daemon

import (
	"sort"
	"sync"
	"testing"
	"time"

	"obsigna.dev/sdk/go/receipt"
)

// TestConcurrentSDKEmitters fires all 3 emitters (Go, TS, Python) concurrently,
// each emitting 10 frames. Verifies the daemon produces 30 receipts with no
// gaps in the sequence chain.
func TestConcurrentSDKEmitters(t *testing.T) {
	f := StartDaemon(t)

	const framesPerEmitter = 10
	const totalFrames = 3 * framesPerEmitter

	var wg sync.WaitGroup
	errCh := make(chan error, 3)

	// Go emitter: 10 frames
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < framesPerEmitter; i++ {
			if err := f.EmitGoFrame(t, "go-concurrent", "sdk", "concurrent-tool", "", "allowed"); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// TypeScript emitter: 10 frames
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < framesPerEmitter; i++ {
			if err := f.EmitTSFrame(t, "ts-concurrent", "sdk", "concurrent-tool", "allowed"); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// Python emitter: 10 frames
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < framesPerEmitter; i++ {
			if err := f.EmitPythonFrame(t, "py-concurrent", "sdk", "concurrent-tool", "allowed"); err != nil {
				errCh <- err
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)

	// Check for emitter errors
	for err := range errCh {
		t.Fatalf("emitter failed: %v", err)
	}

	// Wait for all receipts (30 total). 120 s gives macOS CI runners (which are
	// significantly slower than Linux) enough headroom; the poll exits as soon
	// as all receipts arrive so the happy path is unaffected.
	receipts := f.WaitForReceiptCount(t, totalFrames, 120*time.Second)

	// store.GetChain orders by insert id, which under concurrent emitters does
	// not necessarily match Chain.Sequence (frame-receive order vs.
	// chain-allocation order). Sort by Sequence so the prev_hash walk and the
	// "no gaps" check below operate on chain-canonical order. Without this,
	// a perfectly valid chain could fail prev_hash assertions purely because
	// receipts arrived back from the store in a different order than the
	// daemon allocated them.
	sort.Slice(receipts, func(i, j int) bool {
		return receipts[i].CredentialSubject.Chain.Sequence < receipts[j].CredentialSubject.Chain.Sequence
	})

	// Duplicate-sequence check first: a duplicate would also break the
	// prev_hash walk, but with a misleading "wrong prev_hash" error rather
	// than the real cause.
	seen := make(map[int]bool, len(receipts))
	for _, r := range receipts {
		seq := r.CredentialSubject.Chain.Sequence
		if seen[seq] {
			t.Errorf("seq %d allocated twice", seq)
		}
		seen[seq] = true
	}

	// Sequence assertion: receipts are now sorted ascending, so seq[i] must
	// equal i+1 (chain sequences are 1-indexed). This catches both gaps and
	// off-by-one errors in a single check.
	for i, r := range receipts {
		got := r.CredentialSubject.Chain.Sequence
		if got != i+1 {
			t.Errorf("receipts[%d].Sequence = %d, want %d (gap or duplicate)", i, got, i+1)
		}
	}

	// Prev-hash walk + signature verification on the now-sorted chain.
	for i, r := range receipts {
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

		ok, err := receipt.Verify(r, f.PublicKey)
		if err != nil || !ok {
			t.Errorf("receipt %d: verify ok=%v err=%v", i, ok, err)
		}
	}
}
