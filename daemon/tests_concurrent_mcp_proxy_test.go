//go:build integration && (linux || darwin)

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/agent-receipts/ar/sdk/go/emitter"
	"github.com/agent-receipts/ar/sdk/go/receipt"
)

// isTransientIOTimeout reports whether err is a network timeout (e.g. a
// deadline-exceeded write on an AF_UNIX socket). Used to distinguish transport
// stalls — which are safe to retry after a brief pause — from logic errors.
func isTransientIOTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// TestTwoMCPProxySessionsConcurrent simulates two independent mcp-proxy
// sessions, each holding a persistent emitter connection, emitting concurrently
// to the same daemon. Regression test for the chain sequence UNIQUE constraint
// race (#236 comment 2): if the daemon's sequence-allocation is not serialised,
// concurrent sessions can be allocated the same sequence number, breaking chain
// integrity. Each session uses a distinct server name so receipts are
// attributable to their origin.
func TestTwoMCPProxySessionsConcurrent(t *testing.T) {
	fix := StartDaemon(t)

	const (
		sessions        = 2
		emitsPerSession = 50
		total           = sessions * emitsPerSession
	)

	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("daemon trace:\n%s", fix.Trace())
		}
	})

	errCh := make(chan error, sessions)

	for i := 0; i < sessions; i++ {
		go func(session int) {
			// Per-goroutine rand source seeded from session index: reproducible per
			// session and avoids contention on the global source.
			rng := rand.New(rand.NewSource(int64(session)))

			// One persistent emitter per session — models a long-lived mcp-proxy process
			// that keeps one connection open across multiple tool calls.
			em, err := emitter.NewDaemon(
				emitter.WithSocketPath(fix.Config.SocketPath),
				emitter.WithSessionID(fmt.Sprintf("mcp-proxy-session-%d", session)),
				emitter.WithLogger(slog.Default()),
			)
			if err != nil {
				errCh <- fmt.Errorf("session %d: create emitter: %w", session, err)
				return
			}
			defer em.Close()

			for j := 0; j < emitsPerSession; j++ {
				// Vary tool name per emit so each receipt has a distinct action.type.
				// Per-session server name makes receipts attributable to their source session.
				ev := emitter.Event{
					Channel:  "mcp_proxy",
					Tool:     emitter.Tool{Name: fmt.Sprintf("op_%d", j), Server: fmt.Sprintf("upstream-%d", session)},
					Decision: "allowed",
				}

				// Retry transient socket write timeouts (observed on macOS under high
				// scheduler pressure). The emitter resets its connection after any write
				// failure, so each retry re-dials a clean conn; the failed partial write
				// is never seen by the daemon. Only timeout-class transport errors are
				// retried — logic errors (bad decision, closed emitter, etc.) fail fast.
				var emitErr error
				for attempt := 0; attempt < 3; attempt++ {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					emitErr = em.Emit(ctx, ev)
					cancel()
					if emitErr == nil {
						break
					}
					if !isTransientIOTimeout(emitErr) {
						errCh <- fmt.Errorf("session %d emit %d: %w", session, j, emitErr)
						return
					}
					time.Sleep(time.Duration(10*(attempt+1)) * time.Millisecond)
				}
				if emitErr != nil {
					errCh <- fmt.Errorf("session %d emit %d (retries exhausted): %w", session, j, emitErr)
					return
				}

				// Occasional jitter widens the concurrent-write window to increase
				// the chance of catching a sequence-allocation race.
				if j%10 == 9 {
					time.Sleep(time.Duration(rng.Intn(500)) * time.Microsecond)
				}
			}
			errCh <- nil
		}(i)
	}

	for i := 0; i < sessions; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("session failed: %v", err)
		}
	}

	receipts := fix.WaitForReceiptCount(t, total, 120*time.Second)

	sort.Slice(receipts, func(i, j int) bool {
		return receipts[i].CredentialSubject.Chain.Sequence <
			receipts[j].CredentialSubject.Chain.Sequence
	})

	// Duplicate-sequence check first: a duplicate names the UNIQUE constraint
	// regression before the contiguity loop emits misleading "wrong sequence" errors.
	seen := make(map[int]bool, len(receipts))
	for _, r := range receipts {
		seq := r.CredentialSubject.Chain.Sequence
		if seen[seq] {
			t.Errorf("seq %d allocated twice (UNIQUE constraint regression)", seq)
		}
		seen[seq] = true
	}

	// Contiguous sequences: fail fast on first gap so subsequent errors are not noise.
	for i, r := range receipts {
		if got := r.CredentialSubject.Chain.Sequence; got != i+1 {
			t.Fatalf("receipts[%d].Sequence = %d, want %d (gap in chain)", i, got, i+1)
		}
	}

	// All receipts must share the daemon's chain ID.
	for i, r := range receipts {
		if r.CredentialSubject.Chain.ChainID != fix.Config.ChainID {
			t.Errorf("receipts[%d]: chain_id = %q, want %q",
				i, r.CredentialSubject.Chain.ChainID, fix.Config.ChainID)
		}
	}

	// Both sessions must have contributed the expected number of receipts.
	counts := make(map[string]int, sessions)
	for _, r := range receipts {
		typ := r.CredentialSubject.Action.Type
		for s := 0; s < sessions; s++ {
			if strings.Contains(typ, fmt.Sprintf("upstream-%d", s)) {
				counts[fmt.Sprintf("upstream-%d", s)]++
			}
		}
	}
	for s := 0; s < sessions; s++ {
		key := fmt.Sprintf("upstream-%d", s)
		if counts[key] != emitsPerSession {
			t.Errorf("session %d (%s): got %d receipts, want %d",
				s, key, counts[key], emitsPerSession)
		}
	}

	// prev_hash walk + signature verification on the sorted chain.
	for i, r := range receipts {
		if i == 0 {
			if r.CredentialSubject.Chain.PreviousReceiptHash != nil {
				t.Errorf("first receipt: prev_hash = %v, want nil",
					r.CredentialSubject.Chain.PreviousReceiptHash)
			}
		} else {
			want, err := receipt.HashReceipt(receipts[i-1])
			if err != nil {
				t.Fatalf("hash receipt %d: %v", i-1, err)
			}
			got := r.CredentialSubject.Chain.PreviousReceiptHash
			if got == nil || *got != want {
				t.Errorf("receipt %d: prev_hash = %v, want %s", i, got, want)
			}
		}

		ok, err := receipt.Verify(r, fix.PublicKey)
		if !ok || err != nil {
			t.Errorf("receipt %d: verify ok=%v err=%v", i, ok, err)
		}
	}
}
