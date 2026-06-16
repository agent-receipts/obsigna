package checkpoint

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/anchor"
)

// Emitter signs chain-HEAD checkpoints and fans them out to every configured
// sink. It is the daemon-side glue between the receipt commit path and the
// out-of-band anchor.
//
// Fan-out: one checkpoint goes to ALL sinks (the seam proof — git in one
// fate-sharing domain, file/syslog standing for another). A per-sink write
// failure is logged and counted but NEVER blocks or fails the caller:
// receipts are the primary record, and a missing checkpoint is caught later
// by verify gap-detection. This is the deliberate opposite of the rotation
// anchor's abort-on-failure ordering, and the opposite of the PY-P9 silent-
// drop antipattern — failures are loud (structured log + metric), not fatal
// and not swallowed.
//
// Cadence is "emit once every N observed receipts" per chain (default 1, every
// receipt — chosen for spike testability). Flush forces an emission regardless
// of the counter, used on graceful shutdown.
type Emitter struct {
	sinks   []anchor.Sink
	signer  Signer
	cadence int
	now     func() time.Time
	logf    func(string, ...any)

	mu      sync.Mutex
	counts  map[string]int   // observed receipts since last emit, per chain
	lastSeq map[string]int64 // highest sequence already anchored, per chain

	emitted  atomic.Int64
	failures atomic.Int64
}

// NewEmitter returns an Emitter fanning out to sinks, signing with signer.
// cadence < 1 is normalised to 1 (every receipt). logf receives structured
// failure lines; nil silences them (the metric counters still move).
func NewEmitter(sinks []anchor.Sink, signer Signer, cadence int, logf func(string, ...any)) *Emitter {
	if cadence < 1 {
		cadence = 1
	}
	return &Emitter{
		sinks:   sinks,
		signer:  signer,
		cadence: cadence,
		now:     func() time.Time { return time.Now().UTC() },
		logf:    logf,
		counts:  make(map[string]int),
		lastSeq: make(map[string]int64),
	}
}

// Observe records that chainID advanced to (seq, headHash). When the per-chain
// counter reaches the cadence, a checkpoint is emitted and the counter resets.
// Never returns an error: it runs after the receipt is already committed, so it
// cannot block or undo receipt emission.
func (e *Emitter) Observe(chainID string, seq int64, headHash string) {
	e.mu.Lock()
	e.counts[chainID]++
	emit := false
	if e.counts[chainID] >= e.cadence {
		e.counts[chainID] = 0
		emit = e.markEmitLocked(chainID, seq)
	}
	e.mu.Unlock()

	if emit {
		e.emit(chainID, seq, headHash)
	}
}

// Flush forces a checkpoint for chainID at (seq, headHash) regardless of the
// cadence counter and resets it. Used on graceful shutdown so the final head
// of every open chain is anchored even when the last receipts did not land on
// a cadence boundary.
func (e *Emitter) Flush(chainID string, seq int64, headHash string) {
	e.mu.Lock()
	e.counts[chainID] = 0
	emit := e.markEmitLocked(chainID, seq)
	e.mu.Unlock()
	if emit {
		e.emit(chainID, seq, headHash)
	}
}

// markEmitLocked reports whether a checkpoint at seq should be emitted for
// chainID, and records it as anchored when so. It gates on the highest sequence
// already anchored: a head at or below it has been anchored already, so
// re-emitting would write a duplicate (or out-of-order) checkpoint that
// verify reads as a non-strictly-increasing — i.e. corrupt — log. This is what
// makes Flush idempotent against the per-receipt Observe path: a graceful
// shutdown whose terminator was skipped (deadline) re-flushes the last head,
// and without this guard that head would be anchored twice. Caller holds e.mu.
func (e *Emitter) markEmitLocked(chainID string, seq int64) bool {
	if seq <= e.lastSeq[chainID] {
		return false
	}
	e.lastSeq[chainID] = seq
	return true
}

// Emitted reports the number of checkpoints written to at least one sink.
// Failures reports the number of (sink, checkpoint) write failures. Both are
// the spike's visibility surface — exposed for tests and a stand-in for the
// real metrics a production emitter would export.
func (e *Emitter) Emitted() int64  { return e.emitted.Load() }
func (e *Emitter) Failures() int64 { return e.failures.Load() }

// emit signs the checkpoint once and writes it to every sink. A signing
// failure aborts this emission (logged + counted); a sink failure is logged +
// counted but the remaining sinks are still attempted.
func (e *Emitter) emit(chainID string, seq int64, headHash string) {
	cp := Checkpoint{
		ChainID:     chainID,
		Sequence:    seq,
		ReceiptHash: headHash,
		Timestamp:   e.now().Format(time.RFC3339Nano),
	}
	signed, err := Sign(cp, e.signer)
	if err != nil {
		e.failures.Add(1)
		e.log("level=error checkpoint sign failed: chain=%s seq=%d: %v", chainID, seq, err)
		return
	}
	payload, err := json.Marshal(signed)
	if err != nil {
		e.failures.Add(1)
		e.log("level=error checkpoint marshal failed: chain=%s seq=%d: %v", chainID, seq, err)
		return
	}

	wroteAny := false
	for _, s := range e.sinks {
		if err := s.Write(anchor.EventTypeCheckpoint, payload); err != nil {
			e.failures.Add(1)
			e.log("level=error checkpoint sink write failed: chain=%s seq=%d sink=%T: %v", chainID, seq, s, err)
			continue
		}
		wroteAny = true
	}
	if wroteAny {
		e.emitted.Add(1)
	}
}

func (e *Emitter) log(format string, args ...any) {
	if e.logf == nil {
		return
	}
	e.logf(format, args...)
}

// Close closes every sink, returning the first error. Sinks are independent,
// so a failure on one does not stop the others from closing.
func (e *Emitter) Close() error {
	var firstErr error
	for _, s := range e.sinks {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close sink %T: %w", s, err)
		}
	}
	return firstErr
}
