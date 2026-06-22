package checkpoint

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"obsigna.dev/daemon/internal/anchor"
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
//
// Async emission: the actual sink writes run on a dedicated worker goroutine so
// that Observe (called on the per-receipt hot path) returns immediately even
// when a sink is slow (e.g. a git fork/exec or a blocked syslog write). The
// receipt itself is already durable before Observe is called; the checkpoint
// is an additive out-of-band artifact, so its write can safely trail the
// receipt commit. The worker queue is bounded: when the queue is full, Observe
// logs and counts the drop rather than blocking the caller (loud, not fatal,
// not swallowed — same failure philosophy as sink write failures).
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
	dropped  atomic.Int64
	closed   atomic.Bool

	// workerCh receives emitJobs for the worker goroutine. Never closed;
	// the worker is stopped via stopCh instead (see worker()).
	workerCh chan emitJob
	// stopCh is closed by Close to signal the worker to drain and exit.
	stopCh chan struct{}
	// workerDone is closed when the worker goroutine has fully exited.
	workerDone chan struct{}
	// closeOnce ensures Close's shutdown sequence runs exactly once.
	closeOnce sync.Once
}

// emitJob carries one pending checkpoint emission to the worker goroutine.
// When done is non-nil, the worker closes it after the emit completes so a
// synchronous caller (Flush or FlushAll) can wait for the specific emission.
type emitJob struct {
	chainID  string
	seq      int64
	headHash string
	done     chan struct{} // nil for fire-and-forget (Observe path)
}

// defaultQueueDepth is the number of pending emissions the worker channel
// buffers before Observe starts dropping. At one checkpoint per receipt and
// typical sub-millisecond sink latency, this is more than enough headroom for
// a spike in receipt rate without spilling a backlog to disk. Sized to match
// a short burst (one session's worth of rapid tool calls) rather than unbounded
// growth.
const defaultQueueDepth = 256

// NewEmitter returns an Emitter fanning out to sinks, signing with signer.
// cadence < 1 is normalised to 1 (every receipt). logf receives structured
// failure lines; nil silences them (the metric counters still move).
//
// A worker goroutine is started immediately and runs until Close is called.
func NewEmitter(sinks []anchor.Sink, signer Signer, cadence int, logf func(string, ...any)) *Emitter {
	return newEmitterWithQueueDepth(sinks, signer, cadence, logf, defaultQueueDepth)
}

// newEmitterWithQueueDepth is the internal constructor that accepts an
// explicit queue depth, used by tests to exercise the drop path without
// relying on the default 256-deep buffer.
func newEmitterWithQueueDepth(sinks []anchor.Sink, signer Signer, cadence int, logf func(string, ...any), queueDepth int) *Emitter {
	if cadence < 1 {
		cadence = 1
	}
	if queueDepth < 1 {
		queueDepth = 1
	}
	e := &Emitter{
		sinks:      sinks,
		signer:     signer,
		cadence:    cadence,
		now:        func() time.Time { return time.Now().UTC() },
		logf:       logf,
		counts:     make(map[string]int),
		lastSeq:    make(map[string]int64),
		workerCh:   make(chan emitJob, queueDepth),
		stopCh:     make(chan struct{}),
		workerDone: make(chan struct{}),
	}
	go e.worker()
	return e
}

// worker drains emitJobs from workerCh until stopCh is closed, then drains
// any remaining buffered jobs before exiting. This two-phase design — signal
// stop via stopCh, drain via the remaining buffer — means Close drains all
// in-flight items without closing workerCh (which would require all senders to
// guard against send-on-closed-channel panics).
func (e *Emitter) worker() {
	defer close(e.workerDone)
	for {
		select {
		case job := <-e.workerCh:
			e.runJob(job)
		case <-e.stopCh:
			// Drain any items that were already buffered before stopCh was closed.
			for {
				select {
				case job := <-e.workerCh:
					e.runJob(job)
				default:
					return
				}
			}
		}
	}
}

// runJob executes one emitJob: writes to sinks and signals the done channel.
func (e *Emitter) runJob(job emitJob) {
	e.emit(job.chainID, job.seq, job.headHash)
	if job.done != nil {
		close(job.done)
	}
}

// Observe records that chainID advanced to (seq, headHash). When the per-chain
// counter reaches the cadence, a checkpoint is enqueued for the worker goroutine.
// Observe returns immediately regardless of sink speed (the emit is async).
// If the worker queue is full, the checkpoint is dropped, logged, and counted —
// failures are visible, not silently swallowed. Never returns an error.
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
		e.enqueue(emitJob{chainID: chainID, seq: seq, headHash: headHash})
	}
}

// Flush requests a checkpoint for chainID at (seq, headHash) outside the normal
// cadence and resets the cadence counter. Used on graceful shutdown so the final
// head of every open chain is anchored even when the last receipts did not land
// on a cadence boundary.
//
// Flush blocks until the emission has been written to the sinks (or the worker
// has exited), so callers can rely on the checkpoint being durable before they
// return from the shutdown sequence.
//
// Like the per-receipt path it goes through markEmitLocked, so a head that is
// already anchored — e.g. the terminator was skipped on a tight shutdown
// deadline and the tail is unchanged — is a no-op rather than a duplicate
// checkpoint.
func (e *Emitter) Flush(chainID string, seq int64, headHash string) {
	e.mu.Lock()
	e.counts[chainID] = 0
	emit := e.markEmitLocked(chainID, seq)
	e.mu.Unlock()

	if !emit {
		return
	}
	done := make(chan struct{})
	job := emitJob{chainID: chainID, seq: seq, headHash: headHash, done: done}
	// Flush is called on the graceful-shutdown path and must not drop. If the
	// worker channel is full (unusual — the worker is fast and Flush is
	// infrequent), block rather than drop, until the worker drains the queue or
	// exits.
	select {
	case e.workerCh <- job:
	case <-e.workerDone:
		// Worker already exited (Close was called concurrently); do the emit
		// inline so the shutdown sequence is not silently skipped.
		e.emit(chainID, seq, headHash)
		return
	}
	// Wait for the worker to finish this specific emission.
	select {
	case <-done:
	case <-e.workerDone:
	}
}

// FlushAll enqueues a sentinel job and waits until the worker has processed all
// items ahead of it in the queue. It does NOT close the emitter — the emitter
// can continue accepting new Observe calls after FlushAll returns.
//
// Calling FlushAll after Close waits for the worker to exit, returning
// immediately if it has already exited.
func (e *Emitter) FlushAll() error {
	done := make(chan struct{})
	// workerCh is never closed; it is always safe to send on it unless the
	// worker has already exited (workerDone closed). The select protects the
	// case where Close has run and the worker has drained and exited.
	select {
	case e.workerCh <- emitJob{done: done}:
	case <-e.workerDone:
		return nil
	}
	select {
	case <-done:
	case <-e.workerDone:
	}
	return nil
}

// enqueue sends a fire-and-forget job to the worker. If the emitter is closed
// or the channel is full, the job is dropped, logged, and counted.
func (e *Emitter) enqueue(job emitJob) {
	if e.closed.Load() {
		e.dropped.Add(1)
		e.log("level=warn checkpoint drop: emitter closed: chain=%s seq=%d", job.chainID, job.seq)
		return
	}
	select {
	case e.workerCh <- job:
	default:
		e.dropped.Add(1)
		e.log("level=warn checkpoint drop: queue full: chain=%s seq=%d (checkpoint skipped; verify gap-detection covers this)",
			job.chainID, job.seq)
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
// Failures reports the number of (sink, checkpoint) write failures. Dropped
// reports the number of enqueue drops due to a full worker queue. All three
// are the emitter's visibility surface — exposed for tests and a stand-in for
// the real metrics a production emitter would export.
func (e *Emitter) Emitted() int64  { return e.emitted.Load() }
func (e *Emitter) Failures() int64 { return e.failures.Load() }
func (e *Emitter) Dropped() int64  { return e.dropped.Load() }

// emit signs the checkpoint once and writes it to every sink. A signing
// failure aborts this emission (logged + counted); a sink failure is logged +
// counted but the remaining sinks are still attempted. Empty chainID is a
// sentinel (FlushAll drain marker) and is a no-op.
func (e *Emitter) emit(chainID string, seq int64, headHash string) {
	if chainID == "" {
		return
	}
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

// Close signals the worker to drain all pending emissions and exit, then closes
// every sink. Sinks are independent, so a failure on one does not stop the
// others from closing. Returns the first close error.
//
// Close is idempotent: subsequent calls after the first are no-ops.
func (e *Emitter) Close() error {
	var firstErr error
	e.closeOnce.Do(func() {
		// Mark closed before signalling the worker so that any concurrent
		// enqueue() call after this point is counted as dropped rather than
		// silently lost to a dead-but-buffered channel.
		e.closed.Store(true)
		// Signal the worker to stop accepting new items and drain the buffer.
		close(e.stopCh)
		// Wait for the worker to finish processing all buffered items and exit.
		<-e.workerDone

		for _, s := range e.sinks {
			if err := s.Close(); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("close sink %T: %w", s, err)
			}
		}
	})
	return firstErr
}
