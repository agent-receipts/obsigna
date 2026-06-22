package emitters

// WALEmitter provides at-least-once receipt delivery via a write-ahead log
// (ADR-0020 §"At-least-once delivery and the WAL", which retains ADR-0019
// §O3/§P1 for the interrupted-chain semantics it builds on).
//
// It wraps an inner [Emitter] (typically an [HttpEmitter] in [StrategySync]
// mode) and records every receipt in a [Wal] BEFORE attempting delivery. The
// entry is cleared only once the inner emitter acknowledges (HttpEmitter
// resolves on collector 201 or 409). If delivery fails the entry survives, so
// the receipt can be re-delivered on the next [WALEmitter.Replay] (process
// restart) or [WALEmitter.Flush] (graceful shutdown).
//
// Two backends ship:
//
//   - [FileWal] — durable, for long-lived compute (EC2/VM/bare metal). Entries
//     survive a process restart; call [WALEmitter.Replay] once at startup,
//     before accepting new emissions, to drain anything left behind by a
//     previous crash.
//   - [MemoryWal] — in-memory only, for ephemeral compute (Lambda, Cloud Run,
//     Fargate) where no persistent disk is available. Pending entries are lost
//     on a hard timeout; on SIGTERM call [WALEmitter.Flush] with a short
//     deadline (the issue recommends 2s) and, if it reports receipts still
//     pending, emit a terminal agent_end {status: interrupted} receipt per
//     ADR-0019 §P1.
//
// The SDK installs no signal handlers — wiring SIGTERM to Flush is the
// caller's responsibility, matching the rest of the emitter layer:
//
//	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
//	defer cancel()
//	<-ctx.Done()
//	flushCtx, fcancel := context.WithTimeout(context.Background(), 2*time.Second)
//	defer fcancel()
//	remaining, _ := walEmitter.Flush(flushCtx)
//	if remaining > 0 {
//		// best-effort: sign + emit agent_end {status: interrupted}
//	}
//
// The WAL is a local delivery aid, not part of the receipt protocol — its
// on-disk format is private and is NOT required to match across SDKs.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"

	"obsigna.dev/sdk/go/receipt"
)

// Wal is a backend that durably records receipts awaiting acknowledgement.
//
// Implementations MUST preserve append order in [Wal.List] and treat a
// repeated [Wal.Append] of the same receipt ID as an idempotent overwrite: it
// must not create a second entry or change the entry's position in the order,
// but it does update the stored content.
type Wal interface {
	// Append durably records r as pending. Idempotent on r.ID: a re-append
	// overwrites the stored receipt in place without changing its position.
	Append(ctx context.Context, r receipt.AgentReceipt) error
	// Remove drops the receipt with the given id once acknowledged. No-op
	// when the id is unknown.
	Remove(ctx context.Context, id string) error
	// List returns the pending receipts in append order.
	List(ctx context.Context) ([]receipt.AgentReceipt, error)
}

// WALDrainResult is the outcome of a [WALEmitter.Replay] or
// [WALEmitter.Flush].
type WALDrainResult struct {
	// Delivered is the number of receipts acknowledged and cleared from the
	// WAL during the drain.
	Delivered int
	// Remaining is the number of receipts still pending afterwards (delivery
	// failed or the context deadline was hit).
	Remaining int
}

// ---------------------------------------------------------------------------
// MemoryWal

// MemoryWal is an in-memory [Wal]. Entries live only for the lifetime of the
// process — suitable for ephemeral compute where persistent disk is not
// available. Receipt loss is possible on a hard crash or timeout (see
// [WALEmitter.Flush]).
type MemoryWal struct {
	mu      sync.Mutex
	order   []string                        // ids in append order
	entries map[string]receipt.AgentReceipt // id -> latest receipt
}

// NewMemoryWal returns an empty in-memory WAL.
func NewMemoryWal() *MemoryWal {
	return &MemoryWal{entries: make(map[string]receipt.AgentReceipt)}
}

// Append records r as pending. A re-append of an existing id overwrites the
// stored receipt but keeps its original position in the order.
func (w *MemoryWal) Append(_ context.Context, r receipt.AgentReceipt) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.entries[r.ID]; !ok {
		w.order = append(w.order, r.ID)
	}
	w.entries[r.ID] = r
	return nil
}

// Remove drops the entry with the given id. No-op if the id is unknown.
func (w *MemoryWal) Remove(_ context.Context, id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.entries[id]; !ok {
		return nil
	}
	delete(w.entries, id)
	for i, existing := range w.order {
		if existing == id {
			w.order = append(w.order[:i], w.order[i+1:]...)
			break
		}
	}
	return nil
}

// List returns the pending receipts in append order.
func (w *MemoryWal) List(_ context.Context) ([]receipt.AgentReceipt, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]receipt.AgentReceipt, 0, len(w.order))
	for _, id := range w.order {
		out = append(out, w.entries[id])
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// FileWal

// indexWidth is the zero-padded width of the monotonic entry index encoded in
// each filename. 16 digits comfortably exceeds any realistic pending-entry
// count and keeps lexical sort order equal to numeric order.
const indexWidth = 16

// entryName matches a valid WAL entry filename (16 digits + .json). The
// temp file used during atomic writes carries a different suffix and so is
// ignored on load.
var entryName = regexp.MustCompile(`^(\d{16})\.json$`)

type fileEntry struct {
	index   int
	receipt receipt.AgentReceipt
}

// FileWal is a file-backed [Wal]. Each pending receipt is one JSON file in
// dir, named by a zero-padded monotonic index so that directory order equals
// append order. Writes are atomic (temp file + fsync + rename), so a crash
// mid-write never leaves a half-written entry that load would choke on.
// Survives a process restart: the directory is scanned eagerly in
// [NewFileWal] and any leftover entries become the replay backlog.
type FileWal struct {
	dir string

	mu       sync.Mutex
	byID     map[string]fileEntry
	maxIndex int
}

// NewFileWal opens (creating if necessary) a file-backed WAL rooted at dir and
// loads any leftover entries from a previous run.
//
// Unlike the TypeScript reference, which loads lazily on first use, the Go
// constructor loads eagerly and returns an error. This is the idiomatic Go
// shape — failures (e.g. an unreadable directory) surface at construction
// rather than on the first Append, and callers can handle them with the usual
// `wal, err := NewFileWal(dir)` pattern. This is an intentional deviation.
func NewFileWal(dir string) (*FileWal, error) {
	w := &FileWal{dir: dir, byID: make(map[string]fileEntry)}
	if err := w.load(); err != nil {
		return nil, err
	}
	return w, nil
}

// load scans dir for valid entry files, dropping torn/unreadable ones and
// deduplicating by receipt id (keeping the highest index, unlinking stale
// lower-index files). Caller must NOT hold w.mu — it is called only from the
// constructor before the value is shared.
func (w *FileWal) load() error {
	// 0o700: keep the WAL directory owner-only so other local users can't list
	// pending receipts in a multi-user environment. Entry files are written
	// 0o600 (os.CreateTemp default) below.
	if err := os.MkdirAll(w.dir, 0o700); err != nil {
		return fmt.Errorf("FileWal: create dir %s: %w", w.dir, err)
	}
	dirEntries, err := os.ReadDir(w.dir)
	if err != nil {
		return fmt.Errorf("FileWal: read dir %s: %w", w.dir, err)
	}

	type matched struct {
		name  string
		index int
	}
	var matches []matched
	for _, de := range dirEntries {
		m := entryName.FindStringSubmatch(de.Name())
		if m == nil {
			continue
		}
		idx, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		matches = append(matches, matched{name: de.Name(), index: idx})
	}
	// Sort by index so a duplicate id (possible if a crash interleaved an
	// idempotent rewrite) resolves to the highest-index file; the stale
	// lower-index file is unlinked below.
	sort.Slice(matches, func(i, j int) bool { return matches[i].index < matches[j].index })

	for _, m := range matches {
		if m.index > w.maxIndex {
			w.maxIndex = m.index
		}
		raw, err := os.ReadFile(filepath.Join(w.dir, m.name))
		if err != nil {
			// Unreadable entry: drop rather than failing the whole load.
			continue
		}
		var r receipt.AgentReceipt
		if err := json.Unmarshal(raw, &r); err != nil {
			// Torn/truncated JSON from a hard crash: drop it. The receipt was
			// never acked, so at worst the chain shows a gap, which the
			// verifier surfaces.
			continue
		}
		if prior, ok := w.byID[r.ID]; ok {
			w.unlinkQuiet(prior.index)
		}
		w.byID[r.ID] = fileEntry{index: m.index, receipt: r}
	}
	return nil
}

// Append durably records r as pending. A re-append of an existing id reuses
// the existing slot (rewrites in place) so the entry keeps its position.
func (w *FileWal) Append(_ context.Context, r receipt.AgentReceipt) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	index := 0
	if existing, ok := w.byID[r.ID]; ok {
		index = existing.index
	} else {
		w.maxIndex++
		index = w.maxIndex
	}
	if err := w.writeEntry(index, r); err != nil {
		return err
	}
	w.byID[r.ID] = fileEntry{index: index, receipt: r}
	return nil
}

// Remove drops the entry with the given id and unlinks its file. No-op if the
// id is unknown.
func (w *FileWal) Remove(_ context.Context, id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry, ok := w.byID[id]
	if !ok {
		return nil
	}
	delete(w.byID, id)
	if err := os.Remove(w.path(entry.index)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("FileWal: remove entry %s: %w", id, err)
	}
	return nil
}

// List returns the pending receipts in append (index) order.
func (w *FileWal) List(_ context.Context) ([]receipt.AgentReceipt, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	entries := make([]fileEntry, 0, len(w.byID))
	for _, e := range w.byID {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].index < entries[j].index })
	out := make([]receipt.AgentReceipt, len(entries))
	for i, e := range entries {
		out[i] = e.receipt
	}
	return out, nil
}

// writeEntry atomically writes r to the file for index: a temp file in the
// same directory, fsync'd before the rename so a crash can't expose a
// rename-completed-but-data-lost entry. Caller must hold w.mu.
func (w *FileWal) writeEntry(index int, r receipt.AgentReceipt) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("FileWal: marshal receipt %s: %w", r.ID, err)
	}
	tmp, err := os.CreateTemp(w.dir, "wal-*.tmp")
	if err != nil {
		return fmt.Errorf("FileWal: create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename.
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("FileWal: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("FileWal: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("FileWal: close temp: %w", err)
	}
	if err := os.Rename(tmpName, w.path(index)); err != nil {
		return fmt.Errorf("FileWal: rename temp: %w", err)
	}
	cleanup = false
	return nil
}

func (w *FileWal) unlinkQuiet(index int) {
	if err := os.Remove(w.path(index)); err != nil && !errors.Is(err, os.ErrNotExist) {
		// A failure to unlink a stale duplicate is non-fatal: the highest-index
		// entry still wins on the next load.
		_ = err
	}
}

func (w *FileWal) path(index int) string {
	return filepath.Join(w.dir, fmt.Sprintf("%0*d.json", indexWidth, index))
}

// ---------------------------------------------------------------------------
// WALEmitter

// WALEmitter wraps an inner [Emitter] with at-least-once delivery backed by a
// [Wal]. See the file-level doc for the durable vs in-memory backend choice
// and the recommended SIGTERM wiring.
type WALEmitter struct {
	inner Emitter
	wal   Wal
}

// NewWAL constructs a [WALEmitter] delivering through inner and journalling to
// wal.
func NewWAL(inner Emitter, wal Wal) *WALEmitter {
	return &WALEmitter{inner: inner, wal: wal}
}

// Emit writes r to the WAL, delivers it through the inner emitter, then clears
// the WAL entry on acknowledgement. If delivery fails the entry is left in the
// WAL for a later [WALEmitter.Replay] / [WALEmitter.Flush] and the inner
// error is returned to the caller.
func (e *WALEmitter) Emit(ctx context.Context, r receipt.AgentReceipt) error {
	if err := e.wal.Append(ctx, r); err != nil {
		return fmt.Errorf("WALEmitter: append %s: %w", r.ID, err)
	}
	if err := e.inner.Emit(ctx, r); err != nil {
		return fmt.Errorf("WALEmitter: inner emit %s: %w", r.ID, err)
	}
	if err := e.wal.Remove(ctx, r.ID); err != nil {
		return fmt.Errorf("WALEmitter: remove %s: %w", r.ID, err)
	}
	return nil
}

// Replay re-delivers every receipt left unacknowledged in the WAL. Call once
// at startup, before accepting new emissions, to drain a backlog left by a
// previous crash (durable backend) or to retry within a warm invocation. Each
// entry the inner emitter acknowledges is cleared; failures stay in the WAL
// and do not block the remaining entries. It honours ctx for cancellation but
// imposes no deadline of its own.
func (e *WALEmitter) Replay(ctx context.Context) (WALDrainResult, error) {
	return e.drain(ctx)
}

// Flush is a best-effort, context-deadline-bounded drain of all pending
// receipts. Intended for graceful shutdown on SIGTERM in ephemeral compute:
// pass a ctx with a short timeout (the issue recommends 2s, e.g.
// context.WithTimeout(context.Background(), 2*time.Second)). It returns the
// number of receipts still pending when the deadline elapses (0 means the WAL
// drained cleanly). A non-zero result is the caller's cue to emit
// agent_end {status: interrupted} per ADR-0019 §P1.
//
// The deadline is checked between deliveries. A single in-flight inner.Emit
// may overrun the ctx deadline because it cannot be interrupted mid-call (an
// [HttpEmitter] owns its own per-request timeout and retry budget); the drain
// stops before starting the next delivery once ctx is done. This is the
// Go-idiomatic equivalent of the TypeScript flush(deadlineMs).
func (e *WALEmitter) Flush(ctx context.Context) (int, error) {
	res, err := e.drain(ctx)
	return res.Remaining, err
}

// Pending reports the number of receipts currently awaiting acknowledgement.
func (e *WALEmitter) Pending(ctx context.Context) (int, error) {
	pending, err := e.wal.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("WALEmitter: list pending: %w", err)
	}
	return len(pending), nil
}

// drain attempts delivery of every pending receipt. It stops starting new
// deliveries once ctx is done (so Flush honours its caller's deadline);
// Replay passes an un-deadlined ctx and drains everything. A failed delivery
// leaves the entry in the WAL and the loop continues so one stuck receipt does
// not strand the rest.
func (e *WALEmitter) drain(ctx context.Context) (WALDrainResult, error) {
	pending, err := e.wal.List(ctx)
	if err != nil {
		return WALDrainResult{}, fmt.Errorf("WALEmitter: list pending: %w", err)
	}

	delivered := 0
	for _, r := range pending {
		if ctx.Err() != nil {
			break
		}
		if err := e.inner.Emit(ctx, r); err != nil {
			// Leave the entry for the next drain.
			continue
		}
		if err := e.wal.Remove(ctx, r.ID); err != nil {
			return WALDrainResult{}, fmt.Errorf("WALEmitter: remove %s: %w", r.ID, err)
		}
		delivered++
	}

	remaining, err := e.Pending(ctx)
	if err != nil {
		return WALDrainResult{}, err
	}
	return WALDrainResult{Delivered: delivered, Remaining: remaining}, nil
}
