package emitters_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"obsigna.dev/sdk/go/emitters"
	"obsigna.dev/sdk/go/receipt"
)

// walReceipt builds a minimal receipt with the given id and chain sequence so
// tests can assert idempotent re-append updates content (via the sequence).
func walReceipt(id string, sequence int) receipt.AgentReceipt {
	r := receipt.AgentReceipt{ID: id}
	r.CredentialSubject.Chain.Sequence = sequence
	return r
}

// walFakeEmitter is a scriptable inner emitter analogous to the TS FlakyEmitter:
// it succeeds by default, fails for ids registered via failOn (until healed),
// and can introduce an artificial per-emit delay to exercise the Flush
// deadline path. Delivered ids are recorded in arrival order.
type walFakeEmitter struct {
	mu        sync.Mutex
	delivered []string
	failing   map[string]bool
	delay     time.Duration
}

func newWALFakeEmitter() *walFakeEmitter {
	return &walFakeEmitter{failing: make(map[string]bool)}
}

func (f *walFakeEmitter) failOn(ids ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range ids {
		f.failing[id] = true
	}
}

func (f *walFakeEmitter) heal(ids ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range ids {
		delete(f.failing, id)
	}
}

func (f *walFakeEmitter) setDelay(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delay = d
}

func (f *walFakeEmitter) deliveredIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.delivered))
	copy(out, f.delivered)
	return out
}

func (f *walFakeEmitter) Emit(_ context.Context, r receipt.AgentReceipt) error {
	f.mu.Lock()
	delay := f.delay
	fail := f.failing[r.ID]
	f.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}
	if fail {
		return &emitters.EmitError{Status: 503, Msg: "flaky: refusing " + r.ID}
	}

	f.mu.Lock()
	f.delivered = append(f.delivered, r.ID)
	f.mu.Unlock()
	return nil
}

func ids(t *testing.T, wal emitters.Wal) []string {
	t.Helper()
	rs, err := wal.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.ID
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// MemoryWal

func TestMemoryWal_AppendListRemove(t *testing.T) {
	ctx := context.Background()
	wal := emitters.NewMemoryWal()
	for _, id := range []string{"a", "b", "c"} {
		if err := wal.Append(ctx, walReceipt(id, 1)); err != nil {
			t.Fatalf("Append(%s): %v", id, err)
		}
	}
	if got := ids(t, wal); !equalStrings(got, []string{"a", "b", "c"}) {
		t.Fatalf("List = %v; want [a b c]", got)
	}
	if err := wal.Remove(ctx, "b"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if got := ids(t, wal); !equalStrings(got, []string{"a", "c"}) {
		t.Fatalf("List after remove = %v; want [a c]", got)
	}
}

func TestMemoryWal_IdempotentReappendKeepsPosition(t *testing.T) {
	ctx := context.Background()
	wal := emitters.NewMemoryWal()
	if err := wal.Append(ctx, walReceipt("a", 1)); err != nil {
		t.Fatal(err)
	}
	if err := wal.Append(ctx, walReceipt("b", 2)); err != nil {
		t.Fatal(err)
	}
	if err := wal.Append(ctx, walReceipt("a", 99)); err != nil {
		t.Fatal(err)
	}
	list, err := wal.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{list[0].ID, list[1].ID}; !equalStrings(got, []string{"a", "b"}) {
		t.Fatalf("order = %v; want [a b]", got)
	}
	if list[0].CredentialSubject.Chain.Sequence != 99 {
		t.Fatalf("re-append did not update content: sequence = %d; want 99", list[0].CredentialSubject.Chain.Sequence)
	}
}

func TestMemoryWal_RemoveUnknownIsNoop(t *testing.T) {
	ctx := context.Background()
	wal := emitters.NewMemoryWal()
	if err := wal.Append(ctx, walReceipt("a", 1)); err != nil {
		t.Fatal(err)
	}
	if err := wal.Remove(ctx, "missing"); err != nil {
		t.Fatalf("Remove unknown id should be a no-op, got %v", err)
	}
	if got := ids(t, wal); !equalStrings(got, []string{"a"}) {
		t.Fatalf("List = %v; want [a]", got)
	}
}

// ---------------------------------------------------------------------------
// FileWal

func jsonFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func TestFileWal_PersistsInOrderNoLeftoverTemp(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wal, err := emitters.NewFileWal(dir)
	if err != nil {
		t.Fatalf("NewFileWal: %v", err)
	}
	if err := wal.Append(ctx, walReceipt("a", 1)); err != nil {
		t.Fatal(err)
	}
	if err := wal.Append(ctx, walReceipt("b", 2)); err != nil {
		t.Fatal(err)
	}
	if got := ids(t, wal); !equalStrings(got, []string{"a", "b"}) {
		t.Fatalf("List = %v; want [a b]", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected exactly 2 files (no leftover temp), got %d: %v", len(entries), entries)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			t.Fatalf("unexpected non-.json file: %s", e.Name())
		}
	}
}

func TestFileWal_RemoveDeletesFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wal, err := emitters.NewFileWal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := wal.Append(ctx, walReceipt("a", 1)); err != nil {
		t.Fatal(err)
	}
	if err := wal.Append(ctx, walReceipt("b", 2)); err != nil {
		t.Fatal(err)
	}
	if err := wal.Remove(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if got := ids(t, wal); !equalStrings(got, []string{"b"}) {
		t.Fatalf("List = %v; want [b]", got)
	}
	if got := jsonFiles(t, dir); len(got) != 1 {
		t.Fatalf("expected 1 .json file, got %d: %v", len(got), got)
	}
}

func TestFileWal_SurvivesRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	first, err := emitters.NewFileWal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Append(ctx, walReceipt("a", 1)); err != nil {
		t.Fatal(err)
	}
	if err := first.Append(ctx, walReceipt("b", 2)); err != nil {
		t.Fatal(err)
	}
	if err := first.Remove(ctx, "a"); err != nil {
		t.Fatal(err)
	}

	second, err := emitters.NewFileWal(dir)
	if err != nil {
		t.Fatal(err)
	}
	list, err := second.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "b" {
		t.Fatalf("reloaded list = %v; want [b]", ids(t, second))
	}
	if list[0].CredentialSubject.Chain.Sequence != 2 {
		t.Fatalf("reloaded content lost: sequence = %d; want 2", list[0].CredentialSubject.Chain.Sequence)
	}
}

func TestFileWal_PreservesOrderAfterRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	first, err := emitters.NewFileWal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Append(ctx, walReceipt("a", 1)); err != nil {
		t.Fatal(err)
	}
	if err := first.Append(ctx, walReceipt("b", 2)); err != nil {
		t.Fatal(err)
	}

	second, err := emitters.NewFileWal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Append(ctx, walReceipt("c", 3)); err != nil {
		t.Fatal(err)
	}
	if got := ids(t, second); !equalStrings(got, []string{"a", "b", "c"}) {
		t.Fatalf("List = %v; want [a b c]", got)
	}
}

func TestFileWal_IdempotentReappendRewritesInPlace(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wal, err := emitters.NewFileWal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := wal.Append(ctx, walReceipt("a", 1)); err != nil {
		t.Fatal(err)
	}
	if err := wal.Append(ctx, walReceipt("b", 2)); err != nil {
		t.Fatal(err)
	}
	if err := wal.Append(ctx, walReceipt("a", 50)); err != nil {
		t.Fatal(err)
	}
	list, err := wal.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{list[0].ID, list[1].ID}; !equalStrings(got, []string{"a", "b"}) {
		t.Fatalf("order = %v; want [a b]", got)
	}
	if list[0].CredentialSubject.Chain.Sequence != 50 {
		t.Fatalf("re-append did not rewrite content: sequence = %d; want 50", list[0].CredentialSubject.Chain.Sequence)
	}
	if got := jsonFiles(t, dir); len(got) != 2 {
		t.Fatalf("expected 2 .json files (no dup), got %d: %v", len(got), got)
	}
}

func TestFileWal_DropsTornEntry(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wal, err := emitters.NewFileWal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := wal.Append(ctx, walReceipt("a", 1)); err != nil {
		t.Fatal(err)
	}
	if err := wal.Append(ctx, walReceipt("b", 2)); err != nil {
		t.Fatal(err)
	}
	// Corrupt the lowest-index entry as a hard-crash mid-write would.
	files := jsonFiles(t, dir)
	if len(files) == 0 {
		t.Fatal("no entry to corrupt")
	}
	if err := os.WriteFile(filepath.Join(dir, files[0]), []byte("{ not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded, err := emitters.NewFileWal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(t, reloaded); !equalStrings(got, []string{"b"}) {
		t.Fatalf("torn entry not dropped: List = %v; want [b]", got)
	}
}

// ---------------------------------------------------------------------------
// WALEmitter

func TestWALEmitter_ClearsEntryOnAck(t *testing.T) {
	ctx := context.Background()
	wal := emitters.NewMemoryWal()
	inner := newWALFakeEmitter()
	em := emitters.NewWAL(inner, wal)

	if err := em.Emit(ctx, walReceipt("a", 1)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := inner.deliveredIDs(); !equalStrings(got, []string{"a"}) {
		t.Fatalf("delivered = %v; want [a]", got)
	}
	if n, err := em.Pending(ctx); err != nil || n != 0 {
		t.Fatalf("Pending = %d, %v; want 0, nil", n, err)
	}
}

func TestWALEmitter_RetainsEntryAndReturnsErrorOnFailure(t *testing.T) {
	ctx := context.Background()
	wal := emitters.NewMemoryWal()
	inner := newWALFakeEmitter()
	inner.failOn("a")
	em := emitters.NewWAL(inner, wal)

	err := em.Emit(ctx, walReceipt("a", 1))
	if err == nil {
		t.Fatal("expected Emit to return the inner error")
	}
	var ee *emitters.EmitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *emitters.EmitError, got %T: %v", err, err)
	}
	if got := inner.deliveredIDs(); len(got) != 0 {
		t.Fatalf("delivered = %v; want empty", got)
	}
	if n, err := em.Pending(ctx); err != nil || n != 1 {
		t.Fatalf("Pending = %d, %v; want 1, nil", n, err)
	}
}

func TestWALEmitter_ReplayRedeliversAll(t *testing.T) {
	ctx := context.Background()
	wal := emitters.NewMemoryWal()
	inner := newWALFakeEmitter()
	inner.failOn("a", "b")
	em := emitters.NewWAL(inner, wal)

	if err := em.Emit(ctx, walReceipt("a", 1)); err == nil {
		t.Fatal("expected Emit(a) to fail")
	}
	if err := em.Emit(ctx, walReceipt("b", 2)); err == nil {
		t.Fatal("expected Emit(b) to fail")
	}
	if n, _ := em.Pending(ctx); n != 2 {
		t.Fatalf("Pending = %d; want 2", n)
	}

	inner.heal("a", "b")
	res, err := em.Replay(ctx)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if res.Delivered != 2 || res.Remaining != 0 {
		t.Fatalf("Replay = %+v; want {Delivered:2 Remaining:0}", res)
	}
	if got := inner.deliveredIDs(); !equalStrings(got, []string{"a", "b"}) {
		t.Fatalf("delivered = %v; want [a b]", got)
	}
	if n, _ := em.Pending(ctx); n != 0 {
		t.Fatalf("Pending = %d; want 0", n)
	}
}

func TestWALEmitter_ReplayLeavesFailingWithoutBlocking(t *testing.T) {
	ctx := context.Background()
	wal := emitters.NewMemoryWal()
	inner := newWALFakeEmitter()
	inner.failOn("a", "b", "c")
	em := emitters.NewWAL(inner, wal)
	for _, id := range []string{"a", "b", "c"} {
		if err := em.Emit(ctx, walReceipt(id, 1)); err == nil {
			t.Fatalf("expected Emit(%s) to fail", id)
		}
	}

	inner.heal("a", "c")
	res, err := em.Replay(ctx)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if res.Delivered != 2 || res.Remaining != 1 {
		t.Fatalf("Replay = %+v; want {Delivered:2 Remaining:1}", res)
	}
	got := inner.deliveredIDs()
	sort.Strings(got)
	if !equalStrings(got, []string{"a", "c"}) {
		t.Fatalf("delivered = %v; want [a c]", got)
	}
	if got := ids(t, wal); !equalStrings(got, []string{"b"}) {
		t.Fatalf("remaining = %v; want [b]", got)
	}
}

func TestWALEmitter_ReplaysDurableBacklogAfterRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Process 1: delivery fails, entry persists to disk, then the process
	// "crashes" (we drop the emitter).
	{
		wal, err := emitters.NewFileWal(dir)
		if err != nil {
			t.Fatal(err)
		}
		inner := newWALFakeEmitter()
		inner.failOn("a")
		em := emitters.NewWAL(inner, wal)
		if err := em.Emit(ctx, walReceipt("a", 1)); err == nil {
			t.Fatal("expected Emit(a) to fail")
		}
	}

	// Process 2: fresh emitter over the same WAL dir; collector is healthy.
	wal2, err := emitters.NewFileWal(dir)
	if err != nil {
		t.Fatal(err)
	}
	inner2 := newWALFakeEmitter()
	em2 := emitters.NewWAL(inner2, wal2)
	if n, _ := em2.Pending(ctx); n != 1 {
		t.Fatalf("Pending after restart = %d; want 1", n)
	}

	res, err := em2.Replay(ctx)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if res.Delivered != 1 || res.Remaining != 0 {
		t.Fatalf("Replay = %+v; want {Delivered:1 Remaining:0}", res)
	}
	if got := inner2.deliveredIDs(); !equalStrings(got, []string{"a"}) {
		t.Fatalf("delivered = %v; want [a]", got)
	}
	if got := jsonFiles(t, dir); len(got) != 0 {
		t.Fatalf("expected 0 .json files after drain, got %d: %v", len(got), got)
	}
}

func TestWALEmitter_FlushReturnsZeroAfterCleanDrain(t *testing.T) {
	ctx := context.Background()
	wal := emitters.NewMemoryWal()
	inner := newWALFakeEmitter()
	inner.failOn("a")
	em := emitters.NewWAL(inner, wal)
	if err := em.Emit(ctx, walReceipt("a", 1)); err == nil {
		t.Fatal("expected Emit(a) to fail")
	}

	inner.heal("a")
	flushCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	remaining, err := em.Flush(flushCtx)
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("Flush remaining = %d; want 0", remaining)
	}
	if got := inner.deliveredIDs(); !equalStrings(got, []string{"a"}) {
		t.Fatalf("delivered = %v; want [a]", got)
	}
}

func TestWALEmitter_FlushHonorsDeadline(t *testing.T) {
	ctx := context.Background()
	wal := emitters.NewMemoryWal()
	inner := newWALFakeEmitter()
	// Deliveries are healthy but slow; the deadline cuts the drain short.
	inner.setDelay(200 * time.Millisecond)
	em := emitters.NewWAL(inner, wal)
	if err := wal.Append(ctx, walReceipt("a", 1)); err != nil {
		t.Fatal(err)
	}
	if err := wal.Append(ctx, walReceipt("b", 2)); err != nil {
		t.Fatal(err)
	}

	flushCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	remaining, err := em.Flush(flushCtx)
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if remaining == 0 {
		t.Fatal("expected at least one receipt still pending after the deadline")
	}
}

func TestWALEmitter_ImplementsEmitter(t *testing.T) {
	var _ emitters.Emitter = emitters.NewWAL(emitters.NewInMemory(), emitters.NewMemoryWal())
}
