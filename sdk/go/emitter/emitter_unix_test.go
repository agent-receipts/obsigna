//go:build linux || darwin

// Unix-only tests that bind a real AF_UNIX listener and assert the wire
// behaviour of Emit: length-prefix framing matches the daemon's reader,
// reconnect after listener restart works without a Close/New dance,
// and sessionID is stable across multiple Emits.
//
// Tests live in this file rather than emitter_test.go because Windows lacks
// AF_UNIX in net.Listen for older Go releases used in CI matrix.
package emitter

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// shortSocketDir returns a temp directory whose path leaves room for an
// AF_UNIX socket name. macOS sun_path is 104 bytes; t.TempDir() under
// /var/folders/… can produce ~119-char paths that overflow that limit.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	base := "/tmp"
	if _, err := os.Stat(base); err != nil {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "aremit*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// recordingListener accepts on a Unix socket and records every length-prefix
// frame it receives. Used to assert wire-format correctness without booting a
// full daemon. Stop closes both the listener AND any in-flight peer
// connections so reconnect tests can assert the emitter re-dials cleanly
// after the daemon goes away.
type recordingListener struct {
	ln       *net.UnixListener
	path     string
	mu       sync.Mutex
	frames   [][]byte
	conns    map[net.Conn]struct{}
	stopped  chan struct{}
	stopOnce sync.Once
}

func newRecordingListener(t *testing.T, dir string) *recordingListener {
	t.Helper()
	path := filepath.Join(dir, "events.sock")
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	rl := &recordingListener{
		ln:      ln,
		path:    path,
		conns:   make(map[net.Conn]struct{}),
		stopped: make(chan struct{}),
	}
	go rl.acceptLoop()
	t.Cleanup(rl.Stop)
	return rl
}

func (r *recordingListener) acceptLoop() {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			select {
			case <-r.stopped:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		r.mu.Lock()
		select {
		case <-r.stopped:
			r.mu.Unlock()
			conn.Close()
			return
		default:
		}
		r.conns[conn] = struct{}{}
		r.mu.Unlock()
		go r.serveConn(conn)
	}
}

func (r *recordingListener) serveConn(conn net.Conn) {
	defer func() {
		r.mu.Lock()
		delete(r.conns, conn)
		r.mu.Unlock()
		conn.Close()
	}()
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > MaxFrameSize {
			return
		}
		buf := make([]byte, int(n))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		r.mu.Lock()
		r.frames = append(r.frames, buf)
		r.mu.Unlock()
	}
}

func (r *recordingListener) Stop() {
	r.stopOnce.Do(func() {
		r.mu.Lock()
		close(r.stopped)
		// Close every accepted conn so the emitter's cached connection
		// observes EOF/EPIPE on its next write — this is what triggers the
		// re-dial path the reconnect test exercises.
		for c := range r.conns {
			_ = c.Close()
		}
		r.mu.Unlock()
		r.ln.Close()
	})
}

// snapshot returns a copy of the frames received so far.
func (r *recordingListener) snapshot() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.frames))
	copy(out, r.frames)
	return out
}

func (r *recordingListener) waitForFrames(t *testing.T, want int, timeout time.Duration) [][]byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got := r.snapshot()
		if len(got) >= want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d frames received within %s; want %d", len(got), timeout, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEmit_RoundTripWireFormat(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	em, err := NewDaemon(
		WithSocketPath(rl.path),
		WithSessionID("wire-format-test"),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	ev := Event{
		Channel:  "mcp",
		Tool:     Tool{Server: "github", Name: "list_repos"},
		Input:    json.RawMessage(`{"owner":"foo"}`),
		Output:   json.RawMessage(`{"count":3}`),
		Decision: "allowed",
	}
	if err := em.Emit(context.Background(), ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	frames := rl.waitForFrames(t, 1, 2*time.Second)
	if len(frames) != 1 {
		t.Fatalf("got %d frames; want 1", len(frames))
	}

	var got frame
	if err := json.Unmarshal(frames[0], &got); err != nil {
		t.Fatalf("unmarshal frame: %v (raw: %s)", err, frames[0])
	}
	if got.Version != SupportedFrameVersion {
		t.Errorf("frame.v = %q; want %q", got.Version, SupportedFrameVersion)
	}
	if got.SessionID != "wire-format-test" {
		t.Errorf("frame.session_id = %q; want %q", got.SessionID, "wire-format-test")
	}
	if got.Channel != "mcp" {
		t.Errorf("frame.channel = %q; want %q", got.Channel, "mcp")
	}
	if got.Tool.Server != "github" || got.Tool.Name != "list_repos" {
		t.Errorf("frame.tool = %+v; want {github list_repos}", got.Tool)
	}
	if got.Decision != "allowed" {
		t.Errorf("frame.decision = %q; want allowed", got.Decision)
	}
	if !json.Valid(got.Input) || string(got.Input) != `{"owner":"foo"}` {
		t.Errorf("frame.input = %s; want %s", got.Input, `{"owner":"foo"}`)
	}
	if !json.Valid(got.Output) || string(got.Output) != `{"count":3}` {
		t.Errorf("frame.output = %s; want %s", got.Output, `{"count":3}`)
	}
	if _, err := time.Parse(time.RFC3339Nano, got.TsEmit); err != nil {
		t.Errorf("frame.ts_emit %q is not RFC3339Nano: %v", got.TsEmit, err)
	}
}

func TestEmit_SessionIDStableAcrossCalls(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	const sid = "stable-session-2026-05"
	em, err := NewDaemon(
		WithSocketPath(rl.path),
		WithSessionID(sid),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	for i := 0; i < 3; i++ {
		if err := em.Emit(context.Background(), Event{
			Channel:  "mcp",
			Tool:     Tool{Name: "ping"},
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}

	frames := rl.waitForFrames(t, 3, 2*time.Second)
	for i, f := range frames {
		var got frame
		if err := json.Unmarshal(f, &got); err != nil {
			t.Fatalf("frame %d: unmarshal: %v", i, err)
		}
		if got.SessionID != sid {
			t.Errorf("frame %d: session_id = %q; want %q", i, got.SessionID, sid)
		}
	}
}

func TestEmit_ReconnectsAfterListenerRestart(t *testing.T) {
	dir := shortSocketDir(t)

	rl1 := newRecordingListener(t, dir)
	em, err := NewDaemon(
		WithSocketPath(rl1.path),
		WithSessionID("reconnect-test"),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	// First Emit reaches rl1.
	if err := em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "first"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("Emit first: %v", err)
	}
	rl1.waitForFrames(t, 1, 2*time.Second)

	// Stop the listener and remove the socket file: the next Emit should
	// drop silently rather than hang or return an error.
	rl1.Stop()
	_ = os.Remove(rl1.path)

	// Drive the in-Emitter conn into a write failure so the next-Emit
	// re-dial path is exercised. Without an intermediate Emit the cached
	// conn would still be valid (writes succeed into the kernel buffer
	// even after the peer closes), so the second listener wouldn't see
	// the next frame.
	for i := 0; i < 3; i++ {
		_ = em.Emit(context.Background(), Event{
			Channel:  "mcp",
			Tool:     Tool{Name: "during-outage"},
			Decision: "allowed",
		})
		time.Sleep(50 * time.Millisecond)
	}

	// Bring up a fresh listener at the same path.
	rl2 := newRecordingListener(t, dir)

	// New Emit must reach rl2; the emitter re-dials transparently.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := em.Emit(context.Background(), Event{
			Channel:  "mcp",
			Tool:     Tool{Name: "after-restart"},
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("Emit after restart: %v", err)
		}
		got := rl2.snapshot()
		if len(got) > 0 {
			// Verify we received the post-restart frame.
			var f frame
			if err := json.Unmarshal(got[len(got)-1], &f); err != nil {
				t.Fatalf("unmarshal frame: %v", err)
			}
			if f.Tool.Name == "after-restart" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("rl2 never received an after-restart frame; got %d frames total", len(got))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestEmit_BestEffortFireAndForgetWhenSocketMissing(t *testing.T) {
	dir := shortSocketDir(t)
	em, err := NewDaemon(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithSessionID("no-daemon-test"),
		WithLogger(silentLogger()),
		WithBestEffort(),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	start := time.Now()
	err = em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
	})
	elapsed := time.Since(start)

	// Best-effort opt-out: returns nil on transport failure, not an error.
	if err != nil {
		t.Fatalf("Emit returned error %v; want nil (WithBestEffort)", err)
	}
	// 25ms dial timeout + 100ms write deadline = 125ms upper bound. Allow
	// 2x for slow CI.
	if elapsed > 250*time.Millisecond {
		t.Errorf("Emit took %s; want <250ms (non-blocking contract)", elapsed)
	}
}

// TestEmit_ContextCancelledOnEntry asserts that Emit returns the context error
// immediately when the context is already cancelled before the call.
func TestEmit_ContextCancelledOnEntry(t *testing.T) {
	dir := shortSocketDir(t)
	em, err := NewDaemon(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	err = em.Emit(ctx, Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
	})
	if err == nil {
		t.Error("Emit with cancelled ctx returned nil; want context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Emit returned %v; want context.Canceled", err)
	}
}

// TestNew_EmptySessionIDGeneratesUUID covers the WithSessionID("") branch:
// passing an empty string is treated as "no host id" and New falls back to
// generating a UUID, matching the behaviour when WithSessionID is not passed.
func TestNew_EmptySessionIDGeneratesUUID(t *testing.T) {
	dir := shortSocketDir(t)
	em, err := NewDaemon(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithSessionID(""), // explicit empty → generate UUID
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()
	if got := em.SessionID(); got == "" {
		t.Error("SessionID() is empty after WithSessionID(\"\"); want generated UUID")
	}
}

// TestEmit_NonNilEmptyInput checks the specific error for a non-nil empty
// Input slice (distinct from nil, which means "no payload").
func TestEmit_NonNilEmptyInput(t *testing.T) {
	dir := shortSocketDir(t)
	em, err := NewDaemon(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	err = em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
		Input:    []byte{}, // non-nil, zero-length
	})
	if err == nil {
		t.Error("Emit with non-nil empty Input returned nil; want error")
	}
}

// TestEmit_NonNilEmptyOutput mirrors TestEmit_NonNilEmptyInput for Output.
func TestEmit_NonNilEmptyOutput(t *testing.T) {
	dir := shortSocketDir(t)
	em, err := NewDaemon(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	err = em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
		Output:   []byte{}, // non-nil, zero-length
	})
	if err == nil {
		t.Error("Emit with non-nil empty Output returned nil; want error")
	}
}

// TestEmit_OversizedCombinedPayload asserts that Input+Output exceeding
// MaxFrameSize is rejected before any dial attempt.
func TestEmit_OversizedCombinedPayload(t *testing.T) {
	dir := shortSocketDir(t)
	em, err := NewDaemon(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	// Build two JSON strings that together exceed MaxFrameSize.
	half := MaxFrameSize/2 + 1
	big := make([]byte, half)
	big[0] = '"'
	for i := 1; i < half-1; i++ {
		big[i] = 'x'
	}
	big[half-1] = '"'

	err = em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
		Input:    big,
		Output:   big,
	})
	if err == nil {
		t.Error("Emit with oversized payload returned nil; want error")
	}
}

// TestEmit_OnClosedEmitter verifies that Emit returns an error when called on
// a closed emitter (after Close has been called).
func TestEmit_OnClosedEmitter(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	em, err := NewDaemon(
		WithSocketPath(rl.path),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}

	// Close the emitter.
	if err := em.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Emit on a closed emitter: must return an error, not drop silently.
	err = em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
	})
	if err == nil {
		t.Error("Emit on closed emitter returned nil; want error")
	}
}

// TestSessionID asserts that SessionID returns the value set by WithSessionID
// and that a generated ID is non-empty when no session is supplied.
func TestSessionID(t *testing.T) {
	dir := shortSocketDir(t)

	t.Run("explicit", func(t *testing.T) {
		em, err := NewDaemon(
			WithSocketPath(filepath.Join(dir, "missing.sock")),
			WithSessionID("explicit-session-id"),
		)
		if err != nil {
			t.Fatalf("NewDaemon: %v", err)
		}
		defer em.Close()
		if got := em.SessionID(); got != "explicit-session-id" {
			t.Errorf("SessionID() = %q; want %q", got, "explicit-session-id")
		}
	})

	t.Run("generated", func(t *testing.T) {
		em, err := NewDaemon(
			WithSocketPath(filepath.Join(dir, "missing.sock")),
		)
		if err != nil {
			t.Fatalf("NewDaemon: %v", err)
		}
		defer em.Close()
		if got := em.SessionID(); got == "" {
			t.Error("SessionID() is empty; want generated UUID")
		}
	})
}

// TestWriteAll_ShortWrite checks that writeAll returns io.ErrShortWrite
// when the writer returns (0, nil) — the zero-progress no-error case.
func TestWriteAll_ShortWrite(t *testing.T) {
	w := &zeroWriter{}
	err := writeAll(w, []byte("hello"))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("writeAll with zero-progress writer: got %v; want io.ErrShortWrite", err)
	}
}

// zeroWriter always returns (0, nil) — simulates a writer that makes no
// progress without returning an error, which triggers the ErrShortWrite guard.
type zeroWriter struct{}

func (*zeroWriter) Write(_ []byte) (int, error) { return 0, nil }

// TestWriteFrame_TighterContextDeadline verifies that writeFrame uses the
// context deadline when it is tighter than writeTimeout. This test sets a
// 20ms deadline (tighter than the 100ms writeTimeout) and verifies the
// write still succeeds on a responsive listener (using the tighter deadline).
func TestWriteFrame_TighterContextDeadline(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	em, err := NewDaemon(
		WithSocketPath(rl.path),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	// First Emit to establish the connection.
	if err := em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "warmup"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("warmup Emit: %v", err)
	}
	rl.waitForFrames(t, 1, 2*time.Second)

	// Now emit with a deadline tighter than writeTimeout (100ms).
	// The listener is responsive so the write should complete within 20ms.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := em.Emit(ctx, Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "with-deadline"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("Emit with tighter deadline: %v", err)
	}
	rl.waitForFrames(t, 2, 2*time.Second)
}

// TestDefaultSocketPath_EnvOverride covers the AGENTRECEIPTS_SOCKET env var
// branch of DefaultSocketPath on supported platforms.
func TestDefaultSocketPath_EnvOverride(t *testing.T) {
	const want = "/custom/override/events.sock"
	t.Setenv("AGENTRECEIPTS_SOCKET", want)
	got := DefaultSocketPath()
	if got != want {
		t.Errorf("DefaultSocketPath() = %q; want %q", got, want)
	}
}

// TestDefaultSocketPath_NoRuntimeEnv exercises the bare environment on
// supported platforms: AGENTRECEIPTS_SOCKET, TMPDIR, and XDG_RUNTIME_DIR
// all empty. The path must still resolve to something — on darwin via
// the HOME-based XDG_DATA_HOME default (issue #545), on linux via the
// /run system-install fallback. We only assert non-empty here; the
// exact value is platform-specific and exercised by the targeted tests
// below.
func TestDefaultSocketPath_NoRuntimeEnv(t *testing.T) {
	t.Setenv("AGENTRECEIPTS_SOCKET", "")
	t.Setenv("TMPDIR", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	got := DefaultSocketPath()
	if got == "" {
		t.Errorf("DefaultSocketPath() = %q; want non-empty path on supported platform", got)
	}
}

// TestEmit_WriteFailureResetsConn exercises the write-failure branch in Emit:
// when writeFrame returns an error the conn must be reset to nil so the next
// Emit re-dials rather than attempting to write on a broken conn indefinitely.
func TestEmit_WriteFailureResetsConn(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	// WithBestEffort so the write-failure and re-dial paths return nil — this
	// test exercises conn-reset mechanics, not the surface-error contract.
	em, err := NewDaemon(
		WithSocketPath(rl.path),
		WithLogger(silentLogger()),
		WithBestEffort(),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	// Establish a connection via the first Emit.
	if err := em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "first"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	rl.waitForFrames(t, 1, 2*time.Second)

	// Stop the listener so the next write fails.
	rl.Stop()
	_ = os.Remove(rl.path)
	// Give the OS time to propagate the conn close.
	time.Sleep(50 * time.Millisecond)

	// This Emit should fail the write and reset e.conn to nil (returns nil
	// under WithBestEffort).
	if err := em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "failing"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("failing Emit returned error %v; want nil (WithBestEffort)", err)
	}

	// e.conn should now be nil; a subsequent Emit must attempt a new dial
	// (which will fail because the socket is gone) and return nil.
	if err := em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "after-reset"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("post-reset Emit returned error %v; want nil", err)
	}
}

// TestEmit_DropCounterIncrementsOnFailure verifies that every failed send
// (dial or write) increments the emitter's drop counter. The counter is
// internal state, but its effect is observable via the drop_count field in the
// first frame delivered to a recovered listener.
func TestEmit_DropCounterIncrementsOnFailure(t *testing.T) {
	dir := shortSocketDir(t)
	missingPath := filepath.Join(dir, "missing.sock")

	// WithBestEffort so the failing emits return nil; the drop counter still
	// increments on every failed send regardless of the opt-out.
	em, err := NewDaemon(
		WithSocketPath(missingPath),
		WithLogger(silentLogger()),
		WithBestEffort(),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	// Three Emits to a missing socket → three dial failures → drop_count = 3.
	for i := 0; i < 3; i++ {
		if err := em.Emit(context.Background(), Event{
			Channel:  "mcp",
			Tool:     Tool{Name: "noop"},
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("Emit %d: expected nil (WithBestEffort), got %v", i, err)
		}
	}

	// Now bring up a listener at the same path and emit once more.
	rl := newRecordingListener(t, dir)
	if err := os.Rename(rl.path, missingPath); err != nil {
		t.Fatalf("rename listener socket: %v", err)
	}
	rl.path = missingPath

	if err := em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "recovery"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("recovery Emit: %v", err)
	}

	frames := rl.waitForFrames(t, 1, 2*time.Second)
	var got frame
	if err := json.Unmarshal(frames[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.DropCount != 3 {
		t.Errorf("drop_count = %d; want 3", got.DropCount)
	}
}

// TestEmit_DropCounterResetAfterFlush verifies that after the drop count is
// flushed in a successful send it is reset to zero, so the following frame
// carries drop_count = 0 (omitted on wire, which is the same as zero).
func TestEmit_DropCounterResetAfterFlush(t *testing.T) {
	dir := shortSocketDir(t)
	missingPath := filepath.Join(dir, "missing.sock")

	em, err := NewDaemon(
		WithSocketPath(missingPath),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	// One drop.
	_ = em.Emit(context.Background(), Event{Channel: "mcp", Tool: Tool{Name: "n"}, Decision: "allowed"})

	// Bring up listener.
	rl := newRecordingListener(t, dir)
	if err := os.Rename(rl.path, missingPath); err != nil {
		t.Fatalf("rename listener socket: %v", err)
	}
	rl.path = missingPath

	// First successful send flushes drop_count = 1.
	if err := em.Emit(context.Background(), Event{Channel: "mcp", Tool: Tool{Name: "flush"}, Decision: "allowed"}); err != nil {
		t.Fatalf("flush Emit: %v", err)
	}
	// Second successful send should have drop_count = 0.
	if err := em.Emit(context.Background(), Event{Channel: "mcp", Tool: Tool{Name: "clean"}, Decision: "allowed"}); err != nil {
		t.Fatalf("clean Emit: %v", err)
	}

	frames := rl.waitForFrames(t, 2, 2*time.Second)

	var flush, clean frame
	if err := json.Unmarshal(frames[0], &flush); err != nil {
		t.Fatalf("unmarshal flush frame: %v", err)
	}
	if err := json.Unmarshal(frames[1], &clean); err != nil {
		t.Fatalf("unmarshal clean frame: %v", err)
	}

	if flush.DropCount != 1 {
		t.Errorf("flush frame drop_count = %d; want 1", flush.DropCount)
	}
	if clean.DropCount != 0 {
		t.Errorf("clean frame drop_count = %d; want 0 (counter should be reset after flush)", clean.DropCount)
	}
}

// TestEmit_DropCounterRestoredOnWriteFailure verifies that when a send
// attempt fails mid-write (writeFrame error), the pending drop count that was
// optimistically consumed (via Swap) is added back so it is not lost.
//
// Uses in-package access to inject a known value (7) before the failure; the
// first successful post-failure frame must carry at least 7+1 = 8 drops
// (injected + the write failure itself). Any additional dial failures between
// the stop and reconnect add to the count, hence ">= 8" not "== 8".
func TestEmit_DropCounterRestoredOnWriteFailure(t *testing.T) {
	dir := shortSocketDir(t)

	rl1 := newRecordingListener(t, dir)
	em, err := NewDaemon(WithSocketPath(rl1.path), WithLogger(silentLogger()))
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	// Establish the connection.
	if err := em.Emit(context.Background(), Event{Channel: "mcp", Tool: Tool{Name: "prime"}, Decision: "allowed"}); err != nil {
		t.Fatalf("prime Emit: %v", err)
	}
	rl1.waitForFrames(t, 1, 2*time.Second)

	// Inject a known pending count before killing the listener.
	const injected = 7
	em.dropCount.Store(injected)

	// Stop rl1 so the next write fails; give the OS time to propagate.
	rl1.Stop()
	_ = os.Remove(rl1.path)
	time.Sleep(50 * time.Millisecond)

	// This emit hits the dead connection: pendingDrops = 7, write fails,
	// Add(7) restores, then logDrop adds 1 → dropCount = 8.
	_ = em.Emit(context.Background(), Event{Channel: "mcp", Tool: Tool{Name: "dead"}, Decision: "allowed"})

	// Start rl2 at rl1's path so the emitter can reconnect.
	rl2 := newRecordingListener(t, dir)
	if err := os.Rename(rl2.path, rl1.path); err != nil {
		t.Fatalf("rename listener socket: %v", err)
	}
	rl2.path = rl1.path

	// Loop until the emitter delivers a frame; any intermediate dial
	// failures only increase the count beyond the minimum.
	deadline := time.Now().Add(3 * time.Second)
	for {
		_ = em.Emit(context.Background(), Event{Channel: "mcp", Tool: Tool{Name: "flush"}, Decision: "allowed"})
		for _, raw := range rl2.snapshot() {
			var f frame
			if err := json.Unmarshal(raw, &f); err != nil {
				continue
			}
			// Must carry at least injected+1 (the injected value was
			// restored, and the write failure itself added 1 more).
			if f.DropCount < injected+1 {
				t.Errorf("drop_count = %d; want >= %d (injected=%d + write failure)",
					f.DropCount, injected+1, injected)
			}
			// The counter must be zero on the immediately following frame.
			beforeCount := len(rl2.snapshot())
			_ = em.Emit(context.Background(), Event{Channel: "mcp", Tool: Tool{Name: "clean"}, Decision: "allowed"})
			frames2 := rl2.waitForFrames(t, beforeCount+1, 2*time.Second)
			var clean frame
			if err := json.Unmarshal(frames2[len(frames2)-1], &clean); err != nil {
				t.Fatalf("unmarshal clean frame: %v", err)
			}
			if clean.DropCount != 0 {
				t.Errorf("clean frame drop_count = %d; want 0 (counter must reset after flush)", clean.DropCount)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("never received a frame; drop_count must carry >= %d", injected+1)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestEmit_DialFailure_SurfacesError asserts the default emit failure contract
// (ADR-0025): Emit returns a non-nil error when the daemon socket is missing,
// rather than silently returning nil.
func TestEmit_DialFailure_SurfacesError(t *testing.T) {
	dir := shortSocketDir(t)
	em, err := NewDaemon(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	err = em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
	})
	if !errors.Is(err, ErrTransport) {
		t.Errorf("Emit err = %v; want a transport failure (errors.Is ErrTransport) on dial failure (ADR-0025)", err)
	}
}

// TestEmit_WriteFailure_SurfacesError asserts the default contract surfaces an
// error when the write fails (listener closed mid-stream), rather than
// silently returning nil.
func TestEmit_WriteFailure_SurfacesError(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	em, err := NewDaemon(
		WithSocketPath(rl.path),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	// Establish the connection via a successful emit.
	if err := em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "first"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	rl.waitForFrames(t, 1, 2*time.Second)

	// Stop listener and remove socket so the next write fails.
	rl.Stop()
	_ = os.Remove(rl.path)
	time.Sleep(50 * time.Millisecond)

	err = em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "failing"},
		Decision: "allowed",
	})
	if !errors.Is(err, ErrTransport) {
		t.Errorf("Emit err = %v; want a transport failure (errors.Is ErrTransport) on write failure (ADR-0025)", err)
	}
}

// TestEmit_BestEffort_DialFailureReturnsNil confirms WithBestEffort opts out of
// the surface-error contract: dial failure returns nil (loss-tolerant path).
func TestEmit_BestEffort_DialFailureReturnsNil(t *testing.T) {
	dir := shortSocketDir(t)
	em, err := NewDaemon(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithLogger(silentLogger()),
		WithBestEffort(),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	if err := em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
	}); err != nil {
		t.Errorf("Emit with WithBestEffort returned error %v; want nil", err)
	}
}

// TestEmit_WithIdentityDefaultsStampedOnFrame asserts that identity fields set
// via WithIdentity are included in every emitted frame and absent when not set.
func TestEmit_WithIdentityDefaultsStampedOnFrame(t *testing.T) {
	dir := shortSocketDir(t)

	t.Run("identity fields present", func(t *testing.T) {
		rl := newRecordingListener(t, dir)
		em, err := NewDaemon(
			WithSocketPath(rl.path),
			WithLogger(silentLogger()),
			WithIdentity(Identity{
				IssuerName:   "Claude Code",
				IssuerModel:  "claude-opus-4-5",
				OperatorID:   "did:web:anthropic.com",
				OperatorName: "Anthropic",
			}),
		)
		if err != nil {
			t.Fatalf("NewDaemon: %v", err)
		}
		defer em.Close()

		if err := em.Emit(context.Background(), Event{
			Channel:  "mcp",
			Tool:     Tool{Name: "bash"},
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("Emit: %v", err)
		}

		frames := rl.waitForFrames(t, 1, 2*time.Second)
		var got frame
		if err := json.Unmarshal(frames[0], &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.IssuerName != "Claude Code" {
			t.Errorf("issuer_name = %q; want %q", got.IssuerName, "Claude Code")
		}
		if got.IssuerModel != "claude-opus-4-5" {
			t.Errorf("issuer_model = %q; want %q", got.IssuerModel, "claude-opus-4-5")
		}
		if got.OperatorID != "did:web:anthropic.com" {
			t.Errorf("operator_id = %q; want %q", got.OperatorID, "did:web:anthropic.com")
		}
		if got.OperatorName != "Anthropic" {
			t.Errorf("operator_name = %q; want %q", got.OperatorName, "Anthropic")
		}
	})

	t.Run("identity fields absent when not set", func(t *testing.T) {
		rl := newRecordingListener(t, dir)
		em, err := NewDaemon(
			WithSocketPath(rl.path),
			WithLogger(silentLogger()),
			// no WithIdentity
		)
		if err != nil {
			t.Fatalf("NewDaemon: %v", err)
		}
		defer em.Close()

		if err := em.Emit(context.Background(), Event{
			Channel:  "mcp",
			Tool:     Tool{Name: "bash"},
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("Emit: %v", err)
		}

		frames := rl.waitForFrames(t, 1, 2*time.Second)
		// Unmarshal into a map to verify that the identity keys are absent
		// entirely (omitempty should suppress them), not just absent from
		// string content.
		var got map[string]json.RawMessage
		if err := json.Unmarshal(frames[0], &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, key := range []string{"issuer_name", "issuer_model", "operator_id", "operator_name"} {
			if _, present := got[key]; present {
				t.Errorf("frame JSON contains %q but should be omitted when empty", key)
			}
		}
	})

	t.Run("per-event override takes precedence over default", func(t *testing.T) {
		rl := newRecordingListener(t, dir)
		em, err := NewDaemon(
			WithSocketPath(rl.path),
			WithLogger(silentLogger()),
			WithIdentity(Identity{
				IssuerName:   "Default Host",
				OperatorID:   "did:web:default.com",
				OperatorName: "Default Operator",
			}),
		)
		if err != nil {
			t.Fatalf("NewDaemon: %v", err)
		}
		defer em.Close()

		if err := em.Emit(context.Background(), Event{
			Channel:      "mcp",
			Tool:         Tool{Name: "bash"},
			Decision:     "allowed",
			IssuerName:   "Per-Event Host",
			OperatorID:   "did:web:override.com",
			OperatorName: "Per-Event Operator",
		}); err != nil {
			t.Fatalf("Emit: %v", err)
		}

		frames := rl.waitForFrames(t, 1, 2*time.Second)
		var got frame
		if err := json.Unmarshal(frames[0], &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.IssuerName != "Per-Event Host" {
			t.Errorf("issuer_name = %q; want per-event value %q", got.IssuerName, "Per-Event Host")
		}
		if got.OperatorID != "did:web:override.com" {
			t.Errorf("operator_id = %q; want per-event value %q", got.OperatorID, "did:web:override.com")
		}
		if got.OperatorName != "Per-Event Operator" {
			t.Errorf("operator_name = %q; want per-event value %q", got.OperatorName, "Per-Event Operator")
		}
	})

	t.Run("partial per-event override merges with defaults independently", func(t *testing.T) {
		// Defaults: full operator identity. Event overrides only IssuerName.
		// Verifies that per-field merge is independent: unset event fields fall
		// through to the default, and the overridden field is taken from the event.
		rl := newRecordingListener(t, dir)
		em, err := NewDaemon(
			WithSocketPath(rl.path),
			WithLogger(silentLogger()),
			WithIdentity(Identity{
				OperatorID:   "did:web:default.com",
				OperatorName: "Default",
			}),
		)
		if err != nil {
			t.Fatalf("NewDaemon: %v", err)
		}
		defer em.Close()

		if err := em.Emit(context.Background(), Event{
			Channel:    "mcp",
			Tool:       Tool{Name: "bash"},
			Decision:   "allowed",
			IssuerName: "Override",
			// IssuerModel, OperatorID, OperatorName not set — fall through to defaults.
		}); err != nil {
			t.Fatalf("Emit: %v", err)
		}

		frames := rl.waitForFrames(t, 1, 2*time.Second)
		var got frame
		if err := json.Unmarshal(frames[0], &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.IssuerName != "Override" {
			t.Errorf("issuer_name = %q; want %q (per-event override)", got.IssuerName, "Override")
		}
		if got.OperatorID != "did:web:default.com" {
			t.Errorf("operator_id = %q; want %q (from default)", got.OperatorID, "did:web:default.com")
		}
		if got.OperatorName != "Default" {
			t.Errorf("operator_name = %q; want %q (from default)", got.OperatorName, "Default")
		}
		if got.IssuerModel != "" {
			t.Errorf("issuer_model = %q; want empty (not in defaults, not in event)", got.IssuerModel)
		}
	})
}

func TestEmit_ConcurrentCallsAreSerialised(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	em, err := NewDaemon(
		WithSocketPath(rl.path),
		WithSessionID("concurrent-test"),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_ = em.Emit(context.Background(), Event{
				Channel:  "mcp",
				Tool:     Tool{Name: "concurrent"},
				Decision: "allowed",
			})
		}()
	}
	wg.Wait()

	frames := rl.waitForFrames(t, n, 5*time.Second)
	if len(frames) != n {
		t.Fatalf("got %d frames; want %d", len(frames), n)
	}
	// Every frame must be parseable JSON: a torn write would corrupt the
	// length prefix and the recording listener would log a read error,
	// producing fewer than n frames or unparseable bytes here.
	for i, f := range frames {
		var got frame
		if err := json.Unmarshal(f, &got); err != nil {
			t.Errorf("frame %d: unmarshal: %v (raw: %s)", i, err, f)
		}
	}
}

// TestEmit_PromptPreviewStampedOnFrame verifies the optional PromptPreview
// event field reaches the wire frame as prompt_preview, so the daemon can store
// (and bound) intent.prompt_preview. The emitter forwards it verbatim; the
// daemon owns truncation (issue #478).
func TestEmit_PromptPreviewStampedOnFrame(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	em, err := NewDaemon(
		WithSocketPath(rl.path),
		WithSessionID("preview-test"),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	const preview = "Send the Q3 report to the team"
	ev := Event{
		Channel:       "claude-code",
		Tool:          Tool{Name: "Bash"},
		Decision:      "allowed",
		PromptPreview: preview,
	}
	if err := em.Emit(context.Background(), ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	frames := rl.waitForFrames(t, 1, 2*time.Second)
	if len(frames) != 1 {
		t.Fatalf("got %d frames; want 1", len(frames))
	}
	var got frame
	if err := json.Unmarshal(frames[0], &got); err != nil {
		t.Fatalf("unmarshal frame: %v (raw: %s)", err, frames[0])
	}
	if got.PromptPreview != preview {
		t.Errorf("frame.prompt_preview = %q; want %q", got.PromptPreview, preview)
	}
}

// TestEmit_NoPromptPreviewOmitted verifies an empty PromptPreview is omitted
// from the frame entirely (omitempty), so emitters that send no preview produce
// the same bytes as before this field existed.
func TestEmit_NoPromptPreviewOmitted(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	em, err := NewDaemon(
		WithSocketPath(rl.path),
		WithSessionID("no-preview-test"),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	ev := Event{Channel: "claude-code", Tool: Tool{Name: "Bash"}, Decision: "allowed"}
	if err := em.Emit(context.Background(), ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	frames := rl.waitForFrames(t, 1, 2*time.Second)
	if len(frames) != 1 {
		t.Fatalf("got %d frames; want 1", len(frames))
	}
	if strings.Contains(string(frames[0]), "prompt_preview") {
		t.Errorf("frame should omit prompt_preview when unset; got %s", frames[0])
	}
}
