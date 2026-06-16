//go:build linux || darwin

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/agent-receipts/ar/sdk/go/emitter"
)

// shortSocketDir returns a temp directory whose path is short enough to fit a
// socket filename within the 104-byte AF_UNIX sun_path limit on macOS.
// t.TempDir() on macOS GitHub Actions can return paths > 90 bytes, leaving
// no room for the socket filename and causing `bind: invalid argument`.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	base := "/tmp"
	if _, err := os.Stat(base); err != nil {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "ar*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// recordingListener accepts frames from a Unix socket and records them.
type recordingListener struct {
	ln       *net.UnixListener
	path     string
	mu       sync.Mutex
	frames   [][]byte
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
			return
		}
		go r.serveConn(conn)
	}
}

func (r *recordingListener) serveConn(conn net.Conn) {
	defer conn.Close()
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > emitter.MaxFrameSize {
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
		close(r.stopped)
		r.ln.Close()
	})
}

func (r *recordingListener) waitForFrames(t *testing.T, want int, timeout time.Duration) [][]byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		r.mu.Lock()
		got := make([][]byte, len(r.frames))
		copy(got, r.frames)
		r.mu.Unlock()
		if len(got) >= want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d frames received within %s; want %d", len(got), timeout, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// wireFrame mirrors emitter.frame for unmarshalling in tests.
type wireFrame struct {
	Version   string `json:"v"`
	SessionID string `json:"session_id"`
	Channel   string `json:"channel"`
	Tool      struct {
		Server string `json:"server,omitempty"`
		Name   string `json:"name"`
	} `json:"tool"`
	Input    json.RawMessage `json:"input,omitempty"`
	Output   json.RawMessage `json:"output,omitempty"`
	Decision string          `json:"decision"`
	TsEmit   string          `json:"ts_emit"`
}

// TestIntegration_ClaudeCodeFrame exercises the full path from stdin parsing
// through emitter to a real AF_UNIX listener. This is the authoritative test
// that a valid Claude Code hook configuration reaches the daemon correctly.
func TestIntegration_ClaudeCodeFrame(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	const sessionID = "integ-session-2026"
	stdin := `{
		"session_id": "` + sessionID + `",
		"tool_name": "Bash",
		"tool_input": {"command":"go test ./..."},
		"tool_response": {"output":"PASS","exit_code":0}
	}`

	ev, sid, err := readClaudeCode([]byte(stdin), func(string) string { return "" })
	if err != nil {
		t.Fatalf("readClaudeCode: %v", err)
	}

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(rl.path),
		emitter.WithSessionID(sid),
		emitter.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
	if err != nil {
		t.Fatalf("emitter.NewDaemon: %v", err)
	}
	defer em.Close()

	if err := em.Emit(context.Background(), ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	frames := rl.waitForFrames(t, 1, 2*time.Second)

	var got wireFrame
	if err := json.Unmarshal(frames[0], &got); err != nil {
		t.Fatalf("unmarshal frame: %v (raw: %s)", err, frames[0])
	}

	if got.Channel != "claude-code" {
		t.Errorf("channel = %q; want claude-code", got.Channel)
	}
	if got.Tool.Name != "Bash" {
		t.Errorf("tool.name = %q; want Bash", got.Tool.Name)
	}
	if got.Tool.Server != "" {
		t.Errorf("tool.server = %q; want empty", got.Tool.Server)
	}
	if got.Decision != "allowed" {
		t.Errorf("decision = %q; want allowed", got.Decision)
	}
	if got.SessionID != sessionID {
		t.Errorf("session_id = %q; want %q", got.SessionID, sessionID)
	}
	if got.Version != emitter.SupportedFrameVersion {
		t.Errorf("v = %q; want %q", got.Version, emitter.SupportedFrameVersion)
	}
	if _, err := time.Parse(time.RFC3339Nano, got.TsEmit); err != nil {
		t.Errorf("ts_emit %q not RFC3339Nano: %v", got.TsEmit, err)
	}
	if !json.Valid(got.Input) {
		t.Errorf("input not valid JSON: %s", got.Input)
	}
	if !json.Valid(got.Output) {
		t.Errorf("output not valid JSON: %s", got.Output)
	}
}

// TestIntegration_DaemonDown_SurfacesError verifies that by default (ADR-0025,
// the mode the hook uses), Emit returns an error when the daemon socket is
// unreachable. The hook then exits non-zero to surface the failure to the agent
// runtime. Latency must still be bounded by the dial timeout so the agent is
// not blocked indefinitely.
func TestIntegration_DaemonDown_SurfacesError(t *testing.T) {
	dir := shortSocketDir(t)
	// No listener started — socket path doesn't exist.
	socketPath := filepath.Join(dir, "missing.sock")

	stdin := `{
		"hook_event_name": "PostToolUse",
		"session_id": "no-daemon",
		"tool_name": "Read",
		"tool_input": {"file_path":"/tmp/test.txt"},
		"tool_response": {"content":"hello"}
	}`

	ev, sid, err := readClaudeCode([]byte(stdin), func(string) string { return "" })
	if err != nil {
		t.Fatalf("readClaudeCode: %v", err)
	}

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(socketPath),
		emitter.WithSessionID(sid),
		emitter.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
	if err != nil {
		t.Fatalf("emitter.NewDaemon: %v", err)
	}
	defer em.Close()

	start := time.Now()
	emitErr := em.Emit(context.Background(), ev)
	elapsed := time.Since(start)

	// By default (ADR-0025), a missing daemon must surface as an error.
	if emitErr == nil {
		t.Error("Emit returned nil; want error when daemon is unreachable")
	}

	// Latency must still be bounded: dial timeout (25ms) is the dominant cost.
	// Allow 2x for slow CI.
	if elapsed > 250*time.Millisecond {
		t.Errorf("Emit took %s; want <250ms even when surfacing the failure", elapsed)
	}
}

// TestIntegration_DaemonDown_BestEffort verifies that with WithBestEffort, the
// loss-tolerant behaviour is available: Emit returns nil quickly when the
// daemon socket is unreachable (ADR-0025 opt-out).
func TestIntegration_DaemonDown_BestEffort(t *testing.T) {
	dir := shortSocketDir(t)
	// No listener started — socket path doesn't exist.
	socketPath := filepath.Join(dir, "missing.sock")

	stdin := `{
		"hook_event_name": "PostToolUse",
		"session_id": "no-daemon-faf",
		"tool_name": "Read",
		"tool_input": {"file_path":"/tmp/test.txt"},
		"tool_response": {"content":"hello"}
	}`

	ev, sid, err := readClaudeCode([]byte(stdin), func(string) string { return "" })
	if err != nil {
		t.Fatalf("readClaudeCode: %v", err)
	}

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(socketPath),
		emitter.WithSessionID(sid),
		emitter.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		emitter.WithBestEffort(),
	)
	if err != nil {
		t.Fatalf("emitter.NewDaemon: %v", err)
	}
	defer em.Close()

	start := time.Now()
	if err := em.Emit(context.Background(), ev); err != nil {
		t.Fatalf("Emit returned error %v; want nil (WithBestEffort)", err)
	}
	elapsed := time.Since(start)

	// dial timeout (25ms) + write timeout (100ms) = 125ms upper bound.
	// Allow 2x for slow CI.
	if elapsed > 250*time.Millisecond {
		t.Errorf("Emit took %s; want <250ms (non-blocking contract)", elapsed)
	}
}
