package socket

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"obsigna.dev/daemon/internal/sockettest"
)

func TestListen_RefusesNonSocketPreexistingFile(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	// Create a regular file at the socket path. A misconfigured
	// AGENTRECEIPTS_SOCKET pointing here must not silently delete it.
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err == nil {
		ln.Close()
		t.Fatal("expected Listen to refuse a non-socket pre-existing file")
	}
	if !strings.Contains(err.Error(), "non-socket") {
		t.Errorf("error message %q should mention non-socket", err.Error())
	}

	// File must still be there — refusing implies not deleting.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("Listen deleted the pre-existing file: %v", err)
	}
}

func TestListen_RequiresPath(t *testing.T) {
	ln, err := Listen(Options{
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err == nil {
		ln.Close()
		t.Fatal("expected error for empty Path")
	}
	if !strings.Contains(err.Error(), "Path is required") {
		t.Errorf("error %q should mention Path is required", err.Error())
	}
}

func TestListen_RequiresHandler(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	ln, err := Listen(Options{
		Path: filepath.Join(dir, "events.sock"),
	})
	if err == nil {
		ln.Close()
		t.Fatal("expected error for nil Handler")
	}
	if !strings.Contains(err.Error(), "Handler is required") {
		t.Errorf("error %q should mention Handler is required", err.Error())
	}
}

func TestListen_RemovesStaleSocket(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	// Create a stale socket file (no listener) by binding and immediately closing.
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	stale, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close()

	// Confirm: connect must fail with ECONNREFUSED (no listener).
	if _, err := net.DialTimeout("unix", path, 50*time.Millisecond); err == nil {
		t.Fatal("expected stale socket to refuse connections")
	}

	// Listen should silently remove the stale socket and succeed.
	ln, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err != nil {
		t.Fatalf("Listen on stale socket: %v", err)
	}
	ln.Close()
}

func TestListen_RefusesWhenAnotherDaemonIsLive(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	first, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = first.Serve(ctx) }()

	// Poll until a probe connect succeeds, instead of sleeping a fixed amount
	// (which is flaky on slow CI runners). 2s is generous; in practice the
	// listener is ready in microseconds on a quiet machine.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if c, derr := net.DialTimeout("unix", path, 100*time.Millisecond); derr == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first listener did not become acceptable within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}

	second, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err == nil {
		second.Close()
		t.Fatal("expected Listen to refuse when another daemon is live on the same socket")
	}
	if !strings.Contains(err.Error(), "already listening") {
		t.Errorf("error %q should mention an active daemon", err.Error())
	}
}

// --- WriteFrame tests ---

func TestWriteFrame_EmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	err := WriteFrame(&buf, nil)
	if err == nil {
		t.Fatal("expected error for nil payload")
	}
}

func TestWriteFrame_EmptySlice(t *testing.T) {
	var buf bytes.Buffer
	err := WriteFrame(&buf, []byte{})
	if err == nil {
		t.Fatal("expected error for empty slice payload")
	}
}

func TestWriteFrame_OversizedPayload(t *testing.T) {
	var buf bytes.Buffer
	big := make([]byte, MaxFrameSize+1)
	err := WriteFrame(&buf, big)
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error %q should mention too large", err.Error())
	}
}

func TestWriteFrame_ExactMaxSize(t *testing.T) {
	var buf bytes.Buffer
	payload := make([]byte, MaxFrameSize)
	for i := range payload {
		payload[i] = 'x'
	}
	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatalf("WriteFrame at MaxFrameSize: %v", err)
	}
	// Header + payload
	if buf.Len() != 4+MaxFrameSize {
		t.Errorf("written %d bytes, want %d", buf.Len(), 4+MaxFrameSize)
	}
}

func TestWriteFrame_RoundTrip(t *testing.T) {
	payload := []byte(`{"event":"test"}`)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round-trip: got %q, want %q", got, payload)
	}
}

func TestWriteFrame_WriterError(t *testing.T) {
	err := WriteFrame(errWriter{}, []byte("hello"))
	if err == nil {
		t.Fatal("expected error from failing writer")
	}
}

// errWriter always returns an error on Write.
type errWriter struct{}

func (errWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failed")
}

// shortWriter returns n bytes written then an error, exercising writeAll loop.
type shortWriter struct {
	written int
	limit   int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if w.written >= w.limit {
		return 0, errors.New("limit reached")
	}
	n := len(p)
	if w.written+n > w.limit {
		n = w.limit - w.written
	}
	w.written += n
	return n, nil
}

func TestWriteFrame_ShortWriteOnBody(t *testing.T) {
	// Allow the 4-byte header through but fail mid-body.
	w := &shortWriter{limit: 4 + 3}
	err := WriteFrame(w, []byte("hello"))
	if err == nil {
		t.Fatal("expected error when writer truncates body")
	}
}

// --- readFrame tests ---

func TestReadFrame_ZeroLength(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 0)
	r := bytes.NewReader(hdr[:])
	_, err := readFrame(r)
	if err == nil {
		t.Fatal("expected error for zero-length frame")
	}
	if !strings.Contains(err.Error(), "zero-length") {
		t.Errorf("error %q should mention zero-length", err.Error())
	}
}

func TestReadFrame_TooLarge(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(MaxFrameSize+1))
	r := bytes.NewReader(hdr[:])
	_, err := readFrame(r)
	if err == nil {
		t.Fatal("expected error for oversized frame")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error %q should mention too large", err.Error())
	}
}

func TestReadFrame_EOFOnHeader(t *testing.T) {
	r := bytes.NewReader([]byte{})
	_, err := readFrame(r)
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected EOF-ish error for empty reader, got %v", err)
	}
}

func TestReadFrame_EOFMidHeader(t *testing.T) {
	// Only 2 bytes instead of 4.
	r := bytes.NewReader([]byte{0x00, 0x00})
	_, err := readFrame(r)
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestReadFrame_EOFMidBody(t *testing.T) {
	// Header says 10 bytes but only 3 follow.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 10)
	data := append(hdr[:], []byte{1, 2, 3}...)
	r := bytes.NewReader(data)
	_, err := readFrame(r)
	if err == nil {
		t.Fatal("expected error for truncated body")
	}
}

// --- Listener functional tests ---

func TestListener_Path(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")
	ln, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if ln.Path() != path {
		t.Errorf("Path() = %q, want %q", ln.Path(), path)
	}
}

func TestListener_CloseIdempotent(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")
	ln, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second Close must not panic or return an unexpected error.
	if err := ln.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestListener_ServeAndReceiveFrame(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	received := make(chan Frame, 1)
	ln, err := Listen(Options{
		Path: path,
		Handler: func(_ context.Context, f Frame) error {
			received <- f
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ln.Serve(ctx) }()

	waitListening(t, path)

	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := []byte(`{"hello":"world"}`)
	if err := WriteFrame(conn, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	select {
	case f := <-received:
		if !bytes.Equal(f.Payload, payload) {
			t.Errorf("payload = %q, want %q", f.Payload, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for frame")
	}
}

func TestListener_HandlerErrorIsLogged(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	var loggedMsg string
	var logMu sync.Mutex

	handlerErr := errors.New("handler boom")
	var frameCount atomic.Int32
	done := make(chan struct{})

	ln, err := Listen(Options{
		Path: path,
		Handler: func(_ context.Context, _ Frame) error {
			if frameCount.Add(1) == 1 {
				close(done)
			}
			return handlerErr
		},
		ErrorLog: func(format string, args ...any) {
			logMu.Lock()
			// Capture the first log message.
			if loggedMsg == "" {
				loggedMsg = format
			}
			logMu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ln.Serve(ctx) }()

	waitListening(t, path)

	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := WriteFrame(conn, []byte(`{"x":1}`)); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never called")
	}

	// Give the error log a moment to be written.
	time.Sleep(10 * time.Millisecond)

	logMu.Lock()
	msg := loggedMsg
	logMu.Unlock()

	if !strings.Contains(msg, "handler error") {
		t.Errorf("expected error log to mention handler error, got %q", msg)
	}
}

func TestListener_MultipleFramesOnOneConn(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	const nFrames = 5
	var count atomic.Int32
	allReceived := make(chan struct{})

	ln, err := Listen(Options{
		Path: path,
		Handler: func(_ context.Context, _ Frame) error {
			if int(count.Add(1)) == nFrames {
				close(allReceived)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ln.Serve(ctx) }()

	waitListening(t, path)

	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	for i := 0; i < nFrames; i++ {
		if err := WriteFrame(conn, []byte(`{"n":1}`)); err != nil {
			t.Fatalf("WriteFrame %d: %v", i, err)
		}
	}

	select {
	case <-allReceived:
	case <-time.After(3 * time.Second):
		t.Fatalf("only received %d/%d frames", count.Load(), nFrames)
	}
}

func TestListener_ServeStopsOnContextCancel(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	ln, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- ln.Serve(ctx) }()

	waitListening(t, path)
	cancel()

	select {
	case err := <-serveDone:
		if err != nil {
			t.Errorf("Serve returned non-nil error on ctx cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not stop after ctx cancel")
	}
}

func TestListener_ErrorLog_NilDoesNotPanic(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	// ErrorLog: nil — logf must silently discard.
	ln, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return errors.New("boom") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ln.Serve(ctx) }()

	waitListening(t, path)

	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a frame; handler returns error but ErrorLog is nil — must not panic.
	done := make(chan struct{})
	if err := WriteFrame(conn, []byte(`{"x":1}`)); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	// Give the handler time to run.
	go func() {
		time.Sleep(100 * time.Millisecond)
		close(done)
	}()
	<-done
}

func TestListener_CleanupOnPeerClose(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	ln, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ln.Serve(ctx) }()

	waitListening(t, path)

	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Send one frame, then close the connection.
	if err := WriteFrame(conn, []byte(`{"bye":true}`)); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	conn.Close()

	// The listener should still be functional after the peer disconnects.
	// Poll until we can reconnect and send another frame.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c2, derr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if derr == nil {
			if werr := WriteFrame(c2, []byte(`{"reconnect":true}`)); werr != nil {
				c2.Close()
				t.Fatalf("WriteFrame on reconnect: %v", werr)
			}
			c2.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("listener not reachable after peer close")
}

// waitListening polls until a probe connect succeeds, up to 2 seconds.
func waitListening(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if c, err := net.DialTimeout("unix", path, 100*time.Millisecond); err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("listener not ready within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
