package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// --- MakeErrorResponse ---

func TestMakeErrorResponse_NoData(t *testing.T) {
	resp := MakeErrorResponse(json.RawMessage(`42`), -32600, "Invalid Request")
	var got map[string]any
	if err := json.Unmarshal(resp, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc: got %v", got["jsonrpc"])
	}
	errObj, ok := got["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %T", got["error"])
	}
	if errObj["code"] != float64(-32600) {
		t.Errorf("code: got %v", errObj["code"])
	}
	if errObj["message"] != "Invalid Request" {
		t.Errorf("message: got %v", errObj["message"])
	}
	if _, hasData := errObj["data"]; hasData {
		t.Error("data should be absent when not provided")
	}
}

func TestMakeErrorResponse_StringID(t *testing.T) {
	resp := MakeErrorResponse(json.RawMessage(`"req-1"`), -32700, "Parse error")
	var got map[string]any
	if err := json.Unmarshal(resp, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["id"] != "req-1" {
		t.Errorf("expected id req-1, got %v", got["id"])
	}
}

func TestMakeErrorResponse_NilID(t *testing.T) {
	resp := MakeErrorResponse(nil, -32600, "Invalid Request")
	var got map[string]any
	if err := json.Unmarshal(resp, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if id, ok := got["id"]; !ok || id != nil {
		t.Errorf("expected id=null for nil id, got %v (present=%v)", id, ok)
	}
}

func TestMakeErrorResponseWithData_NilData(t *testing.T) {
	resp := MakeErrorResponseWithData(json.RawMessage(`1`), -32001, "blocked", nil)
	var got map[string]any
	if err := json.Unmarshal(resp, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	errObj, ok := got["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %T", got["error"])
	}
	if _, hasData := errObj["data"]; hasData {
		t.Error("data should be absent when nil")
	}
}

func TestMakeErrorResponseWithData_WithData(t *testing.T) {
	resp := MakeErrorResponseWithData(json.RawMessage(`1`), -32002, "denied", map[string]any{
		"rule": "block_all",
	})
	var got map[string]any
	if err := json.Unmarshal(resp, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	errObj := got["error"].(map[string]any)
	data, ok := errObj["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data object, got %T", errObj["data"])
	}
	if data["rule"] != "block_all" {
		t.Errorf("expected rule block_all, got %v", data["rule"])
	}
}

// --- New ---

func TestNew_ReturnsProxy(t *testing.T) {
	handler := func(direction string, raw []byte, msg *Message) *HandlerResult { return nil }
	p := New("echo", []string{"hello"}, handler)
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	if p.command != "echo" {
		t.Errorf("command: got %q", p.command)
	}
	if len(p.args) != 1 || p.args[0] != "hello" {
		t.Errorf("args: got %v", p.args)
	}
}

func TestNew_NilHandler(t *testing.T) {
	p := New("cat", nil, nil)
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	if p.handler != nil {
		t.Error("expected nil handler")
	}
}

// --- writeToClient ---

func TestWriteToClient_WritesLineWithNewline(t *testing.T) {
	var buf bytes.Buffer
	p := &Proxy{clientWriter: &buf}
	data := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)
	if err := p.writeToClient(data); err != nil {
		t.Fatalf("writeToClient: %v", err)
	}
	got := buf.String()
	expected := string(data) + "\n"
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestWriteToClient_ThreadSafe(t *testing.T) {
	var buf syncBuffer
	p := &Proxy{clientWriter: &buf}

	var wg sync.WaitGroup
	const n = 50
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf(`{"id":%d}`, i))
			if err := p.writeToClient(data); err != nil {
				t.Errorf("writeToClient: %v", err)
			}
		}(i)
	}
	wg.Wait()

	// All n lines should be present, each terminated with \n.
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != n {
		t.Errorf("expected %d lines, got %d", n, len(lines))
	}
}

func TestWriteToClient_PropagatesWriteError(t *testing.T) {
	p := &Proxy{clientWriter: &failWriter{}}
	err := p.writeToClient([]byte("test"))
	if err == nil {
		t.Fatal("expected error from failing writer")
	}
}

// --- pipe ---

func TestPipe_ForwardsClientToServer(t *testing.T) {
	var dst bytes.Buffer
	p := &Proxy{handler: nil}

	src := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
	p.pipe(src, &dst, "client_to_server")

	got := dst.String()
	if !strings.Contains(got, `"method":"ping"`) {
		t.Errorf("expected forwarded message in dst, got: %q", got)
	}
}

func TestPipe_ForwardsServerToClient(t *testing.T) {
	var clientBuf bytes.Buffer
	p := &Proxy{clientWriter: &clientBuf, handler: nil}

	src := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n")
	var dst bytes.Buffer
	p.pipe(src, &dst, "server_to_client")

	// server_to_client writes to clientWriter, not dst.
	got := clientBuf.String()
	if !strings.Contains(got, `"result":{}`) {
		t.Errorf("expected forwarded message in clientWriter, got: %q", got)
	}
	if dst.Len() > 0 {
		t.Errorf("expected nothing in dst for server_to_client, got: %q", dst.String())
	}
}

func TestPipe_HandlerBlocksMessage(t *testing.T) {
	var clientBuf bytes.Buffer
	blockResp := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"blocked"}}`)
	handler := func(direction string, raw []byte, msg *Message) *HandlerResult {
		return &HandlerResult{Block: true, ClientResponse: blockResp}
	}
	p := &Proxy{clientWriter: &clientBuf, handler: handler}

	src := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"rm\"}}\n")
	var dst bytes.Buffer
	p.pipe(src, &dst, "client_to_server")

	// dst should be empty (blocked), clientWriter should have the block response.
	if dst.Len() > 0 {
		t.Errorf("expected blocked message not forwarded, got: %q", dst.String())
	}
	got := clientBuf.String()
	if !strings.Contains(got, "blocked") {
		t.Errorf("expected block response in clientWriter, got: %q", got)
	}
}

func TestPipe_HandlerAllowsMessage(t *testing.T) {
	var dst bytes.Buffer
	handler := func(direction string, raw []byte, msg *Message) *HandlerResult {
		return nil // allow
	}
	p := &Proxy{handler: handler}

	src := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n")
	p.pipe(src, &dst, "client_to_server")

	if !strings.Contains(dst.String(), `"method":"ping"`) {
		t.Errorf("expected allowed message forwarded, got: %q", dst.String())
	}
}

func TestPipe_HandlerPanicRecovered(t *testing.T) {
	var dst bytes.Buffer
	handler := func(direction string, raw []byte, msg *Message) *HandlerResult {
		panic("deliberate panic in handler")
	}
	p := &Proxy{handler: handler}

	// The pipe should not crash on a panicking handler; the message should be forwarded.
	src := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n")
	// Should not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("pipe should have recovered handler panic, but got: %v", r)
		}
	}()
	p.pipe(src, &dst, "client_to_server")

	// After panic is recovered (result is nil), message should be forwarded.
	if !strings.Contains(dst.String(), `"method":"ping"`) {
		t.Errorf("expected message forwarded after handler panic, got: %q", dst.String())
	}
}

func TestPipe_InvalidJSONForwardedRaw(t *testing.T) {
	var dst bytes.Buffer
	p := &Proxy{handler: nil}

	// Invalid JSON should still be forwarded verbatim (handler gets nil msg).
	src := strings.NewReader("not-json\n")
	p.pipe(src, &dst, "client_to_server")

	got := dst.String()
	if !strings.Contains(got, "not-json") {
		t.Errorf("expected raw non-JSON forwarded, got: %q", got)
	}
}

func TestPipe_MultipleMessages(t *testing.T) {
	var dst bytes.Buffer
	p := &Proxy{handler: nil}

	msgs := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":2,"method":"pong"}`,
		`{"jsonrpc":"2.0","id":3,"method":"foo"}`,
	}, "\n") + "\n"

	p.pipe(strings.NewReader(msgs), &dst, "client_to_server")

	got := dst.String()
	for _, want := range []string{"ping", "pong", "foo"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output, got: %q", want, got)
		}
	}
}

func TestPipe_CRLFStripped(t *testing.T) {
	var dst bytes.Buffer
	p := &Proxy{handler: nil}

	// Message with \r\n line ending.
	src := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n")
	p.pipe(src, &dst, "client_to_server")

	got := dst.String()
	// The forwarded line should not contain \r.
	if strings.Contains(got, "\r") {
		t.Errorf("expected \\r stripped from forwarded message, got: %q", got)
	}
	if !strings.Contains(got, `"method":"ping"`) {
		t.Errorf("expected message content preserved, got: %q", got)
	}
}

func TestPipe_HandlerReceivesDirection(t *testing.T) {
	var capturedDirection string
	var dst bytes.Buffer
	handler := func(direction string, raw []byte, msg *Message) *HandlerResult {
		capturedDirection = direction
		return nil
	}
	p := &Proxy{handler: handler}

	src := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
	p.pipe(src, &dst, "client_to_server")

	if capturedDirection != "client_to_server" {
		t.Errorf("expected direction client_to_server, got %q", capturedDirection)
	}
}

func TestPipe_HandlerBlockWithNilClientResponse(t *testing.T) {
	var clientBuf bytes.Buffer
	handler := func(direction string, raw []byte, msg *Message) *HandlerResult {
		return &HandlerResult{Block: true, ClientResponse: nil}
	}
	p := &Proxy{clientWriter: &clientBuf, handler: handler}

	src := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"test\"}\n")
	var dst bytes.Buffer
	p.pipe(src, &dst, "client_to_server")

	// Nothing forwarded to dst.
	if dst.Len() > 0 {
		t.Errorf("expected nothing forwarded, got: %q", dst.String())
	}
}

// TestPipe_LineTooLong asserts that a line with no newline exceeding
// maxLineLength closes the pipe instead of buffering it without bound (issue
// #1010: bufio.Reader.ReadBytes grows its returned slice without limit while
// searching for the delimiter, so a peer streaming an arbitrarily large line
// could otherwise exhaust the proxy's memory). Nothing should be forwarded
// for the oversized, unterminated line.
func TestPipe_LineTooLong(t *testing.T) {
	var dst bytes.Buffer
	p := &Proxy{handler: nil}

	oversized := bytes.Repeat([]byte("a"), maxLineLength+1) // no trailing newline
	p.pipe(bytes.NewReader(oversized), &dst, "client_to_server")

	if dst.Len() > 0 {
		t.Errorf("expected nothing forwarded for an oversized line, got %d bytes", dst.Len())
	}
}

// TestPipe_LineAtMaxIsForwarded confirms the cap doesn't reject a line that
// exactly matches maxLineLength.
func TestPipe_LineAtMaxIsForwarded(t *testing.T) {
	var dst bytes.Buffer
	p := &Proxy{handler: nil}

	payload := append(bytes.Repeat([]byte("a"), maxLineLength-1), '\n')
	p.pipe(bytes.NewReader(payload), &dst, "client_to_server")

	if !bytes.Contains(dst.Bytes(), bytes.Repeat([]byte("a"), maxLineLength-1)) {
		t.Errorf("expected the max-length line to be forwarded")
	}
}

// --- readLine ---

func TestReadLine_WithinMax(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("hello\nworld"))

	line, err := readLine(r, 1024)
	if err != nil {
		t.Fatalf("first line: unexpected err %v", err)
	}
	if string(line) != "hello\n" {
		t.Errorf("first line = %q; want %q", line, "hello\n")
	}

	line, err = readLine(r, 1024)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("second line: err = %v; want io.EOF", err)
	}
	if string(line) != "world" {
		t.Errorf("second line = %q; want %q", line, "world")
	}
}

func TestReadLine_ExceedsMax(t *testing.T) {
	const max = 4096
	data := bytes.Repeat([]byte("x"), max*3) // no delimiter anywhere
	r := bufio.NewReader(bytes.NewReader(data))

	_, err := readLine(r, max)
	if !errors.Is(err, errLineTooLong) {
		t.Fatalf("err = %v; want errLineTooLong", err)
	}
}

// --- Run double-start guard ---

func TestRun_SecondCallReturnsError(t *testing.T) {
	p := New("true", nil, nil)
	// Mark as started.
	p.startOnce.Do(func() {})
	err := p.Run(context.Background())
	if err == nil {
		t.Fatal("expected error on second Run call")
	}
	if !strings.Contains(err.Error(), "already started") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- IDString edge cases ---

func TestIDString_NilID(t *testing.T) {
	m := &Message{JSONRPC: "2.0"}
	if got := m.IDString(); got != "" {
		t.Errorf("expected empty string for nil ID, got %q", got)
	}
}

func TestIDString_NumericID(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":99,"method":"ping"}`)
	m := ParseMessage(line)
	if m == nil {
		t.Fatal("expected non-nil message")
	}
	if got := m.IDString(); got != "99" {
		t.Errorf("expected IDString()=%q, got %q", "99", got)
	}
}

// --- ParseToolCallParams error case ---

func TestParseToolCallParams_InvalidJSON(t *testing.T) {
	m := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`not-valid-json`),
	}
	params, err := m.ParseToolCallParams()
	if err == nil {
		t.Fatalf("expected error for invalid params JSON, got params: %+v", params)
	}
}

// --- IsResponse edge cases ---

func TestIsResponse_WithError(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}`)
	m := ParseMessage(line)
	if m == nil {
		t.Fatal("expected non-nil message")
	}
	if !m.IsResponse() {
		t.Error("expected error message to be IsResponse")
	}
	if m.IsRequest() {
		t.Error("expected error message to not be IsRequest")
	}
}

func TestIsNotification_False_WhenHasID(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`)
	m := ParseMessage(line)
	if m == nil {
		t.Fatal("expected non-nil message")
	}
	if m.IsNotification() {
		t.Error("request with ID should not be IsNotification")
	}
}

// --- helpers ---

// syncBuffer is a goroutine-safe bytes.Buffer.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// failWriter always returns an error on Write.
type failWriter struct{}

func (f *failWriter) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}
