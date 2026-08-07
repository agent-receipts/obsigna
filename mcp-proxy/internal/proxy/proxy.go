// Package proxy implements a transparent MCP STDIO proxy.
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime/debug"
	"sync"
	"time"
)

// maxLineLength bounds a single line (one JSON-RPC message) read from either
// STDIO pipe. bufio.Reader.ReadBytes grows its returned slice without limit
// while it searches for the delimiter, so a peer that streams an arbitrarily
// large line with no newline would otherwise exhaust the proxy's memory.
// readLine enforces this cap explicitly instead.
const maxLineLength = 10 * 1024 * 1024 // 10MiB

// errLineTooLong is returned by readLine when a line exceeds maxLineLength
// before a newline is found.
var errLineTooLong = errors.New("line too large")

// HandlerResult tells the proxy what to do with a message.
type HandlerResult struct {
	// Block suppresses forwarding and sends ClientResponse to the client instead.
	Block bool
	// ClientResponse is sent to the client when Block is true.
	ClientResponse []byte
}

// Handler is called for each message flowing through the proxy.
// direction is "client_to_server" or "server_to_client".
// Return nil to forward normally.
type Handler func(direction string, raw []byte, msg *Message) *HandlerResult

// Proxy is a transparent STDIO MCP proxy.
type Proxy struct {
	command string
	args    []string
	handler Handler

	cmd          *exec.Cmd
	clientReader io.Reader // os.Stdin — reads from MCP client
	clientWriter io.Writer // os.Stdout — writes to MCP client
	startOnce    sync.Once
	writerMu     sync.Mutex
}

// New creates a new proxy that will spawn the given command.
func New(command string, args []string, handler Handler) *Proxy {
	return &Proxy{
		command: command,
		args:    args,
		handler: handler,
	}
}

// Run starts the child MCP server and proxies stdin/stdout bidirectionally.
// It blocks until the child process exits, either of the STDIO pumps closes
// (stdin EOF ends a normal STDIO session), or ctx is cancelled. Cancellation
// kills the upstream child so both pumps unblock and Run returns promptly.
func (p *Proxy) Run(ctx context.Context) error {
	var firstCall bool
	p.startOnce.Do(func() {
		firstCall = true
	})
	if !firstCall {
		return fmt.Errorf("proxy already started")
	}

	// Capture stdin/stdout once, synchronously, before launching the pump
	// goroutines so the standard streams are read under Run's own goroutine
	// (tests may inject clientReader to avoid touching the os.Stdin global).
	if p.clientReader == nil {
		p.clientReader = os.Stdin
	}
	p.clientWriter = os.Stdout

	p.cmd = exec.Command(p.command, p.args...)
	p.cmd.Stderr = os.Stderr

	serverIn, err := p.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	serverOut, err := p.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}

	// exits carries the pipe direction name when each goroutine finishes.
	// Capacity 2 so neither sender ever blocks.
	exits := make(chan string, 2)

	// Client → Server
	go func() {
		defer serverIn.Close()
		p.pipe(p.clientReader, serverIn, "client_to_server")
		exits <- "client_to_server"
	}()

	// Server → Client
	go func() {
		p.pipe(serverOut, os.Stdout, "server_to_client")
		exits <- "server_to_client"
	}()

	// Wait for the first pipe to finish or for ctx to be cancelled, then kill
	// the upstream so the surviving pipe (and any blocked reads) unblock
	// instead of blocking forever. remaining tracks how many pump exits we
	// still expect to drain: a pipe exit consumes one, a ctx cancel consumes
	// none.
	remaining := 2
	select {
	case first := <-exits:
		log.Printf("mcp-proxy: pipe %s exited, shutting down", first)
		remaining = 1
	case <-ctx.Done():
		log.Printf("mcp-proxy: context cancelled, shutting down")
	}
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}

	// Drain the remaining pipe exits with a short timeout so we capture the
	// reason but do not block forever. Killing the child closes server stdout
	// (server→client unblocks); the client→server pump may still be blocked on
	// a read of os.Stdin with no pending data, so the timeout bounds the wait.
	for ; remaining > 0; remaining-- {
		select {
		case dir := <-exits:
			log.Printf("mcp-proxy: pipe %s exited", dir)
		case <-time.After(2 * time.Second):
			log.Printf("mcp-proxy: remaining pipe did not exit within timeout")
			remaining = 1 // loop decrement ends the drain
		}
	}

	return p.cmd.Wait()
}

// writeToClient sends a message to the MCP client (thread-safe).
func (p *Proxy) writeToClient(data []byte) error {
	p.writerMu.Lock()
	defer p.writerMu.Unlock()
	_, err := fmt.Fprintf(p.clientWriter, "%s\n", data)
	return err
}

func (p *Proxy) pipe(src io.Reader, dst io.Writer, direction string) {
	reader := bufio.NewReaderSize(src, 64*1024)

	for {
		line, err := readLine(reader, maxLineLength)
		if errors.Is(err, errLineTooLong) {
			log.Printf("mcp-proxy: pipe %s line too large (max %d bytes), closing", direction, maxLineLength)
			return
		}
		if len(line) > 0 {
			// Trim trailing newline for processing.
			raw := line
			if len(raw) > 0 && raw[len(raw)-1] == '\n' {
				raw = raw[:len(raw)-1]
			}
			if len(raw) > 0 && raw[len(raw)-1] == '\r' {
				raw = raw[:len(raw)-1]
			}

			msg := ParseMessage(raw)

			if p.handler != nil {
				var result *HandlerResult
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("mcp-proxy: handler panic (%s): %v\n%s", direction, r, debug.Stack())
						}
					}()
					result = p.handler(direction, raw, msg)
				}()
				if result != nil && result.Block {
					// Send the block response to the client, not to dst.
					if writeErr := p.writeToClient(result.ClientResponse); writeErr != nil {
						log.Printf("mcp-proxy: write block response: %v", writeErr)
					}
					continue
				}
			}

			// For server→client, dst is os.Stdout which is also the
			// client writer. Use writeToClient to serialize all writes
			// and avoid interleaving with block responses.
			if direction == "server_to_client" {
				if writeErr := p.writeToClient(raw); writeErr != nil {
					log.Printf("mcp-proxy: write error (%s): %v", direction, writeErr)
					return
				}
			} else if _, writeErr := fmt.Fprintf(dst, "%s\n", raw); writeErr != nil {
				log.Printf("mcp-proxy: write error (%s): %v", direction, writeErr)
				return
			}
		}

		if err != nil {
			if err == io.EOF {
				log.Printf("mcp-proxy: pipe %s closed (EOF)", direction)
			} else {
				log.Printf("mcp-proxy: pipe %s read error: %v", direction, err)
			}
			return
		}
	}
}

// readLine reads one '\n'-delimited line from r, mirroring
// bufio.Reader.ReadBytes but capping the accumulated line at max bytes
// instead of growing the returned slice without bound while it searches for
// the delimiter. Returns errLineTooLong once max is exceeded, before the
// oversized line is fully accumulated.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > max {
			return line, errLineTooLong
		}
		line = append(line, chunk...)
		if err == nil {
			return line, nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return line, err
	}
}

// MakeErrorResponse creates a JSON-RPC error response for the given request ID.
func MakeErrorResponse(id json.RawMessage, code int, message string) []byte {
	return MakeErrorResponseWithData(id, code, message, nil)
}

// MakeErrorResponseWithData creates a JSON-RPC error response with optional
// structured error data for the given request ID.
func MakeErrorResponseWithData(id json.RawMessage, code int, message string, data map[string]any) []byte {
	errObj := map[string]any{
		"code":    code,
		"message": message,
	}
	if data != nil {
		errObj["data"] = data
	}

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error":   errObj,
	}
	b, _ := json.Marshal(resp)
	return b
}
