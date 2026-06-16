package proxy_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"
)

// buildTestBinary compiles a Go package into tmpDir and returns the binary path.
func buildTestBinary(t *testing.T, pkg, tmpDir, name string) string {
	t.Helper()
	out := filepath.Join(tmpDir, name)
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build %s: %v", pkg, err)
	}
	return out
}

// startParallelProxy starts the mcp-proxy binary with fakeserverBin as upstream
// and returns stdin/stdout pipes, a stderr buffer, and the command.
func startParallelProxy(t *testing.T, proxyBin, fakeserverBin string, extraEnv []string) (io.WriteCloser, io.ReadCloser, *bytes.Buffer, *exec.Cmd) {
	t.Helper()
	cmd := exec.Command(proxyBin,
		"--http", "none",
		"--socket", "", // no daemon in test environment
		"--", fakeserverBin,
	)
	cmd.Env = append(os.Environ(), extraEnv...)

	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	t.Cleanup(func() {
		_ = stdinPipe.Close()
		// Subtests may have already waited; only wait again if the process
		// hasn't been reaped yet, and force-kill if it's still running so
		// cleanup doesn't hang.
		if cmd.ProcessState == nil {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			_ = cmd.Wait()
		}
	})

	// Give the proxy a moment to start the child.
	time.Sleep(200 * time.Millisecond)

	return stdinPipe, stdoutPipe, &stderrBuf, cmd
}

// TestParallelToolCalls covers two scenarios for parallel tool-call traffic.
func TestParallelToolCalls(t *testing.T) {
	tmpDir := t.TempDir()
	proxyBin := buildTestBinary(t,
		"github.com/agent-receipts/ar/mcp-proxy/cmd/obsigna-mcp",
		tmpDir, "obsigna-mcp")
	fakeBin := buildTestBinary(t,
		"github.com/agent-receipts/ar/mcp-proxy/internal/proxy/testdata/fakeserver",
		tmpDir, "fakeserver")

	t.Run("AllRespond", func(t *testing.T) {
		stdinW, stdoutR, _, cmd := startParallelProxy(t, proxyBin, fakeBin, nil)

		const n = 10
		scanner := bufio.NewScanner(stdoutR)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

		// Collect responses in the background.
		respCh := make(chan float64, n*2)
		go func() {
			for scanner.Scan() {
				var m map[string]any
				if err := json.Unmarshal(scanner.Bytes(), &m); err != nil {
					continue
				}
				if id, ok := m["id"].(float64); ok {
					respCh <- id
				}
			}
		}()

		// Send n requests in parallel, serialising writes with a mutex.
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := 1; i <= n; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				msg, _ := json.Marshal(map[string]any{
					"jsonrpc": "2.0",
					"id":      id,
					"method":  "tools/call",
					"params":  map[string]any{"name": "test", "arguments": map[string]any{}},
				})
				mu.Lock()
				fmt.Fprintf(stdinW, "%s\n", msg)
				mu.Unlock()
			}(i)
		}
		wg.Wait()

		// Collect all responses within a deadline.
		received := make(map[float64]bool)
		deadline := time.After(10 * time.Second)
		for len(received) < n {
			select {
			case id := <-respCh:
				received[id] = true
			case <-deadline:
				t.Fatalf("timeout: only received %d/%d responses; got ids: %v", len(received), n, received)
			}
		}

		// Clean shutdown.
		stdinW.Close()
		if err := cmd.Wait(); err != nil {
			t.Logf("proxy exited: %v (expected)", err)
		}
	})

	t.Run("UpstreamDiesMidway", func(t *testing.T) {
		// MAX_RESPONSES=5 makes the fakeserver exit after responding to 5 requests.
		stdinW, stdoutR, stderrBuf, cmd := startParallelProxy(t, proxyBin, fakeBin,
			[]string{"MAX_RESPONSES=5"})

		const n = 10
		scanner := bufio.NewScanner(stdoutR)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

		// Drain stdout in the background so the proxy is never blocked writing.
		go func() {
			for scanner.Scan() {
			}
		}()

		// Send n requests; the upstream will exit after 5 without ever sending
		// the remaining responses.
		var mu sync.Mutex
		for i := 1; i <= n; i++ {
			msg, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      i,
				"method":  "tools/call",
				"params":  map[string]any{"name": "test", "arguments": map[string]any{}},
			})
			mu.Lock()
			fmt.Fprintf(stdinW, "%s\n", msg)
			mu.Unlock()
		}

		// Before the fix, wg.Wait() would block forever because the
		// client→server goroutine keeps running. After the fix, Run() exits
		// promptly once the server→client pipe closes.
		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
		}()

		select {
		case <-done:
			// Good — proxy exited as expected.
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			t.Fatal("proxy did not exit within 5s after upstream died — regression of #158")
		}

		// Proxy stderr should mention the pipe exit (EOF or read error).
		stderr := stderrBuf.String()
		re := regexp.MustCompile(`pipe .*(EOF|read error|exited)`)
		if !re.MatchString(stderr) {
			t.Errorf("expected pipe-exit log in stderr, got:\n%s", stderr)
		}
	})
}
