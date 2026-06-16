// Command obsigna-hook is a short-lived hook binary invoked by agent runtimes
// (Claude Code, Codex, …) on PostToolUse and PreToolUse events. It reads a JSON
// frame from stdin, maps it to an emitter.Event, and forwards it to the
// agent-receipts daemon over a Unix-domain socket.
//
// It is the primary hook entrypoint (ADR-0036). The legacy agent-receipts-hook
// binary is a thin deprecation shim that forwards here (see
// ../agent-receipts-hook), so existing runtime configs that invoke the hook by
// the old name keep working through the rename. Unlike the daemon/mcp/collector
// binaries, the hook gets no `obsigna hook run` launcher: it is a per-tool-call
// callback, and wrapping it would tax every event for no benefit (ADR-0034
// decision 5).
//
// Exit behaviour:
//   - stdin unreadable or runtime not recognised → silent exit 0 (not our concern)
//   - runtime identified, any subsequent failure → exit 1 + message to stderr
//
// The strict-error exit-1 behaviour is intentional: once we know which runtime
// is calling us, a failure to record the receipt is a signal worth surfacing.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"

	"github.com/agent-receipts/ar/sdk/go/emitter"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
// Falls back to the module version from Go's build info (set automatically
// for binaries installed with `go install`), then to "dev". Mirrors the
// resolveVersion pattern in mcp-proxy/cmd/obsigna-mcp/main.go and
// daemon/cmd/obsigna-daemon/main.go so operators see a useful string
// from `--version` in any install scenario.
var version string

func resolveVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

// reader maps a raw stdin payload and an env-lookup function to an
// emitter.Event. The sessionID return value is the host-supplied session
// identifier (empty string when not present in the payload).
type reader func(stdin []byte, env func(string) string) (ev emitter.Event, sessionID string, err error)

var formats = map[string]reader{
	"claude-code": readClaudeCode,
}

// detect returns the format name inferred from the stdin payload and
// environment. An empty string means no format could be auto-detected; the
// caller should fall back to the --format flag or exit silently.
//
// Claude Code does not set CLAUDE_SESSION_ID as an environment variable; it
// passes hook_event_name in the stdin JSON payload instead. We check both
// signals so the binary works with runtimes that take either approach.
// Both "PostToolUse" and "PreToolUse" are accepted from stdin.
func detect(stdin []byte, env func(string) string) string {
	if env("CLAUDE_SESSION_ID") != "" {
		return "claude-code"
	}
	var probe struct {
		HookEventName string `json:"hook_event_name"`
	}
	if json.Unmarshal(stdin, &probe) == nil {
		switch probe.HookEventName {
		case "PostToolUse", "PreToolUse":
			return "claude-code"
		}
	}
	return ""
}

func main() {
	formatFlag := flag.String("format", "", "Force a specific input format (e.g. claude-code). Auto-detected when unset.")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("obsigna-hook %s\n", resolveVersion())
		return
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Cap stdin at MaxFrameSize+overhead: the emitter rejects larger payloads
	// anyway, and a hard limit here prevents unbounded buffering in the
	// short-lived hook process when stdin is not the expected JSON frame.
	stdin, err := io.ReadAll(io.LimitReader(os.Stdin, emitter.MaxFrameSize+4096))
	if err != nil {
		// stdin unreadable — drop silently, exit 0.
		os.Exit(0)
	}

	env := os.Getenv

	format := *formatFlag
	if format == "" {
		format = detect(stdin, env)
	}
	if format == "" {
		// Unknown runtime — nothing to record.
		os.Exit(0)
	}

	// Runtime identified. From this point, failures exit 1 with a message so
	// the agent runtime can surface the problem.

	read, ok := formats[format]
	if !ok {
		fmt.Fprintf(os.Stderr, "obsigna-hook: unsupported format %q\n", format)
		os.Exit(1)
	}

	ev, sessionID, err := read(stdin, env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "obsigna-hook: cannot parse %s payload: %v\n", format, err)
		os.Exit(1)
	}

	opts := []emitter.Option{
		emitter.WithLogger(logger),
	}
	if sessionID != "" {
		opts = append(opts, emitter.WithSessionID(sessionID))
	}

	em, err := emitter.NewDaemon(opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "obsigna-hook: cannot create emitter: %v\n", err)
		os.Exit(1)
	}
	defer em.Close()

	if err := em.Emit(context.Background(), ev); err != nil {
		fmt.Fprintf(os.Stderr, "obsigna-hook: emit failed: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
