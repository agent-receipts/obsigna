package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agent-receipts/ar/sdk/go/emitter"
)

// --- readClaudeCode unit tests ---

func TestReadClaudeCode(t *testing.T) {
	tests := []struct {
		name         string
		stdin        string
		wantErr      bool
		wantTool     string
		wantSID      string
		wantDecision string
		wantInput    bool
		wantOut      bool
	}{
		{
			name: "PostToolUse full frame",
			stdin: `{
				"hook_event_name": "PostToolUse",
				"session_id": "sess-abc",
				"tool_name": "Bash",
				"tool_input": {"command":"go test ./..."},
				"tool_response": {"output":"ok","exit_code":0}
			}`,
			wantTool:     "Bash",
			wantSID:      "sess-abc",
			wantDecision: "allowed",
			wantInput:    true,
			wantOut:      true,
		},
		{
			name: "PreToolUse frame",
			stdin: `{
				"hook_event_name": "PreToolUse",
				"session_id": "sess-pre",
				"tool_use_id": "tu-001",
				"tool_name": "Bash",
				"tool_input": {"command":"rm -rf /"}
			}`,
			wantTool:     "Bash",
			wantSID:      "sess-pre",
			wantDecision: "pending",
			wantInput:    true,
			wantOut:      false,
		},
		{
			name: "legacy frame without hook_event_name falls back to allowed",
			stdin: `{
				"session_id": "sess-legacy",
				"tool_name": "Bash",
				"tool_input": {"command":"go test ./..."},
				"tool_response": {"output":"ok","exit_code":0}
			}`,
			wantTool:     "Bash",
			wantSID:      "sess-legacy",
			wantDecision: "allowed",
			wantInput:    true,
			wantOut:      true,
		},
		{
			name: "no session_id",
			stdin: `{
				"hook_event_name": "PostToolUse",
				"tool_name": "Read",
				"tool_input": {"file_path":"/etc/hosts"},
				"tool_response": {"content":"127.0.0.1 localhost"}
			}`,
			wantTool:     "Read",
			wantSID:      "",
			wantDecision: "allowed",
			wantInput:    true,
			wantOut:      true,
		},
		{
			name: "no tool_input",
			stdin: `{
				"hook_event_name": "PostToolUse",
				"session_id": "s1",
				"tool_name": "WebSearch",
				"tool_response": {"results":[]}
			}`,
			wantTool:     "WebSearch",
			wantSID:      "s1",
			wantDecision: "allowed",
			wantInput:    false,
			wantOut:      true,
		},
		{
			name: "no tool_response",
			stdin: `{
				"hook_event_name": "PostToolUse",
				"session_id": "s2",
				"tool_name": "Write",
				"tool_input": {"file_path":"x.go","content":"package main"}
			}`,
			wantTool:     "Write",
			wantSID:      "s2",
			wantDecision: "allowed",
			wantInput:    true,
			wantOut:      false,
		},
		{
			name:    "missing tool_name",
			stdin:   `{"session_id":"s3","tool_input":{},"tool_response":{}}`,
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			stdin:   `not json at all`,
			wantErr: true,
		},
		{
			name:    "empty stdin",
			stdin:   ``,
			wantErr: true,
		},
		{
			name: "oversized payload (within emitter limit) passes readClaudeCode",
			stdin: func() string {
				// Build a frame with a large but valid JSON input.
				val := strings.Repeat("x", 100)
				f := map[string]any{
					"hook_event_name": "PostToolUse",
					"session_id":      "big",
					"tool_name":       "Bash",
					"tool_input":      map[string]string{"command": val},
					"tool_response":   map[string]string{"output": val},
				}
				b, _ := json.Marshal(f)
				return string(b)
			}(),
			wantTool:     "Bash",
			wantSID:      "big",
			wantDecision: "allowed",
			wantInput:    true,
			wantOut:      true,
		},
	}

	noEnv := func(string) string { return "" }

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, sid, err := readClaudeCode([]byte(tt.stdin), noEnv)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ev.Channel != "claude-code" {
				t.Errorf("Channel = %q; want claude-code", ev.Channel)
			}
			if ev.Tool.Name != tt.wantTool {
				t.Errorf("Tool.Name = %q; want %q", ev.Tool.Name, tt.wantTool)
			}
			if ev.Tool.Server != "" {
				t.Errorf("Tool.Server = %q; want empty", ev.Tool.Server)
			}
			wantDecision := tt.wantDecision
			if wantDecision == "" {
				wantDecision = "allowed"
			}
			if ev.Decision != wantDecision {
				t.Errorf("Decision = %q; want %q", ev.Decision, wantDecision)
			}
			if sid != tt.wantSID {
				t.Errorf("sessionID = %q; want %q", sid, tt.wantSID)
			}
			if tt.wantInput && ev.Input == nil {
				t.Error("Input is nil; want non-nil")
			}
			if !tt.wantInput && ev.Input != nil {
				t.Errorf("Input = %s; want nil", ev.Input)
			}
			if tt.wantOut && ev.Output == nil {
				t.Error("Output is nil; want non-nil")
			}
			if !tt.wantOut && ev.Output != nil {
				t.Errorf("Output = %s; want nil", ev.Output)
			}
		})
	}
}

// TestReadClaudeCode_InputOutputAreValidJSON asserts the returned Input and
// Output are valid JSON when present.
func TestReadClaudeCode_InputOutputAreValidJSON(t *testing.T) {
	stdin := `{
		"session_id": "v",
		"tool_name": "Edit",
		"tool_input": {"file_path":"a.go","old_string":"x","new_string":"y"},
		"tool_response": {"success":true}
	}`
	ev, _, err := readClaudeCode([]byte(stdin), func(string) string { return "" })
	if err != nil {
		t.Fatalf("readClaudeCode: %v", err)
	}
	if !json.Valid(ev.Input) {
		t.Errorf("Input is not valid JSON: %s", ev.Input)
	}
	if !json.Valid(ev.Output) {
		t.Errorf("Output is not valid JSON: %s", ev.Output)
	}
}

// --- detect unit tests ---

func TestDetect(t *testing.T) {
	tests := []struct {
		name  string
		stdin string
		env   map[string]string
		want  string
	}{
		{
			name: "CLAUDE_SESSION_ID env var set",
			env:  map[string]string{"CLAUDE_SESSION_ID": "abc"},
			want: "claude-code",
		},
		{
			name:  "hook_event_name in stdin (no env var)",
			stdin: `{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"Bash","tool_input":{},"tool_response":{}}`,
			env:   map[string]string{},
			want:  "claude-code",
		},
		{
			name:  "hook_event_name takes precedence over missing env var",
			stdin: `{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"Read"}`,
			env:   map[string]string{"CLAUDE_SESSION_ID": ""},
			want:  "claude-code",
		},
		{
			name:  "no env var and no hook_event_name in stdin",
			stdin: `{"session_id":"s","tool_name":"Bash"}`,
			env:   map[string]string{},
			want:  "",
		},
		{
			name:  "PreToolUse hook_event_name is detected as claude-code",
			stdin: `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Bash","tool_input":{}}`,
			env:   map[string]string{},
			want:  "claude-code",
		},
		{
			name:  "unrecognised hook_event_name is not detected",
			stdin: `{"hook_event_name":"StopHook","session_id":"s"}`,
			env:   map[string]string{},
			want:  "",
		},
		{
			name: "no known env vars and empty stdin",
			env:  map[string]string{},
			want: "",
		},
		{
			name: "unrelated env var",
			env:  map[string]string{"HOME": "/home/user"},
			want: "",
		},
		{
			name: "CLAUDE_SESSION_ID empty string",
			env:  map[string]string{"CLAUDE_SESSION_ID": ""},
			want: "",
		},
		{
			name:  "malformed stdin does not panic",
			stdin: `not json`,
			env:   map[string]string{},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detect([]byte(tt.stdin), func(k string) string { return tt.env[k] })
			if got != tt.want {
				t.Errorf("detect() = %q; want %q", got, tt.want)
			}
		})
	}
}

// --- emitter.Event compatibility tests ---

// checkEventAcceptedByEmitter replicates the emitter's validation rules without
// dialling a socket. Used by TestReadClaudeCode_EventAcceptedByEmitter and
// TestReadClaudeCode_PreToolUseAcceptedByEmitter.
func checkEventAcceptedByEmitter(t *testing.T, ev emitter.Event) {
	t.Helper()
	if ev.Channel == "" {
		t.Error("Channel is empty; emitter would reject")
	}
	if ev.Tool.Name == "" {
		t.Error("Tool.Name is empty; emitter would reject")
	}
	switch ev.Decision {
	case "allowed", "denied", "pending":
	default:
		t.Errorf("Decision %q not in allowed set; emitter would reject", ev.Decision)
	}
	if ev.Input != nil && len(ev.Input) == 0 {
		t.Error("Input is non-nil empty slice; emitter would reject")
	}
	if ev.Output != nil && len(ev.Output) == 0 {
		t.Error("Output is non-nil empty slice; emitter would reject")
	}
	if ev.Input != nil && !json.Valid(ev.Input) {
		t.Errorf("Input is not valid JSON: %s", ev.Input)
	}
	if ev.Output != nil && !json.Valid(ev.Output) {
		t.Errorf("Output is not valid JSON: %s", ev.Output)
	}
	// Sanity-check emitter.Tool type is used (compile-time check embedded here).
	var _ emitter.Tool = ev.Tool
}

// TestReadClaudeCode_EventAcceptedByEmitter verifies that the emitter.Event
// produced by readClaudeCode for a PostToolUse frame satisfies the emitter's
// validation rules. This catches mismatches before the emitter rejects the
// frame at emit time.
func TestReadClaudeCode_EventAcceptedByEmitter(t *testing.T) {
	stdin := `{
		"hook_event_name": "PostToolUse",
		"session_id": "compat-test",
		"tool_name": "Bash",
		"tool_input": {"command":"echo hello"},
		"tool_response": {"output":"hello\n","exit_code":0}
	}`
	ev, _, err := readClaudeCode([]byte(stdin), func(string) string { return "" })
	if err != nil {
		t.Fatalf("readClaudeCode: %v", err)
	}
	if ev.Decision != "allowed" {
		t.Errorf("PostToolUse decision = %q; want allowed", ev.Decision)
	}
	checkEventAcceptedByEmitter(t, ev)
}

// TestReadClaudeCode_PreToolUseAcceptedByEmitter verifies that the emitter.Event
// produced by readClaudeCode for a PreToolUse frame satisfies the emitter's
// validation rules, with decision="pending".
func TestReadClaudeCode_PreToolUseAcceptedByEmitter(t *testing.T) {
	stdin := `{
		"hook_event_name": "PreToolUse",
		"session_id": "pre-compat-test",
		"tool_use_id": "tu-abc",
		"tool_name": "Write",
		"tool_input": {"file_path":"x.go","content":"package main"}
	}`
	ev, _, err := readClaudeCode([]byte(stdin), func(string) string { return "" })
	if err != nil {
		t.Fatalf("readClaudeCode: %v", err)
	}
	if ev.Decision != "pending" {
		t.Errorf("PreToolUse decision = %q; want pending", ev.Decision)
	}
	checkEventAcceptedByEmitter(t, ev)
}

// --- extractFileTarget unit tests ---

func TestExtractFileTarget(t *testing.T) {
	cases := []struct {
		name        string
		toolName    string
		input       string
		wantSys     string
		wantRes     string
		wantWarning bool // true = non-empty warning expected
	}{
		// Known file tools — file_path present.
		{
			name:     "Read with file_path",
			toolName: "Read",
			input:    `{"file_path":"/etc/hosts"}`,
			wantSys:  "filesystem",
			wantRes:  "/etc/hosts",
		},
		{
			name:     "Write with file_path",
			toolName: "Write",
			input:    `{"file_path":"src/main.go","content":"package main"}`,
			wantSys:  "filesystem",
			wantRes:  "src/main.go",
		},
		{
			name:     "Edit with file_path",
			toolName: "Edit",
			input:    `{"file_path":"a.go","old_string":"x","new_string":"y"}`,
			wantSys:  "filesystem",
			wantRes:  "a.go",
		},
		{
			name:     "MultiEdit with file_path",
			toolName: "MultiEdit",
			input:    `{"file_path":"b.go","edits":[]}`,
			wantSys:  "filesystem",
			wantRes:  "b.go",
		},
		// Known file tools — file_path absent (schema drift): must warn.
		{
			name:        "Read without file_path triggers warning",
			toolName:    "Read",
			input:       `{"offset":0}`,
			wantWarning: true,
		},
		{
			name:        "Write without file_path triggers warning",
			toolName:    "Write",
			input:       `{"content":"x"}`,
			wantWarning: true,
		},
		// Skip-listed tools — never attempt extraction.
		{
			name:     "Bash is skipped",
			toolName: "Bash",
			input:    `{"command":"ls"}`,
		},
		{
			name:     "Agent is skipped",
			toolName: "Agent",
			input:    `{"prompt":"do stuff"}`,
		},
		{
			name:     "WebFetch is skipped",
			toolName: "WebFetch",
			input:    `{"url":"https://example.com"}`,
		},
		{
			name:     "WebSearch is skipped",
			toolName: "WebSearch",
			input:    `{"query":"golang"}`,
		},
		// MCP tools — always skipped regardless of input.
		{
			name:     "MCP tool with file_path is skipped",
			toolName: "mcp__github-audited__list_issues",
			input:    `{"file_path":"/sneaky"}`,
		},
		// Unknown tools — opportunistic extraction, no warning on miss.
		{
			name:     "unknown tool with file_path is auto-captured",
			toolName: "Move",
			input:    `{"file_path":"old.go","destination":"new.go"}`,
			wantSys:  "filesystem",
			wantRes:  "old.go",
		},
		{
			name:     "unknown tool without file_path: silent, no warning",
			toolName: "Grep",
			input:    `{"pattern":"func","path":"."}`,
		},
		// Edge cases.
		{
			name:     "empty input returns empty",
			toolName: "Read",
			input:    "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sys, res, warn := extractFileTarget(tc.toolName, json.RawMessage(tc.input))
			if sys != tc.wantSys {
				t.Errorf("system = %q; want %q", sys, tc.wantSys)
			}
			if res != tc.wantRes {
				t.Errorf("resource = %q; want %q", res, tc.wantRes)
			}
			if tc.wantWarning && warn == "" {
				t.Error("warning = \"\"; want non-empty warning")
			}
			if !tc.wantWarning && warn != "" {
				t.Errorf("warning = %q; want empty", warn)
			}
		})
	}
}

// TestExtractFileTarget_WarningNamesTheTool checks that the warning message
// includes the tool name so operators can triage the degradation.
func TestExtractFileTarget_WarningNamesTheTool(t *testing.T) {
	_, _, warn := extractFileTarget("Read", json.RawMessage(`{"offset":0}`))
	if warn == "" {
		t.Fatal("expected warning; got empty")
	}
	if !strings.Contains(warn, "Read") {
		t.Errorf("warning %q does not contain tool name %q", warn, "Read")
	}
}

// TestExtractFileTarget_WhitespaceFilePath checks that a file_path containing
// only whitespace is treated as absent (trimmed to empty), not as a valid path.
// Known file tools must still warn; unknown tools must be silent.
func TestExtractFileTarget_WhitespaceFilePath(t *testing.T) {
	t.Run("fileTools warns on whitespace-only path", func(t *testing.T) {
		sys, res, warn := extractFileTarget("Read", json.RawMessage(`{"file_path":"   "}`))
		if sys != "" || res != "" {
			t.Errorf("system=%q resource=%q; want both empty for whitespace path", sys, res)
		}
		if warn == "" {
			t.Error("expected warning for whitespace-only path on Read; got empty")
		}
	})
	t.Run("unknown tool is silent on whitespace-only path", func(t *testing.T) {
		sys, res, warn := extractFileTarget("Move", json.RawMessage(`{"file_path":"\t"}`))
		if sys != "" || res != "" {
			t.Errorf("system=%q resource=%q; want both empty for whitespace path", sys, res)
		}
		if warn != "" {
			t.Errorf("unexpected warning for unknown tool with whitespace path: %q", warn)
		}
	})
}

// TestExtractFileTarget_MalformedJSON verifies that malformed JSON input is
// treated as a silent miss (no warning, no resource). Malformed JSON is not
// a schema-drift signal — it should not trigger the fileTools warning.
func TestExtractFileTarget_MalformedJSON(t *testing.T) {
	sys, res, warn := extractFileTarget("Read", json.RawMessage(`{bad json`))
	if sys != "" || res != "" {
		t.Errorf("system=%q resource=%q; want both empty for malformed JSON", sys, res)
	}
	if warn != "" {
		t.Errorf("warning = %q; want empty (malformed JSON is not a schema-drift signal)", warn)
	}
}

// TestReadClaudeCode_Target verifies that readClaudeCode populates ev.Target
// for filesystem tools, auto-captures unknown tools with file_path, and leaves
// target empty for skip-listed and MCP tools.
func TestReadClaudeCode_Target(t *testing.T) {
	cases := []struct {
		name    string
		stdin   string
		wantSys string
		wantRes string
	}{
		{
			name: "Read populates target",
			stdin: `{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"Read",` +
				`"tool_input":{"file_path":"/etc/hosts"},"tool_response":{"content":"127.0.0.1"}}`,
			wantSys: "filesystem",
			wantRes: "/etc/hosts",
		},
		{
			name: "Write populates target",
			stdin: `{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"Write",` +
				`"tool_input":{"file_path":"out.go","content":"package main"}}`,
			wantSys: "filesystem",
			wantRes: "out.go",
		},
		{
			name: "Edit populates target",
			stdin: `{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"Edit",` +
				`"tool_input":{"file_path":"x.go","old_string":"a","new_string":"b"}}`,
			wantSys: "filesystem",
			wantRes: "x.go",
		},
		{
			name: "MultiEdit populates target",
			stdin: `{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"MultiEdit",` +
				`"tool_input":{"file_path":"z.go","edits":[]}}`,
			wantSys: "filesystem",
			wantRes: "z.go",
		},
		{
			name: "unknown tool with file_path is auto-captured",
			stdin: `{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"Move",` +
				`"tool_input":{"file_path":"old.go","destination":"new.go"}}`,
			wantSys: "filesystem",
			wantRes: "old.go",
		},
		{
			name: "Bash leaves target empty",
			stdin: `{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"Bash",` +
				`"tool_input":{"command":"echo hi"},"tool_response":{"output":"hi"}}`,
		},
		{
			name: "MCP tool leaves target empty",
			stdin: `{"hook_event_name":"PostToolUse","session_id":"s",` +
				`"tool_name":"mcp__github-audited__list_issues","tool_input":{"owner":"foo"}}`,
		},
	}
	noEnv := func(string) string { return "" }
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, _, err := readClaudeCode([]byte(tc.stdin), noEnv)
			if err != nil {
				t.Fatalf("readClaudeCode: %v", err)
			}
			if ev.Target.System != tc.wantSys {
				t.Errorf("Target.System = %q; want %q", ev.Target.System, tc.wantSys)
			}
			if ev.Target.Resource != tc.wantRes {
				t.Errorf("Target.Resource = %q; want %q", ev.Target.Resource, tc.wantRes)
			}
		})
	}
}

// --- resolveVersion unit tests ---

// TestResolveVersion_PrefersLDFlagInjection pins the precedence the
// release pipeline relies on: a -ldflags "-X main.version=..." build
// wins over both Go's build info and the "dev" fallback. Mirrors the
// equivalent test in daemon/cmd/agent-receipts-daemon/main_test.go.
func TestResolveVersion_PrefersLDFlagInjection(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	version = "v9.9.9-test"
	if got, want := resolveVersion(), "v9.9.9-test"; got != want {
		t.Errorf("resolveVersion() = %q, want %q", got, want)
	}
}

// TestResolveVersion_FallsBackToDevWhenUnset is the contract when neither
// the release pipeline injected a version nor `go install` produced a
// module version: --version must still print something useful instead of
// an empty string. "dev" matches mcp-proxy's and daemon's behaviour.
func TestResolveVersion_FallsBackToDevWhenUnset(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	version = ""
	got := resolveVersion()
	// Under `go test`, debug.ReadBuildInfo() can return either an empty
	// or "(devel)" Main.Version depending on how the binary was invoked
	// — both branches must yield a non-empty, sensible string. We accept
	// either "dev" or any non-empty version-shaped value (anything that
	// isn't the empty string the operator would never want to see).
	if got == "" {
		t.Error("resolveVersion() returned empty string; --version output would be empty")
	}
}
