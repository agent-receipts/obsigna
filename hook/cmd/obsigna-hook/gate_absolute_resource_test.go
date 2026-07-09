package main

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"obsigna.dev/sdk/go/emitter"
)

// filesystemResourceIsAbsolute is the gate predicate and the single source of
// truth the CI gate enforces: an emitted filesystem target must carry an
// absolute resource path. A relative filesystem resource makes it return false,
// which fails the gate below and, in CI, the build.
//
// Carve-out (ambiguity clause): the gate covers filesystem resources only.
// "Absolute" is undefined for a non-filesystem resource identifier (e.g. an MCP
// resource URI or an empty target), so any target whose System is not
// "filesystem" — or that carries no resource at all — is exempt. The hook does
// not emit non-filesystem targets today (MCP tools are skipped, both extractors
// return System "filesystem"), so this carve-out is forward-looking; a
// follow-up is filed to define absoluteness for non-fs resources at the spec
// level rather than guessing here.
func filesystemResourceIsAbsolute(ev emitter.Event) bool {
	if ev.Target.System != "filesystem" || ev.Target.Resource == "" {
		return true
	}
	return filepath.IsAbs(ev.Target.Resource)
}

// TestGate_EmittedFilesystemResourceIsAbsolute is the CI gate (frozen decision).
// Every filesystem target readClaudeCode emits must have an absolute resource,
// regardless of whether the runtime supplied a relative or an absolute path in
// the tool input. The fixtures deliberately mix relative inputs (out.go, build,
// out.txt, nested/pkg/file.go) with absolute ones (/etc/hosts) so the gate would
// catch a regression that let a relative path reach the receipt.
func TestGate_EmittedFilesystemResourceIsAbsolute(t *testing.T) {
	const cwd = "/work/project"
	noEnv := func(string) string { return "" }

	// Each fixture is a tool_input paired with the tool name; cwd is injected
	// uniformly so the emitted resource is deterministic.
	fixtures := []struct {
		tool  string
		input map[string]any
	}{
		// Native file tools with relative paths — the common case Claude Code
		// sends when the user works inside the project directory.
		{"Write", map[string]any{"file_path": "out.go", "content": "package main"}},
		{"Edit", map[string]any{"file_path": "x.go", "old_string": "a", "new_string": "b"}},
		{"MultiEdit", map[string]any{"file_path": "nested/pkg/file.go", "edits": []any{}}},
		{"Read", map[string]any{"file_path": "docs/readme.md"}},
		// Already-absolute path — must pass through unchanged (and still absolute).
		{"Read", map[string]any{"file_path": "/etc/hosts"}},
		// Opportunistically-captured unknown tool carrying a relative file_path.
		{"Move", map[string]any{"file_path": "old.go", "destination": "new.go"}},
		// Bash filesystem mutations with relative operands.
		{"Bash", map[string]any{"command": "rm -rf build"}},
		{"Bash", map[string]any{"command": "mv a.txt b.txt"}},
		{"Bash", map[string]any{"command": "cp src.txt dst.txt"}},
		{"Bash", map[string]any{"command": "echo hi > out.txt"}},
	}

	for _, fx := range fixtures {
		input, err := json.Marshal(fx.input)
		if err != nil {
			t.Fatalf("marshal input: %v", err)
		}
		stdin, err := json.Marshal(map[string]any{
			"hook_event_name": "PostToolUse",
			"session_id":      "gate",
			"cwd":             cwd,
			"tool_name":       fx.tool,
			"tool_input":      json.RawMessage(input),
		})
		if err != nil {
			t.Fatalf("marshal stdin: %v", err)
		}
		ev, _, err := readClaudeCode(stdin, noEnv)
		if err != nil {
			t.Fatalf("readClaudeCode(%s): %v", fx.tool, err)
		}
		// Only fixtures that resolve a filesystem target are in scope; a fixture
		// that yields no target (none here) is simply skipped by the predicate.
		if !filesystemResourceIsAbsolute(ev) {
			t.Errorf("%s %v: emitted relative resource %q; every filesystem resource must be absolute",
				fx.tool, fx.input, ev.Target.Resource)
		}
	}
}

// TestGate_PredicateHasTeeth is the negative control the frozen decision
// requires: the gate must FAIL on a relative-path fixture, not merely pass on
// absolute ones. A gate that can never fire is not a gate. It also pins the
// carve-out: a non-filesystem resource is exempt.
func TestGate_PredicateHasTeeth(t *testing.T) {
	relative := emitter.Event{Target: emitter.Target{System: "filesystem", Resource: "relative/path.go"}}
	if filesystemResourceIsAbsolute(relative) {
		t.Error("gate passed a relative filesystem resource; it must fail so CI catches the regression")
	}

	dotRelative := emitter.Event{Target: emitter.Target{System: "filesystem", Resource: "./out.txt"}}
	if filesystemResourceIsAbsolute(dotRelative) {
		t.Error("gate passed a dot-relative filesystem resource; it must fail")
	}

	absolute := emitter.Event{Target: emitter.Target{System: "filesystem", Resource: "/abs/path.go"}}
	if !filesystemResourceIsAbsolute(absolute) {
		t.Error("gate failed an absolute filesystem resource; it must pass")
	}

	// Carve-out: a non-filesystem resource identifier and an empty target are
	// exempt — "absolute" is undefined for them.
	nonFS := emitter.Event{Target: emitter.Target{System: "mcp", Resource: "issue://123"}}
	if !filesystemResourceIsAbsolute(nonFS) {
		t.Error("gate must exempt non-filesystem resources (carve-out)")
	}
	empty := emitter.Event{Target: emitter.Target{}}
	if !filesystemResourceIsAbsolute(empty) {
		t.Error("gate must exempt an empty target")
	}
}
