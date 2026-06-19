package main

import (
	"encoding/json"
	"testing"
)

// TestExtractBashTarget covers the common filesystem-mutating shapes the parser
// must classify, plus the non-extractable cases that must fall back cleanly
// (empty system/resource/action), preserving coverage-fraction honesty.
func TestExtractBashTarget(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantSys    string
		wantRes    string
		wantAction string
	}{
		// --- deletes ---
		{
			name:       "rm single file → delete/high",
			command:    "rm notes.txt",
			wantSys:    "filesystem",
			wantRes:    "notes.txt",
			wantAction: actionFileDelete,
		},
		{
			name:       "rm -rf dir → delete/high",
			command:    "rm -rf build",
			wantSys:    "filesystem",
			wantRes:    "build",
			wantAction: actionFileDelete,
		},
		{
			name:       "rm with -- before operand",
			command:    "rm -- -weird-name",
			wantSys:    "filesystem",
			wantRes:    "-weird-name",
			wantAction: actionFileDelete,
		},
		{
			name:    "rm of multiple files is not a single honest target",
			command: "rm a.txt b.txt",
		},
		{
			name:    "rm with no operand",
			command: "rm -rf",
		},
		// --- moves ---
		{
			name:       "mv a b → move/target is dest",
			command:    "mv old.txt new.txt",
			wantSys:    "filesystem",
			wantRes:    "new.txt",
			wantAction: actionFileMove,
		},
		{
			name:       "mv with flag",
			command:    "mv -f src/app dst/app",
			wantSys:    "filesystem",
			wantRes:    "dst/app",
			wantAction: actionFileMove,
		},
		{
			name:    "mv with only one operand",
			command: "mv solo.txt",
		},
		// --- copies ---
		{
			name:       "cp a b → create/target is dest",
			command:    "cp src.txt dst.txt",
			wantSys:    "filesystem",
			wantRes:    "dst.txt",
			wantAction: actionFileCreate,
		},
		{
			name:       "cp -r dir dest",
			command:    "cp -r ./srcdir ./destdir",
			wantSys:    "filesystem",
			wantRes:    "./destdir",
			wantAction: actionFileCreate,
		},
		// --- redirects ---
		{
			name:       "echo > file → create",
			command:    "echo hello > out.txt",
			wantSys:    "filesystem",
			wantRes:    "out.txt",
			wantAction: actionFileCreate,
		},
		{
			name:       "append >> file → create",
			command:    "printf x >> log.txt",
			wantSys:    "filesystem",
			wantRes:    "log.txt",
			wantAction: actionFileCreate,
		},
		{
			name:    "fd-prefixed redirect is not classified",
			command: "cmd 2> err.txt",
		},
		{
			name:    "redirect chained with a destructive sibling is not claimed",
			command: "echo x > out.txt; rm secret",
		},
		{
			name:    "redirect to fd duplication is not classified",
			command: "cmd >&2",
		},
		// --- quoted paths ---
		{
			name:       "rm of quoted path with spaces",
			command:    `rm "my file.txt"`,
			wantSys:    "filesystem",
			wantRes:    "my file.txt",
			wantAction: actionFileDelete,
		},
		{
			name:       "redirect to quoted path",
			command:    `echo x > "a b.txt"`,
			wantSys:    "filesystem",
			wantRes:    "a b.txt",
			wantAction: actionFileCreate,
		},
		// --- non-extractable: fall back cleanly ---
		{
			name:    "glob target not claimed",
			command: "rm *.log",
		},
		{
			name:    "tilde expansion not claimed",
			command: "rm ~/cache",
		},
		{
			name:    "variable expansion not claimed",
			command: "rm $TARGET",
		},
		{
			name:    "command substitution not claimed",
			command: "rm $(find . -name '*.tmp')",
		},
		{
			name:    "pipe not claimed",
			command: "cat x | rm y",
		},
		{
			name:    "chained command not claimed",
			command: "cd /tmp && rm junk",
		},
		{
			name:    "semicolon chain not claimed",
			command: "echo hi; rm a",
		},
		{
			name:    "non-mutating command ignored",
			command: "go test ./...",
		},
		{
			name:    "ls is not a mutation",
			command: "ls -la /tmp",
		},
		{
			name:    "empty command",
			command: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input, err := json.Marshal(map[string]string{"command": tc.command})
			if err != nil {
				t.Fatalf("marshal input: %v", err)
			}
			sys, res, action := extractBashTarget(json.RawMessage(input))
			if sys != tc.wantSys {
				t.Errorf("system = %q; want %q", sys, tc.wantSys)
			}
			if res != tc.wantRes {
				t.Errorf("resource = %q; want %q", res, tc.wantRes)
			}
			if action != tc.wantAction {
				t.Errorf("actionType = %q; want %q", action, tc.wantAction)
			}
		})
	}
}

// TestExtractBashTarget_MalformedInput verifies malformed or missing input
// falls back silently rather than panicking or claiming a target.
func TestExtractBashTarget_MalformedInput(t *testing.T) {
	cases := []json.RawMessage{
		json.RawMessage(``),
		json.RawMessage(`{bad json`),
		json.RawMessage(`{"command": 123}`),
		json.RawMessage(`{"not_command": "rm x"}`),
		json.RawMessage(`{}`),
	}
	for _, in := range cases {
		sys, res, action := extractBashTarget(in)
		if sys != "" || res != "" || action != "" {
			t.Errorf("extractBashTarget(%s) = (%q,%q,%q); want all empty", in, sys, res, action)
		}
	}
}

// TestExtractBashTarget_RiskMapping documents that the action types returned
// are the ones the taxonomy maps to non-default risk. The hook returns the
// taxonomy type; the daemon resolves risk from it. Asserting the constants here
// guards against an accidental rename that would silently drop the call back to
// UnknownAction (medium) risk.
func TestExtractBashTarget_RiskMapping(t *testing.T) {
	if actionFileDelete != "filesystem.file.delete" {
		t.Errorf("delete action type drifted: %q", actionFileDelete)
	}
	if actionFileMove != "filesystem.file.move" {
		t.Errorf("move action type drifted: %q", actionFileMove)
	}
	if actionFileCreate != "filesystem.file.create" {
		t.Errorf("create action type drifted: %q", actionFileCreate)
	}
}
