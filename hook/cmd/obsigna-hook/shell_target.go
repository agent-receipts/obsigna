package main

import (
	"encoding/json"
	"strings"
)

// Taxonomy action types for filesystem mutations. These mirror the entries in
// sdk/go/taxonomy so the daemon resolves a real risk level from action.type
// (delete → high, move/copy/create → medium/low) instead of defaulting to the
// UnknownAction medium risk a synthetic "claude-code.Bash" type would yield.
const (
	actionFileDelete = "filesystem.file.delete"
	actionFileMove   = "filesystem.file.move"
	actionFileCreate = "filesystem.file.create"
)

// shellMetacharacters are control operators and expansion triggers that make a
// command line impossible to classify with confidence: the target path may be
// the result of a pipe, a substitution, a variable, or one of several chained
// commands. When any appear in the command we decline to extract a target
// rather than guess — preserving the coverage-fraction honesty the codebase
// already uses for native tools.
const shellMetacharacters = "|;&\n`$()<{}"

// chainMetacharacters are the control operators that mean a command line runs
// more than one command (pipe, sequence, background, substitution, here-doc).
// A redirect target is only authoritative when none of these appear: otherwise
// `... > out.txt; rm secret` would report the harmless write and mask the
// destructive delete. It omits `>` so the redirect operator itself is allowed.
const chainMetacharacters = "|;&\n`$(){}"

// pathExpansionChars mark a single operand whose final value is decided by the
// shell, not the literal token: globs (*, ?, [) and home expansion (~). A path
// containing any of these cannot be reported verbatim, so we skip extraction.
const pathExpansionChars = "*?[~"

// extractBashTarget attempts to classify a Bash tool call as a filesystem
// mutation and return its target. It handles the common, unambiguous shapes:
//
//   - rm FILE / rm -rf DIR        → filesystem.file.delete
//   - mv SRC DST                  → filesystem.file.move (target = DST)
//   - cp SRC DST                  → filesystem.file.create (target = DST)
//   - CMD > FILE / CMD >> FILE    → filesystem.file.create (target = FILE)
//
// It is deliberately conservative. When the command contains shell control
// operators, command substitution, variable expansion, globs, or anything else
// whose effective target the shell — not the literal tokens — decides, it
// returns ("", "", "") so the caller falls back to current behaviour (no
// target, default risk). It never claims a target it did not parse.
//
// On a confident match it returns ("filesystem", path, actionType); the caller
// sets ev.Target and ev.ActionType from these. actionType is one of the
// taxonomy filesystem types so the daemon resolves the real risk level.
func extractBashTarget(input json.RawMessage) (system, resource, actionType string) {
	if len(input) == 0 {
		return "", "", ""
	}
	var inp struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(input, &inp); err != nil {
		return "", "", ""
	}
	cmd := strings.TrimSpace(inp.Command)
	if cmd == "" {
		return "", "", ""
	}

	// A redirect target is unambiguous even when the left-hand command is
	// arbitrary (`echo x > file`), so check redirects before bailing on the
	// metacharacter scan — but only when the line runs a single command. With
	// a chain operator present (`... > out.txt; rm secret`) the redirect would
	// report the harmless write and mask a destructive sibling, so we decline.
	// We also accept only a single redirect with a literal operand; anything
	// fancier (fd duplication, here-docs, multiple redirects) falls through.
	if !strings.ContainsAny(cmd, chainMetacharacters) {
		if path, ok := redirectTarget(cmd); ok {
			return "filesystem", path, actionFileCreate
		}
	}

	// Beyond redirects, classification requires a single, self-contained
	// command. Any control operator or expansion trigger means the literal
	// tokens may not be the real target — decline rather than guess.
	if strings.ContainsAny(cmd, shellMetacharacters) {
		return "", "", ""
	}

	fields := splitFields(cmd)
	if len(fields) == 0 {
		return "", "", ""
	}

	switch fields[0] {
	case "rm":
		if path, ok := singleOperand(fields[1:]); ok {
			return "filesystem", path, actionFileDelete
		}
	case "mv":
		if path, ok := lastOperand(fields[1:]); ok {
			return "filesystem", path, actionFileMove
		}
	case "cp":
		if path, ok := lastOperand(fields[1:]); ok {
			return "filesystem", path, actionFileCreate
		}
	}
	return "", "", ""
}

// redirectTarget returns the file written by a single output redirect (> or >>)
// when the operand is a literal path. It returns ok=false when there is no
// redirect, more than one, or the operand is missing/expandable. fd-prefixed
// redirects (e.g. `2>file`) are intentionally not matched: they are rare in
// agent commands and ambiguous to classify.
func redirectTarget(cmd string) (string, bool) {
	idx := strings.Index(cmd, ">")
	if idx < 0 {
		return "", false
	}
	// Reject an fd-duplication or fd-prefixed redirect (`>&`, `2>`): the
	// character before > is part of the operator, not a clean stdout redirect.
	if idx > 0 {
		prev := cmd[idx-1]
		if prev >= '0' && prev <= '9' {
			return "", false
		}
	}
	rest := cmd[idx+1:]
	rest = strings.TrimPrefix(rest, ">") // collapse >> to the same handling
	// A second redirect operator anywhere means we cannot pick one target.
	if strings.Contains(rest, ">") {
		return "", false
	}
	if strings.HasPrefix(rest, "&") {
		return "", false
	}
	operand := strings.TrimSpace(rest)
	fields := splitFields(operand)
	if len(fields) != 1 {
		return "", false
	}
	return cleanPath(fields[0])
}

// singleOperand returns the sole non-flag operand from args, or ok=false when
// there is not exactly one (zero operands, or several — `rm a b` mutates two
// paths and a single Target cannot honestly represent both).
func singleOperand(args []string) (string, bool) {
	operands := operandsOnly(args)
	if len(operands) != 1 {
		return "", false
	}
	return cleanPath(operands[0])
}

// lastOperand returns the final non-flag operand — the destination for mv/cp.
// It requires at least two operands (a source and a destination); a single
// operand means the command is incomplete and not worth classifying.
func lastOperand(args []string) (string, bool) {
	operands := operandsOnly(args)
	if len(operands) < 2 {
		return "", false
	}
	return cleanPath(operands[len(operands)-1])
}

// operandsOnly drops flag tokens (leading "-"). A bare "--" ends option
// parsing; everything after it is an operand. "-" alone (stdin/stdout) is
// treated as a flag-like token and dropped.
func operandsOnly(args []string) []string {
	var out []string
	endOpts := false
	for _, a := range args {
		if !endOpts {
			if a == "--" {
				endOpts = true
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

// cleanPath unquotes a single literal operand and rejects it when the value is
// still shell-dependent (glob/tilde, or it expanded to empty). ok=false signals
// the caller to skip extraction.
func cleanPath(tok string) (string, bool) {
	p := unquote(tok)
	if p == "" {
		return "", false
	}
	if strings.ContainsAny(p, pathExpansionChars) {
		return "", false
	}
	return p, true
}

// splitFields splits a command into whitespace-separated tokens, honouring
// single and double quotes so a quoted path with spaces stays one token. It is
// a minimal shell-word splitter, not a full parser: the metacharacter scan in
// extractBashTarget has already excluded the inputs it could not handle.
func splitFields(s string) []string {
	var fields []string
	var cur strings.Builder
	inSingle, inDouble := false, false
	started := false
	flush := func() {
		if started {
			fields = append(fields, cur.String())
			cur.Reset()
			started = false
		}
	}
	for _, r := range s {
		switch {
		case inSingle:
			if r == '\'' {
				inSingle = false
			} else {
				cur.WriteRune(r)
			}
		case inDouble:
			if r == '"' {
				inDouble = false
			} else {
				cur.WriteRune(r)
			}
		case r == '\'':
			inSingle = true
			started = true
		case r == '"':
			inDouble = true
			started = true
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	flush()
	return fields
}

// unquote strips a single matched pair of surrounding quotes from a token that
// splitFields kept whole. splitFields already removes interior quotes, so this
// is a defensive no-op for tokens it produced; it stays for callers passing raw
// operands (e.g. a redirect operand lifted before field splitting).
func unquote(tok string) string {
	if len(tok) >= 2 {
		if (tok[0] == '\'' && tok[len(tok)-1] == '\'') ||
			(tok[0] == '"' && tok[len(tok)-1] == '"') {
			return tok[1 : len(tok)-1]
		}
	}
	return tok
}
