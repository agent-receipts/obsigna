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

// forbiddenOps are unquoted shell metacharacters that make a command line
// impossible to classify with confidence: the effective target may be the
// result of a pipe, a substitution, a variable, an input redirect, or one of
// several chained commands. When the lexer meets any of these outside quotes it
// declines, preserving the coverage-fraction honesty the codebase already uses
// for native tools. Output redirects ('>') are handled separately, not here.
const forbiddenOps = "|;&<(){}$`\n"

// pathExpansionChars mark a single operand whose final value is decided by the
// shell, not the literal token: globs (*, ?, [) and home expansion (~). A path
// containing any of these cannot be reported verbatim, so we skip extraction.
const pathExpansionChars = "*?[~"

// tokenKind distinguishes a literal word from an output-redirect operator.
type tokenKind int

const (
	kindWord tokenKind = iota
	kindRedirect
)

type token struct {
	kind tokenKind
	text string
}

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
// A mutating verb takes precedence over a redirect: `rm foo > log` is the
// delete of foo (high risk), not a create of log — otherwise the redirect would
// mask the destructive command and downgrade its risk.
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

	tokens, ok := lex(cmd)
	if !ok || len(tokens) == 0 {
		return "", "", ""
	}

	// Separate the word tokens from a single output redirect and its operand.
	// More than one redirect, or a redirect with no literal operand, is too
	// ambiguous to classify.
	var words []string
	redirCount := 0
	redirTarget := ""
	for i := 0; i < len(tokens); i++ {
		if tokens[i].kind != kindRedirect {
			words = append(words, tokens[i].text)
			continue
		}
		redirCount++
		if i+1 >= len(tokens) || tokens[i+1].kind != kindWord {
			return "", "", ""
		}
		redirTarget = tokens[i+1].text
		i++ // consume the operand
	}
	if redirCount > 1 {
		return "", "", ""
	}

	// A mutating verb wins over the redirect: classify by the verb so a
	// destructive command keeps its real risk even when its output is redirected.
	if len(words) > 0 {
		switch words[0] {
		case "rm":
			if path, ok := singleOperand(words[1:]); ok {
				return "filesystem", path, actionFileDelete
			}
			return "", "", ""
		case "mv":
			if path, ok := lastOperand(words[1:]); ok {
				return "filesystem", path, actionFileMove
			}
			return "", "", ""
		case "cp":
			if path, ok := lastOperand(words[1:]); ok {
				return "filesystem", path, actionFileCreate
			}
			return "", "", ""
		}
	}

	// No mutating verb: a lone output redirect creates/truncates its target.
	if redirCount == 1 {
		if path, ok := cleanPath(redirTarget); ok {
			return "filesystem", path, actionFileCreate
		}
	}
	return "", "", ""
}

// lex splits a single shell command into word and output-redirect tokens,
// honouring single and double quotes so a quoted metacharacter (`"a > b"`,
// `"x;y"`) is part of a word, never an operator. It returns ok=false when the
// command contains a construct we refuse to classify: an unquoted forbidden
// operator (pipe, chain, substitution, input redirect, brace/paren group), an
// fd-prefixed or fd-duplicating redirect (`2>`, `>&`), a tripled redirect, or
// an unterminated quote. Quotes are stripped from the emitted word text.
func lex(s string) ([]token, bool) {
	var tokens []token
	var cur strings.Builder
	started := false
	inSingle, inDouble := false, false
	flush := func() {
		if started {
			tokens = append(tokens, token{kindWord, cur.String()})
			cur.Reset()
			started = false
		}
	}

	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
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
		case r == '>':
			// An fd-prefixed redirect (`2>file`) glues digits to '>': the
			// pending word is all digits with no separating space. Decline.
			if started && isAllDigits(cur.String()) {
				return nil, false
			}
			flush()
			if i+1 < len(runes) && runes[i+1] == '>' {
				i++ // collapse '>>' to the same redirect
			}
			// A further '>' (tripled) or '&' (fd duplication, `>&2`) is not a
			// clean output redirect to a literal file.
			if i+1 < len(runes) && (runes[i+1] == '>' || runes[i+1] == '&') {
				return nil, false
			}
			tokens = append(tokens, token{kindRedirect, ">"})
		case strings.ContainsRune(forbiddenOps, r):
			return nil, false
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if inSingle || inDouble {
		return nil, false // unterminated quote
	}
	flush()
	return tokens, true
}

// isAllDigits reports whether s is non-empty and every byte is an ASCII digit.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
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

// cleanPath rejects a literal operand when its value is still shell-dependent
// (glob/tilde) or empty. The lexer has already stripped quotes, so the token is
// the literal path. ok=false signals the caller to skip extraction.
func cleanPath(tok string) (string, bool) {
	if tok == "" {
		return "", false
	}
	if strings.ContainsAny(tok, pathExpansionChars) {
		return "", false
	}
	return tok, true
}
