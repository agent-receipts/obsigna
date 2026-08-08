package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const redacted = "[REDACTED]"

// sensitiveKeys is the set of JSON object keys (case-insensitive) whose values
// are always replaced with [REDACTED]. Mirrors the proxy's audit.sensitiveKeys.
var sensitiveKeys = map[string]bool{
	"password":          true,
	"token":             true,
	"api_key":           true,
	"apikey":            true,
	"secret":            true,
	"authorization":     true,
	"private_key":       true,
	"privatekey":        true,
	"access_token":      true,
	"refresh_token":     true,
	"client_secret":     true,
	"credentials":       true,
	"session_token":     true,
	"session_id":        true,
	"sessionid":         true,
	"auth_token":        true,
	"cookie":            true,
	"set-cookie":        true,
	"x-api-key":         true,
	"bearer":            true,
	"jwt":               true,
	"signing_key":       true,
	"encryption_key":    true,
	"database_url":      true,
	"connection_string": true,
	"dsn":               true,
	"ssh_key":           true,
	"passphrase":        true,
	"pin":               true,
}

// builtinPatterns is the ordered list of regular-expression patterns the
// default Redactor applies. They are applied after JSON-key redaction.
// Unexported to prevent accidental mutation.
var builtinPatterns = []namedPattern{
	{
		name: "github-pat-classic",
		re:   regexp.MustCompile(`ghp_[A-Za-z0-9]{36,}`),
	},
	{
		name: "github-pat-finegrained",
		re:   regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`),
	},
	{
		name: "github-oauth",
		re:   regexp.MustCompile(`gho_[A-Za-z0-9]{36,}`),
	},
	{
		name: "github-app-installation",
		re:   regexp.MustCompile(`ghs_[A-Za-z0-9]{36,}`),
	},
	{
		name: "github-user-to-server",
		re:   regexp.MustCompile(`ghu_[A-Za-z0-9]{36,}`),
	},
	{
		name: "github-installation-legacy",
		re:   regexp.MustCompile(`v1\.[a-f0-9]{40,}`),
	},
	{
		name: "openai-anthropic-key",
		re:   regexp.MustCompile(`sk-[A-Za-z0-9\-]{20,}`),
	},
	{
		name: "aws-access-key",
		re:   regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
	},
	{
		name: "bearer-token",
		re:   regexp.MustCompile(`Bearer\s+[A-Za-z0-9._\-/+=]{20,}`),
	},
	{
		// JWT: three base64url segments separated by dots. Both the header
		// and payload are base64url-encoded JSON objects, which always begin
		// with `eyJ` (the encoding of `{"`). Anchoring both of the first two
		// segments to `eyJ` keeps the pattern specific to JWTs and avoids
		// matching arbitrary dotted base64 strings. The signature segment may
		// be empty for unsigned (alg=none) JWTs.
		name: "jwt",
		re:   regexp.MustCompile(`eyJ[A-Za-z0-9_=\-]+\.eyJ[A-Za-z0-9_=\-]+\.[A-Za-z0-9_=\-]*`),
	},
	{
		name: "slack-token",
		re:   regexp.MustCompile(`xox[bpras]-[A-Za-z0-9\-]+`),
	},
	{
		name: "pem-private-key",
		re:   regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----`),
	},
	{
		// Exclude `[` and `]` so that already-redacted placeholders like
		// `[REDACTED]` are not re-matched (makes Redact idempotent).
		name: "url-param-token",
		re:   regexp.MustCompile(`(?i)([?&](?:access_token|token|api[_-]?key|apikey|key|auth)=)[^&\s"'<>\[\]]+`),
	},
}

type namedPattern struct {
	name string
	re   *regexp.Regexp
}

// Redactor applies JSON-key redaction and pattern-based redaction to strings.
// Custom patterns (from a YAML file) are applied after the built-in patterns.
type Redactor struct {
	custom []*regexp.Regexp
}

// NewRedactor creates a Redactor. custom patterns are applied after the
// built-in patterns; pass nil for built-ins only.
func NewRedactor(custom []*regexp.Regexp) *Redactor {
	return &Redactor{custom: custom}
}

// Redact applies three redaction passes to raw:
//  1. JSON-aware key redaction (sensitiveKeys) — only when raw is valid JSON.
//  2. Built-in regex patterns (builtinPatterns).
//  3. Custom patterns supplied at construction time.
//
// The url-param-token built-in uses a capture-group replacement to preserve
// the key name (e.g. "token=") while replacing only the value.
func (r *Redactor) Redact(raw string) string {
	// 1. JSON-aware key redaction.
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
		if b, err := json.Marshal(redactJSONValue(parsed)); err == nil {
			raw = string(b)
		}
	}

	// 2. Built-in patterns.
	for _, p := range builtinPatterns {
		if p.name == "url-param-token" {
			raw = p.re.ReplaceAllString(raw, "${1}"+redacted)
		} else {
			raw = p.re.ReplaceAllString(raw, redacted)
		}
	}

	// 3. Custom patterns.
	for _, re := range r.custom {
		raw = re.ReplaceAllString(raw, redacted)
	}

	return raw
}

// RedactIfSet applies Redact when r is non-nil, and returns raw unchanged
// when it is nil — the "no Redactor configured" case every call site would
// otherwise have to guard against individually.
func (r *Redactor) RedactIfSet(raw string) string {
	if r == nil {
		return raw
	}
	return r.Redact(raw)
}

func redactJSONValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, child := range val {
			if sensitiveKeys[strings.ToLower(k)] {
				out[k] = redacted
			} else {
				out[k] = redactJSONValue(child)
			}
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = redactJSONValue(item)
		}
		return out
	default:
		return v
	}
}

// patternFile is the YAML structure for the redact-patterns file.
type patternFile struct {
	Patterns []patternEntry `yaml:"patterns"`
}

type patternEntry struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
}

// LoadPatternFile reads a YAML file of additional redaction patterns and
// returns compiled *regexp.Regexp values ready to pass to NewRedactor.
//
// The file format is:
//
//	patterns:
//	  - name: my-secret
//	    pattern: 'MY_SECRET_[A-Z0-9]+'
//
// Every entry requires a non-empty name and a non-empty, valid Go regex.
func LoadPatternFile(path string) ([]*regexp.Regexp, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var pf patternFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := make([]*regexp.Regexp, 0, len(pf.Patterns))
	for i, p := range pf.Patterns {
		if p.Name == "" {
			return nil, fmt.Errorf("pattern %d in %s: name is required", i, path)
		}
		if strings.TrimSpace(p.Pattern) == "" {
			return nil, fmt.Errorf("pattern %q in %s: pattern is required", p.Name, path)
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("pattern %q in %s: invalid regex: %w", p.Name, path, err)
		}
		out = append(out, re)
	}
	return out, nil
}
