package receipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// marshalNoHTMLEscape serialises v to JSON without HTML-escaping <, >, or &.
// Go's encoding/json.Marshal HTML-escapes those characters by default; RFC 8785
// requires verbatim emission.
func marshalNoHTMLEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("encode json (no html escape): %w", err)
	}
	// Encode appends a trailing newline; strip it.
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return b, nil
}

// SHA256Hash computes the SHA-256 hash of data and returns "sha256:<hex>".
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
func SHA256Hash(data string) string {
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("sha256:%x", h)
}

// HashReceipt computes the SHA-256 hash of a signed receipt (excluding proof).
// Returns the hash in "sha256:<hex>" format.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
func HashReceipt(r AgentReceipt) (string, error) {
	unsigned := UnsignedAgentReceipt{
		Context:           r.Context,
		ID:                r.ID,
		Type:              r.Type,
		Version:           r.Version,
		Issuer:            r.Issuer,
		IssuanceDate:      r.IssuanceDate,
		CredentialSubject: r.CredentialSubject,
	}
	canonical, err := Canonicalize(unsigned)
	if err != nil {
		return "", fmt.Errorf("canonicalize receipt: %w", err)
	}
	return SHA256Hash(canonical), nil
}

// HashRawReceipt computes the canonical SHA-256 hash of a receipt directly
// from its on-wire JSON bytes, without round-tripping through the Go struct.
//
// This is the hash form auditors and forward-compat receivers should use:
// it preserves every JSON field present on the wire, including ones the
// current Go struct does not know about. HashReceipt, by contrast, hashes a
// re-marshal of the struct, so any field added by a newer SDK gets dropped
// before the hash is computed — meaning a collector running an older SDK
// would store a hash that diverges from what the agent (and any auditor
// looking at the raw bytes) sees.
//
// The proof block is stripped before hashing, matching HashReceipt's
// "unsigned receipt" hashing scheme. Both top-level field ordering and
// nested field ordering are handled by Canonicalize per RFC 8785.
//
// Returns an error if rawJSON is not a JSON object.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
func HashRawReceipt(rawJSON []byte) (string, error) {
	var generic map[string]any
	if err := json.Unmarshal(rawJSON, &generic); err != nil {
		return "", fmt.Errorf("unmarshal raw receipt: %w", err)
	}
	// json.Unmarshal of "null" into *map sets generic to nil rather than
	// failing — reject explicitly so we don't silently hash an empty object.
	if generic == nil {
		return "", fmt.Errorf("raw receipt is not a JSON object")
	}
	delete(generic, "proof")
	canonical, err := Canonicalize(generic)
	if err != nil {
		return "", fmt.Errorf("canonicalize raw receipt: %w", err)
	}
	return SHA256Hash(canonical), nil
}

// Canonicalize serialises v to RFC 8785 canonical JSON.
//
// Deprecated: github.com/agent-receipts/sdk-go is no longer maintained. Use the canonical module obsigna.dev/sdk/go instead (see ADR-0023).
func Canonicalize(v any) (string, error) {
	// Marshal to JSON first so we work with a generic representation.
	// We need to avoid html-escaping here too. Use a custom approach:
	// marshal to get a JSON intermediate, then unmarshal to a generic tree.
	raw, err := marshalNoHTMLEscape(v)
	if err != nil {
		return "", fmt.Errorf("marshal without html-escape: %w", err)
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return "", fmt.Errorf("unmarshal canonical intermediate: %w", err)
	}
	return canonicalizeValue(generic)
}

func canonicalizeValue(v any) (string, error) {
	if v == nil {
		return "null", nil
	}
	switch val := v.(type) {
	case bool:
		if val {
			return "true", nil
		}
		return "false", nil
	case float64:
		return canonicalizeNumber(val)
	case string:
		return canonicalizeString(val), nil
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			s, err := canonicalizeValue(item)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case map[string]any:
		// RFC 8785 §3.2.3: sort by UTF-16 code-unit order, not UTF-8 byte order.
		// Precompute UTF-16 code units once per key to avoid O(n log n) allocations
		// inside the comparator.
		type keyEntry struct {
			s     string
			units []uint16
		}
		entries := make([]keyEntry, 0, len(val))
		for k := range val {
			entries = append(entries, keyEntry{s: k, units: utf16.Encode([]rune(k))})
		}
		sort.Slice(entries, func(i, j int) bool {
			return utf16UnitsLess(entries[i].units, entries[j].units)
		})

		parts := make([]string, 0, len(val))
		for _, e := range entries {
			keyStr := canonicalizeString(e.s)
			valStr, err := canonicalizeValue(val[e.s])
			if err != nil {
				return "", err
			}
			parts = append(parts, keyStr+":"+valStr)
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	default:
		return "", fmt.Errorf("unsupported type: %T", v)
	}
}

// utf16UnitsLess reports whether a sorts before b in UTF-16 code-unit order,
// as required by RFC 8785 §3.2.3.
func utf16UnitsLess(a, b []uint16) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// canonicalizeString serialises a Go string to its RFC 8785 JSON form.
// RFC 8785 requires minimal escaping per ES6 JSON.stringify:
//   - U+0022 (") → \"
//   - U+005C (\) → \\
//   - U+0000–U+001F → \uXXXX (with named shortcuts for \b \t \n \f \r)
//
// Notably, <, >, and & are NOT escaped (unlike Go's encoding/json default).
// U+2028 and U+2029 are NOT escaped (ES6 behaviour, not ES5).
func canonicalizeString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x0020 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// canonicalizeNumber formats a float64 according to RFC 8785 §3.2.2.3,
// which mandates the ECMAScript Number.prototype.toString() algorithm.
// This matches the TypeScript SDK's use of String(n).
func canonicalizeNumber(n float64) (string, error) {
	if math.IsNaN(n) || math.IsInf(n, 0) {
		return "", fmt.Errorf("non-finite number: %v", n)
	}
	// -0 must serialize as "0" per RFC 8785.
	if n == 0 {
		return "0", nil
	}
	return es6NumberToString(n), nil
}

// es6NumberToString replicates the ECMAScript Number::toString algorithm
// (ECMA-262 §6.1.6.1.20) which RFC 8785 mandates for number serialization.
//
// The algorithm uses the shortest decimal representation that round-trips
// to the same float64, then applies exponential notation when the exponent
// is < -6 or >= 21.
func es6NumberToString(n float64) string {
	if n < 0 {
		return "-" + es6NumberToString(-n)
	}

	// Use 'e' format to get the shortest significand and exponent.
	// strconv.FormatFloat with 'e' and prec=-1 gives the shortest
	// representation in scientific notation: d.dddde±dd
	s := strconv.FormatFloat(n, 'e', -1, 64)

	// Parse the mantissa and exponent from the string.
	eIdx := strings.IndexByte(s, 'e')
	mantissa := s[:eIdx]
	expStr := s[eIdx+1:]
	exp, _ := strconv.Atoi(expStr)

	// Split mantissa into integer and fractional digits.
	// mantissa is either "d" or "d.ddd"
	var digits string
	if dotIdx := strings.IndexByte(mantissa, '.'); dotIdx >= 0 {
		digits = mantissa[:dotIdx] + mantissa[dotIdx+1:]
	} else {
		digits = mantissa
	}

	// k = number of significant digits, e = exponent+1 (position of decimal)
	k := len(digits)
	e := exp + 1 // e is the power such that the value is 0.digits * 10^e

	// ECMAScript rules for choosing notation:
	if e >= 1 && e <= 21 {
		if k <= e {
			// Integer that fits without exponential: append zeros.
			return digits + strings.Repeat("0", e-k)
		}
		// Decimal point within the digits: d.ddd
		return digits[:e] + "." + digits[e:]
	}
	if e >= -5 && e <= 0 {
		// Small number: 0.000ddd
		return "0." + strings.Repeat("0", -e) + digits
	}

	// Exponential notation.
	var mantissaPart string
	if k == 1 {
		mantissaPart = digits
	} else {
		mantissaPart = digits[:1] + "." + digits[1:]
	}
	expVal := e - 1
	if expVal > 0 {
		return mantissaPart + "e+" + strconv.Itoa(expVal)
	}
	return mantissaPart + "e-" + strconv.Itoa(-expVal)
}
