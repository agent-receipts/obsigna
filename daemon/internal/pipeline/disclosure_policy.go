package pipeline

import (
	"fmt"
	"sort"
	"strings"

	"obsigna.dev/sdk/go/receipt"
)

// DisclosurePolicy decides whether a given action's parameters are encrypted
// into the parameters_disclosure envelope. It mirrors the operator-facing value
// space documented for the OpenClaw plugin's parameterDisclosure setting:
// false | true | "high" | string[] (ADR-0012).
//
// The policy only governs *which* actions disclose; it is independent of whether
// a forensic public key is configured. With no key, nothing can be encrypted
// regardless of policy (the pipeline falls back to hash-only).
type DisclosurePolicy struct {
	mode      disclosureMode
	allowlist map[string]struct{}
}

type disclosureMode int

const (
	// disclosureOff discloses nothing — hash-only, the privacy-preserving default.
	disclosureOff disclosureMode = iota
	// disclosureAll discloses every action's parameters.
	disclosureAll
	// disclosureHigh discloses only high- and critical-risk actions.
	disclosureHigh
	// disclosureAllowlist discloses only the action types named in allowlist.
	disclosureAllowlist
)

// ParseDisclosurePolicy parses an operator-supplied policy string into a
// DisclosurePolicy. Accepted forms (case-insensitive for the keywords):
//
//   - "" / "false" / "off" / "0" → disclose nothing (default)
//   - "true" / "all" / "1"       → disclose all actions
//   - "high"                      → disclose high- and critical-risk actions
//   - comma-separated list        → disclose only those action types
//     (e.g. "system.command.execute,filesystem.file.delete")
//
// "1" and "0" are accepted as legacy boolean spellings (previously the env var
// was parsed with strconv.ParseBool) so existing configs upgrade cleanly.
//
// A list entry equal to one of the reserved keywords is rejected, so an operator
// cannot accidentally smuggle "all" into an allowlist and disclose everything.
func ParseDisclosurePolicy(s string) (DisclosurePolicy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "false", "off", "0":
		return DisclosurePolicy{mode: disclosureOff}, nil
	case "true", "all", "1":
		return DisclosurePolicy{mode: disclosureAll}, nil
	case "high":
		return DisclosurePolicy{mode: disclosureHigh}, nil
	}

	// Anything else is treated as a comma-separated allowlist of action types.
	allow := make(map[string]struct{})
	for _, raw := range strings.Split(s, ",") {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			return DisclosurePolicy{}, fmt.Errorf("disclosure policy %q: empty action type in list", s)
		}
		switch strings.ToLower(tok) {
		case "true", "false", "all", "off", "high", "0", "1":
			return DisclosurePolicy{}, fmt.Errorf(
				"disclosure policy %q: reserved keyword %q cannot appear in an action-type allowlist", s, tok)
		}
		allow[tok] = struct{}{}
	}
	if len(allow) == 0 {
		return DisclosurePolicy{}, fmt.Errorf("disclosure policy %q: no action types", s)
	}
	return DisclosurePolicy{mode: disclosureAllowlist, allowlist: allow}, nil
}

// ShouldDisclose reports whether parameters for an action of the given type and
// risk level should be encrypted under this policy.
func (p DisclosurePolicy) ShouldDisclose(actionType string, risk receipt.RiskLevel) bool {
	switch p.mode {
	case disclosureAll:
		return true
	case disclosureHigh:
		return risk == receipt.RiskHigh || risk == receipt.RiskCritical
	case disclosureAllowlist:
		_, ok := p.allowlist[actionType]
		return ok
	default: // disclosureOff
		return false
	}
}

// Enabled reports whether the policy discloses anything at all. Used at startup
// to decide whether a forensic public key is required.
func (p DisclosurePolicy) Enabled() bool {
	return p.mode != disclosureOff
}

// String renders the policy for logging in a form that round-trips through
// ParseDisclosurePolicy.
func (p DisclosurePolicy) String() string {
	switch p.mode {
	case disclosureAll:
		return "all"
	case disclosureHigh:
		return "high"
	case disclosureAllowlist:
		types := make([]string, 0, len(p.allowlist))
		for t := range p.allowlist {
			types = append(types, t)
		}
		// Sort for a stable rendering — the allowlist is map-backed, so without
		// this the startup log and printed config would vary across runs.
		sort.Strings(types)
		return strings.Join(types, ",")
	default:
		return "off"
	}
}
