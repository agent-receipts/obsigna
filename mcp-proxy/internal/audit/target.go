package audit

import (
	"net/url"
	"strings"
)

// maxResourceLen caps the byte length of an extracted resource string. It
// mirrors the daemon's target_resource cap (Linux PATH_MAX, 4096 bytes): a
// resource longer than this would be rejected by the emitter and drop the whole
// receipt, so ExtractTarget omits the target instead of risking that.
const maxResourceLen = 4096

// maxSystemLen caps the byte length of the system (the MCP server name). It
// mirrors the daemon/emitter identity-field cap (256 bytes) for the same reason
// as maxResourceLen: the emitter rejects an oversized target_system and drops
// the whole receipt, so ExtractTarget omits the target rather than cost the
// audit record. serverName is uncapped where it populates Tool.Server, so a
// value this long is unusual but not impossible.
const maxSystemLen = 256

// uriKeys hold a network/endpoint identifier (HTTP APIs, object stores, message
// queues). Checked first because a URI is the most specific, most stable
// resource an MCP tool can name.
var uriKeys = []string{"url", "uri", "endpoint"}

// tableKeys hold a database table or collection name. A neighbouring
// database/schema/dataset key, when present, qualifies it (e.g. "analytics.events").
var tableKeys = []string{"table", "collection"}

var dbQualifierKeys = []string{"database", "schema", "dataset", "keyspace"}

// genericKeys hold an unambiguously resource-shaped identifier. These trail the
// URI/table/repo tiers because they are coarser, and exclude bare "id"/"name"
// which are too generic to be reliable contention keys.
var genericKeys = []string{"path", "key", "bucket", "object", "resource", "resource_id"}

// ExtractTarget derives an (action.target.system, action.target.resource) pair
// from an MCP tool call so cross-agent contention on shared external state
// (APIs, tables, repos) surfaces the same way shared-file contention does for
// the filesystem hook.
//
// system is always the MCP server name — the service acted upon (spec §6.2).
// resource is extracted opportunistically from the call arguments using an
// ordered set of well-known key shapes:
//
//  1. URI/endpoint (url, uri, endpoint) — canonicalised to scheme://host/path.
//  2. Database table (table, collection), qualified by database/schema if present.
//  3. Version-control repo (owner + repo) — "owner/repo".
//  4. Generic resource keys (path, key, bucket, object, resource, resource_id).
//
// The heuristic is best-effort: a tool whose arguments match none of these
// shapes yields no target ("", ""), exactly as a non-filesystem tool does in
// the hook. Both return values are always set together or both empty, so the
// emitter's all-or-nothing Target rule never trips. A resource longer than
// maxResourceLen is dropped rather than truncated — a truncated identifier
// would be a misleading contention key. An over-long system (server name) is
// dropped for the same reason: a half- or over-populated target would cost the
// whole receipt at the emitter, and a best-effort target must never do that.
// toolName is currently unused (resource is derived from serverName + args);
// it is accepted as `_` so the call site reads as (server, tool, args) and a
// future tool-specific heuristic can use it without a signature change.
func ExtractTarget(serverName, _ string, args map[string]any) (system, resource string) {
	if serverName == "" || len(serverName) > maxSystemLen || len(args) == 0 {
		return "", ""
	}

	res := extractResource(args)
	if res == "" || len(res) > maxResourceLen {
		return "", ""
	}
	return serverName, res
}

// extractResource walks the tier list and returns the first resource shape that
// matches, or "" when none do.
func extractResource(args map[string]any) string {
	if v := firstStringValue(args, uriKeys); v != "" {
		return canonicalURI(v)
	}
	if table := firstStringValue(args, tableKeys); table != "" {
		if qual := firstStringValue(args, dbQualifierKeys); qual != "" {
			return qual + "." + table
		}
		return table
	}
	if repo := repoResource(args); repo != "" {
		return repo
	}
	return firstStringValue(args, genericKeys)
}

// repoResource returns "owner/repo" when both keys carry non-empty string
// values, the canonical resource for version-control MCP servers (github,
// gitlab). Repo-level granularity is intentional: two agents touching the same
// repository contend even when they target different issues or files within it.
func repoResource(args map[string]any) string {
	owner := lookupString(args, "owner")
	repo := lookupString(args, "repo")
	if owner != "" && repo != "" {
		return owner + "/" + repo
	}
	return ""
}

// canonicalURI reduces a URI to scheme://host/path, dropping query and fragment
// so the same endpoint reached with different parameters resolves to one
// resource. A value that does not parse as a URI with both a scheme and a host
// (relative paths, scheme-relative "//host/path", opaque identifiers) cannot be
// safely rebuilt as scheme://host, so it is returned as-is — but with the query
// and fragment still stripped, because those may carry tokens/secrets that must
// never reach the signed, persisted resource string.
func canonicalURI(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return stripQueryFragment(raw)
	}
	host := strings.ToLower(u.Host)
	path := strings.TrimRight(u.Path, "/")
	return strings.ToLower(u.Scheme) + "://" + host + path
}

// stripQueryFragment truncates raw at the first '?' or '#', removing any URL
// query or fragment. Used for endpoint values that don't canonicalise to
// scheme://host so request parameters — which may include secrets — don't leak
// into action.target.resource.
func stripQueryFragment(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	return strings.TrimSpace(raw)
}

// firstStringValue returns the trimmed string value of the first key present
// with a non-empty string value, scanning keys in order.
func firstStringValue(args map[string]any, keys []string) string {
	for _, k := range keys {
		if v := lookupString(args, k); v != "" {
			return v
		}
	}
	return ""
}

// lookupString returns the trimmed string value of the arg whose key matches
// key case-insensitively, or "" when absent or not a non-empty string. MCP
// servers vary in casing ("url", "URL", "Endpoint"), and the rest of this
// package (e.g. classifier.ScoreRisk) already treats argument keys
// case-insensitively, so target extraction matches that convention.
func lookupString(args map[string]any, key string) string {
	for argKey, argVal := range args {
		if strings.EqualFold(argKey, key) {
			return stringValue(argVal)
		}
	}
	return ""
}

// stringValue returns the trimmed string if v is a string, else "". Non-string
// JSON values (numbers, bools, objects) are not usable as a stable resource key.
func stringValue(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}
