package audit

import (
	"strings"
	"testing"
)

func TestExtractTarget(t *testing.T) {
	tests := []struct {
		name         string
		server       string
		tool         string
		args         map[string]any
		wantSystem   string
		wantResource string
	}{
		// URI tier.
		{
			name:         "url canonicalised, query and fragment dropped",
			server:       "fetch",
			tool:         "get_page",
			args:         map[string]any{"url": "https://API.Example.com/v1/users?page=2#top"},
			wantSystem:   "fetch",
			wantResource: "https://api.example.com/v1/users",
		},
		{
			name:         "uri with trailing slash trimmed",
			server:       "http",
			tool:         "call",
			args:         map[string]any{"uri": "https://example.com/orders/"},
			wantSystem:   "http",
			wantResource: "https://example.com/orders",
		},
		{
			name:         "non-http uri keeps scheme and host",
			server:       "s3",
			tool:         "get_object",
			args:         map[string]any{"endpoint": "s3://my-bucket/path/to/key"},
			wantSystem:   "s3",
			wantResource: "s3://my-bucket/path/to/key",
		},
		{
			name:         "scheme-relative url returned raw, not malformed",
			server:       "fetch",
			tool:         "get",
			args:         map[string]any{"url": "//example.com/path"},
			wantSystem:   "fetch",
			wantResource: "//example.com/path",
		},
		{
			name:         "opaque endpoint without host returned trimmed",
			server:       "api",
			tool:         "call",
			args:         map[string]any{"endpoint": "  api.internal/v2/things  "},
			wantSystem:   "api",
			wantResource: "api.internal/v2/things",
		},
		{
			name:         "opaque endpoint query stripped so secrets do not leak",
			server:       "api",
			tool:         "call",
			args:         map[string]any{"endpoint": "api.internal/v2/things?token=s3cret#frag"},
			wantSystem:   "api",
			wantResource: "api.internal/v2/things",
		},
		{
			name:         "scheme-relative url query stripped",
			server:       "fetch",
			tool:         "get",
			args:         map[string]any{"url": "//example.com/path?x=1"},
			wantSystem:   "fetch",
			wantResource: "//example.com/path",
		},
		{
			name:         "uri key matched case-insensitively",
			server:       "fetch",
			tool:         "get",
			args:         map[string]any{"URL": "https://example.com/a"},
			wantSystem:   "fetch",
			wantResource: "https://example.com/a",
		},
		{
			name:         "endpoint key matched case-insensitively",
			server:       "api",
			tool:         "call",
			args:         map[string]any{"Endpoint": "https://example.com/b"},
			wantSystem:   "api",
			wantResource: "https://example.com/b",
		},
		{
			name:         "repo owner/repo keys matched case-insensitively",
			server:       "github",
			tool:         "create_issue",
			args:         map[string]any{"Owner": "agent-receipts", "Repo": "obsigna"},
			wantSystem:   "github",
			wantResource: "agent-receipts/obsigna",
		},

		// Table tier.
		{
			name:         "bare table",
			server:       "postgres",
			tool:         "query_table",
			args:         map[string]any{"table": "events"},
			wantSystem:   "postgres",
			wantResource: "events",
		},
		{
			name:         "table qualified by database",
			server:       "postgres",
			tool:         "select",
			args:         map[string]any{"database": "analytics", "table": "events"},
			wantSystem:   "postgres",
			wantResource: "analytics.events",
		},
		{
			name:         "collection qualified by schema",
			server:       "mongo",
			tool:         "find",
			args:         map[string]any{"schema": "app", "collection": "sessions"},
			wantSystem:   "mongo",
			wantResource: "app.sessions",
		},

		// Repo tier.
		{
			name:         "owner and repo",
			server:       "github",
			tool:         "create_issue",
			args:         map[string]any{"owner": "agent-receipts", "repo": "obsigna", "title": "x"},
			wantSystem:   "github",
			wantResource: "agent-receipts/obsigna",
		},
		{
			name:         "same repo regardless of issue number",
			server:       "github",
			tool:         "issue_read",
			args:         map[string]any{"owner": "agent-receipts", "repo": "obsigna", "issue_number": float64(852)},
			wantSystem:   "github",
			wantResource: "agent-receipts/obsigna",
		},
		{
			name:         "owner without repo does not match repo tier",
			server:       "github",
			tool:         "get_user",
			args:         map[string]any{"owner": "agent-receipts"},
			wantSystem:   "",
			wantResource: "",
		},

		// Generic tier.
		{
			name:         "generic path",
			server:       "files",
			tool:         "stat",
			args:         map[string]any{"path": "/var/data/report.csv"},
			wantSystem:   "files",
			wantResource: "/var/data/report.csv",
		},
		{
			name:         "generic bucket",
			server:       "blob",
			tool:         "head",
			args:         map[string]any{"bucket": "prod-assets"},
			wantSystem:   "blob",
			wantResource: "prod-assets",
		},

		// Tier precedence: uri beats table beats repo beats generic.
		{
			name:         "uri wins over table and path",
			server:       "mixed",
			tool:         "do",
			args:         map[string]any{"url": "https://h/x", "table": "t", "path": "/p"},
			wantSystem:   "mixed",
			wantResource: "https://h/x",
		},
		{
			name:         "table wins over repo and path",
			server:       "mixed",
			tool:         "do",
			args:         map[string]any{"table": "t", "owner": "o", "repo": "r", "path": "/p"},
			wantSystem:   "mixed",
			wantResource: "t",
		},

		// No match / guards.
		{
			name:         "no recognised key",
			server:       "thing",
			tool:         "do_thing",
			args:         map[string]any{"count": float64(3), "force": true},
			wantSystem:   "",
			wantResource: "",
		},
		{
			name:         "bare id and name are not resource keys",
			server:       "thing",
			tool:         "do_thing",
			args:         map[string]any{"id": "123", "name": "Alice"},
			wantSystem:   "",
			wantResource: "",
		},
		{
			name:         "nil args",
			server:       "thing",
			tool:         "do_thing",
			args:         nil,
			wantSystem:   "",
			wantResource: "",
		},
		{
			name:         "empty server name yields no target",
			server:       "",
			tool:         "do_thing",
			args:         map[string]any{"table": "events"},
			wantSystem:   "",
			wantResource: "",
		},
		{
			name:         "non-string resource value ignored",
			server:       "thing",
			tool:         "do_thing",
			args:         map[string]any{"table": float64(7)},
			wantSystem:   "",
			wantResource: "",
		},
		{
			name:         "whitespace-only value ignored",
			server:       "thing",
			tool:         "do_thing",
			args:         map[string]any{"path": "   "},
			wantSystem:   "",
			wantResource: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSystem, gotResource := ExtractTarget(tt.server, tt.tool, tt.args)
			if gotSystem != tt.wantSystem || gotResource != tt.wantResource {
				t.Errorf("ExtractTarget(%q, %q, %v) = (%q, %q); want (%q, %q)",
					tt.server, tt.tool, tt.args, gotSystem, gotResource, tt.wantSystem, tt.wantResource)
			}
			// Invariant: system and resource are both set or both empty, so the
			// emitter's all-or-nothing Target rule never trips.
			if (gotSystem == "") != (gotResource == "") {
				t.Errorf("half-populated target: system=%q resource=%q", gotSystem, gotResource)
			}
		})
	}
}

func TestExtractTargetDropsOversizeResource(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("a", maxResourceLen)
	system, resource := ExtractTarget("web", "get", map[string]any{"url": long})
	if system != "" || resource != "" {
		t.Errorf("oversize resource should yield no target; got (%q, len %d)", system, len(resource))
	}
}

// An over-long server name must yield no target rather than a target the
// emitter would reject — which would drop the whole receipt, not just the
// target. serverName populates Tool.Server uncapped, so this guards the case
// where it also flows into the capped Target.System.
func TestExtractTargetDropsOversizeSystem(t *testing.T) {
	longServer := strings.Repeat("s", maxSystemLen+1)
	system, resource := ExtractTarget(longServer, "query", map[string]any{"table": "events"})
	if system != "" || resource != "" {
		t.Errorf("oversize system should yield no target; got (%q, %q)", system, resource)
	}
}
