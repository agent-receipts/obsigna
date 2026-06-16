package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/policy"
)

// DoctorReport is the structured output of `mcp-proxy doctor`. Exposed for
// test-only consumers; the CLI renders it to text or JSON.
type DoctorReport struct {
	RulesPath      string   `json:"rules_path"`
	TotalRules     int      `json:"total_rules"`
	EnabledRules   int      `json:"enabled_rules"`
	PauseRules     []string `json:"pause_rules"`
	BlockRules     []string `json:"block_rules"`
	FlagRules      []string `json:"flag_rules"`
	DisabledRules  []string `json:"disabled_rules,omitempty"`
	ApproverURL    string   `json:"approver_url"`
	ApproverReach  string   `json:"approver_reachable"` // reachable | unreachable | not_configured
	ApproverDetail string   `json:"approver_detail,omitempty"`
	Issues         []string `json:"issues"`
	Healthy        bool     `json:"healthy"`
}

// DiagnoseConfig builds a DoctorReport from a rules path and approver URL.
// Side effects are bounded: it may read the rules file from disk, and calls
// the injected probe (which may perform network I/O). The probe function is
// pluggable so tests can stub it out.
// Returns the report and an overall exit-code bool (true = healthy).
func DiagnoseConfig(rulesPath, approverURL string, probe func(url string) (string, error)) (DoctorReport, bool) {
	report := DoctorReport{
		RulesPath:   rulesPath,
		ApproverURL: approverURL,
	}

	var rules []policy.Rule
	var err error
	if rulesPath == "" {
		rules = policy.DefaultRules()
		report.RulesPath = "(built-in defaults)"
	} else {
		rules, err = policy.LoadRules(rulesPath)
		if err != nil {
			report.Issues = append(report.Issues, fmt.Sprintf("load rules: %v", err))
			return report, false
		}
	}
	engine := policy.NewEngine(rules)
	summary := engine.Describe()
	report.TotalRules = summary.TotalRules
	report.EnabledRules = summary.EnabledRules
	report.PauseRules = summary.PauseRules
	report.BlockRules = summary.BlockRules
	report.FlagRules = summary.FlagRules
	report.DisabledRules = summary.DisabledRules

	switch {
	case approverURL == "":
		report.ApproverReach = "not_configured"
		if summary.NeedsApprover() {
			report.Issues = append(report.Issues,
				fmt.Sprintf("%d pause rule(s) loaded but no approver URL configured — pause calls will fail with -32003", len(summary.PauseRules)))
		}
	default:
		detail, perr := probe(approverURL)
		if perr == nil {
			report.ApproverReach = "reachable"
			report.ApproverDetail = detail
		} else {
			report.ApproverReach = "unreachable"
			report.ApproverDetail = perr.Error()
			report.Issues = append(report.Issues, fmt.Sprintf("approver at %s is unreachable: %v", approverURL, perr))
		}
	}

	report.Healthy = len(report.Issues) == 0
	return report, report.Healthy
}

// probeApprover makes a lightweight HEAD against the approver URL to check
// it's alive, falling back to GET if the server rejects HEAD. Any HTTP
// response — including 401/404 — counts as reachable; the goal is liveness,
// not endpoint correctness. Only connection-level failures (DNS, refused,
// TLS) are treated as unreachable. Side effects on target servers are
// minimised by trying HEAD first.
func probeApprover(url string) (string, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	target := url + "/"

	req, err := http.NewRequest(http.MethodHead, target, nil)
	if err != nil {
		return "", fmt.Errorf("build HEAD request: %w", err)
	}
	resp, headErr := client.Do(req)
	if headErr == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotImplemented {
			return fmt.Sprintf("HTTP %d", resp.StatusCode), nil
		}
	}

	// HEAD failed or server didn't support it — fall back to GET.
	getResp, getErr := client.Get(target)
	if getErr != nil {
		if headErr != nil {
			return "", fmt.Errorf("HEAD: %v; GET: %w", headErr, getErr)
		}
		return "", getErr
	}
	defer getResp.Body.Close()
	return fmt.Sprintf("HTTP %d", getResp.StatusCode), nil
}

func cmdDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	rulesPath := fs.String("rules", "", "Policy rules YAML (default: built-in)")
	approverURL := fs.String("approver", "", "Approver URL to probe (default: none)")
	asJSON := fs.Bool("json", false, "Output as JSON")
	fs.Parse(args)

	report, healthy := DiagnoseConfig(*rulesPath, *approverURL, probeApprover)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
		if !healthy {
			os.Exit(1)
		}
		return
	}

	fmt.Printf("mcp-proxy doctor\n")
	fmt.Printf("  rules:         %s\n", report.RulesPath)
	fmt.Printf("  loaded:        %d enabled (%d total)\n", report.EnabledRules, report.TotalRules)
	if len(report.PauseRules) > 0 {
		fmt.Printf("  pause rules:   %s\n", strings.Join(report.PauseRules, ", "))
	}
	if len(report.BlockRules) > 0 {
		fmt.Printf("  block rules:   %s\n", strings.Join(report.BlockRules, ", "))
	}
	if len(report.FlagRules) > 0 {
		fmt.Printf("  flag rules:    %s\n", strings.Join(report.FlagRules, ", "))
	}
	fmt.Printf("  approver:      %s", report.ApproverReach)
	if report.ApproverURL != "" {
		fmt.Printf(" (%s)", report.ApproverURL)
	}
	if report.ApproverDetail != "" {
		fmt.Printf(" — %s", report.ApproverDetail)
	}
	fmt.Println()

	if len(report.Issues) == 0 {
		fmt.Println("\nOK — configuration is healthy.")
		return
	}

	fmt.Println("\nIssues:")
	for _, issue := range report.Issues {
		fmt.Printf("  - %s\n", issue)
	}
	os.Exit(1)
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	name := fs.String("name", "default", "Name for this proxy instance (used in the config snippet)")
	noApproval := fs.Bool("no-approval", false, "Omit -http from the config snippet (no approval server)")
	httpPort := fs.Int("http-port", 7778, "Approval listener port written into the config snippet")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: mcp-proxy init [-name <name>] [-no-approval] [-http-port <port>]\n\n")
		fmt.Fprintf(os.Stderr, "  One-command setup: creates ~/.local/share/agent-receipts/ and prints a\n")
		fmt.Fprintf(os.Stderr, "  claude_desktop_config.json snippet to stdout.\n\n")
		fmt.Fprintf(os.Stderr, "  Receipts are now written by the agent-receipts daemon; start the daemon\n")
		fmt.Fprintf(os.Stderr, "  before running the proxy.\n\n")
		fmt.Fprintf(os.Stderr, "  Safe to re-run.\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if !validInitName(*name) {
		fmt.Fprintf(os.Stderr, "mcp-proxy init: -name %q is invalid: use only letters, digits, hyphens, underscores, and dots (max 64 chars)\n", *name)
		os.Exit(2)
	}
	if *httpPort < 1 || *httpPort > 65535 {
		fmt.Fprintf(os.Stderr, "mcp-proxy init: -http-port %d is out of range (1-65535)\n", *httpPort)
		os.Exit(2)
	}

	dir := xdgDataHome()
	if dir == "" {
		fmt.Fprintf(os.Stderr, "mcp-proxy init: resolve data directory: home directory unavailable\n")
		os.Exit(1)
	}
	dir = filepath.Join(dir, "agent-receipts")

	binPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-proxy init: warning: could not resolve binary path (%v); using %q — replace with an absolute path before saving the snippet\n", err, "mcp-proxy")
		binPath = "mcp-proxy"
	}

	if err := runInit(dir, *name, *noApproval, *httpPort, binPath, os.Stderr, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "mcp-proxy init: %v\n", err)
		os.Exit(1)
	}
}

// validInitName reports whether name is safe to use as a key filename component.
// Allows letters, digits, hyphens, underscores, and dots; max 64 chars.
// Rejects empty strings and names that would escape the target directory.
func validInitName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// runInit performs the guided setup: creates dir and writes a config snippet to
// out. Status messages go to errOut. Accepting dir and binPath as parameters
// makes the function testable.
//
// Receipts are now written by the agent-receipts daemon (ADR-0010); mcp-proxy
// is a thin emitter and no longer needs its own signing key or receipts.db.
// Start the daemon before starting the proxy.
func runInit(dir, name string, noApproval bool, httpPort int, binPath string, errOut, out io.Writer) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory %q: %w", dir, err)
	}
	// MkdirAll does not tighten permissions on an existing directory, so chmod
	// explicitly to ensure the data directory is not world-readable.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("set permissions on directory %q: %w", dir, err)
	}
	fmt.Fprintf(errOut, "Data directory: %s\n", dir)

	// Build config snippet. The default policy always contains pause/block rules,
	// so include -http by default; --no-approval opts out.
	var proxyArgs []string
	if !noApproval {
		proxyArgs = append(proxyArgs, "-http", fmt.Sprintf("127.0.0.1:%d", httpPort))
	}
	proxyArgs = append(proxyArgs, "YOUR_MCP_SERVER_COMMAND", "AND_ITS_ARGS")

	snippet := map[string]any{
		"mcpServers": map[string]any{
			name: map[string]any{
				"command": binPath,
				"args":    proxyArgs,
			},
		},
	}
	enc, err := json.MarshalIndent(snippet, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config snippet: %w", err)
	}

	fmt.Fprintf(errOut, "\nAdd to your claude_desktop_config.json (replace the trailing args with your MCP server):\n")
	fmt.Fprintln(out, string(enc))
	return nil
}
