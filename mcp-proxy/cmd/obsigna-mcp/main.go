package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
	"github.com/agent-receipts/ar/mcp-proxy/internal/host"
	"github.com/agent-receipts/ar/mcp-proxy/internal/policy"
	"github.com/agent-receipts/ar/mcp-proxy/internal/proxy"
	"github.com/agent-receipts/ar/sdk/go/emitter"
	"github.com/google/uuid"
)

// httpShutdownGrace bounds how long the approval HTTP server gets to finish
// in-flight requests after a shutdown signal before it is forced closed.
const httpShutdownGrace = 5 * time.Second

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
// Falls back to the module version from Go's build info (set automatically
// for binaries installed with `go install`), then to "dev".
var version string

func resolveVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-version", "--version":
			fmt.Printf("obsigna-mcp %s\n", resolveVersion())
			return
		case "doctor":
			cmdDoctor(os.Args[2:])
			return
		case "init":
			cmdInit(os.Args[2:])
			return
		case "serve":
			os.Args = append(os.Args[:1], os.Args[2:]...)
			// Fall through to serve.
		}
	}

	os.Exit(serve())
}

// serve runs the proxy session and returns the process exit code. It returns
// (rather than calling os.Exit) for any failure that occurs after the daemon
// emitter is wired up, so the deferred emitter Close() and approval-server
// teardown run before the process exits. main() performs the os.Exit at the
// top-level boundary once serve has returned and its deferreds have run.
func serve() int {
	var (
		rulesPath    = flag.String("rules", "", "Policy rules (YAML file)")
		serverName   = flag.String("name", "", "Server name for audit trail")
		httpAddr     = flag.String("http", "none", "HTTP address for the approval listener (default: none — listener is off). Pass 127.0.0.1:0 for a random free port or 127.0.0.1:<port> to pin a port. See https://agentreceipts.ai/mcp-proxy/approval-ui/.")
		approvalWait = flag.Duration("approval-timeout", 60*time.Second, "Maximum time to wait for HTTP approval when a policy rule pauses a tool call")
		socketPath   = flag.String("socket", emitter.DefaultSocketPath(), "Unix-domain socket for the agent-receipts daemon (ADR-0010). Defaults to AGENTRECEIPTS_SOCKET if set; explicit --socket wins. Pass --socket=\"\" to disable emission entirely. Emit errors are logged but do not block tool calls.")
		issuerName   = flag.String("issuer-name", envOr("AGENTRECEIPTS_ISSUER_NAME", ""), "Override detected issuer name (env: AGENTRECEIPTS_ISSUER_NAME)")
		issuerModel  = flag.String("issuer-model", envOr("AGENTRECEIPTS_ISSUER_MODEL", ""), "AI model identifier (env: AGENTRECEIPTS_ISSUER_MODEL)")
		operatorID   = flag.String("operator-id", envOr("AGENTRECEIPTS_OPERATOR_ID", ""), "Operator DID (env: AGENTRECEIPTS_OPERATOR_ID)")
		operatorName = flag.String("operator-name", envOr("AGENTRECEIPTS_OPERATOR_NAME", ""), "Operator name (env: AGENTRECEIPTS_OPERATOR_NAME)")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: obsigna-mcp [flags] <command> [args...]\n")
		fmt.Fprintf(os.Stderr, "  Wraps an MCP server with policy enforcement and forwards tool-call\n")
		fmt.Fprintf(os.Stderr, "  events to the agent-receipts daemon for signing and persistence.\n\n")
		fmt.Fprintf(os.Stderr, "Subcommands: serve, doctor, init\n\n")
		fmt.Fprintf(os.Stderr, "  -version\n\tPrint version and exit\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Detect whether -http was explicitly set on the command line.
	// flag.Visit only visits flags that were actually provided; if -http is
	// absent the flag retains its default ("none") and httpExplicit stays false.
	httpExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "http" {
			httpExplicit = true
		}
	})

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	command := args[0]
	commandArgs := args[1:]

	// Drive shutdown off a signal-cancelled context. SIGINT/SIGTERM cancel ctx,
	// which unblocks the proxy pumps, any in-flight approval wait, and triggers
	// graceful shutdown of the approval HTTP server. The normal STDIO path
	// (client closes stdin → EOF) is unaffected and still ends Run cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Server name defaults to command basename.
	if *serverName == "" {
		parts := strings.Split(command, "/")
		*serverName = parts[len(parts)-1]
	}

	// Resolve issuer/operator identity: auto-detect the host, then apply any
	// flag or env overrides. Flags take precedence over auto-detection.
	id := host.Detect()
	if *issuerName != "" {
		id.IssuerName = *issuerName
		id.Source = "flags"
	}
	if *issuerModel != "" {
		id.IssuerModel = *issuerModel
		id.Source = "flags"
	}
	if *operatorID != "" {
		id.OperatorID = *operatorID
		id.Source = "flags"
	}
	if *operatorName != "" {
		id.OperatorName = *operatorName
		id.Source = "flags"
	}
	if id.OperatorName != "" && id.OperatorID == "" {
		log.Fatalf("mcp-proxy: --operator-name (or AGENTRECEIPTS_OPERATOR_NAME) requires --operator-id (or AGENTRECEIPTS_OPERATOR_ID)")
	}
	if id.IssuerName != "" || id.IssuerModel != "" || id.OperatorID != "" || id.OperatorName != "" {
		log.Printf("mcp-proxy: host=%s issuer=%q model=%q operator.id=%q operator.name=%q",
			id.Source, id.IssuerName, id.IssuerModel, id.OperatorID, id.OperatorName)
	}

	sessionID := uuid.New().String()

	// One-shot legacy notice. Operators upgrading from <v0.9.0 may have a
	// ~/.local/share/agent-receipts/audit.db left from the old local store;
	// the daemon's store at the same directory is authoritative now.
	noteLegacyAuditDB()

	// Warn (every startup) if the agent-receipts data directory pre-exists with
	// group/other-accessible perms. The directory is created 0o700, but
	// os.MkdirAll won't tighten an existing one — so a dir left at e.g. 0o755
	// would silently expose the daemon's store and keys to other local users.
	// No-op on Windows (Unix perm bits don't apply there).
	warnDataDirPerms(os.Stderr)

	// Wire the daemon emitter (ADR-0010). The daemon is the sole receipt writer;
	// the proxy is a thin emitter. Emit surfaces transport failure by default
	// (ADR-0025), so an unreachable daemon propagates to the handler as a log
	// line. An empty --socket is still accepted for backward compatibility with
	// installations that have not yet deployed the daemon.
	var em *emitter.DaemonEmitter
	if sp := *socketPath; sp != "" {
		var initErr error
		em, initErr = emitter.NewDaemon(
			emitter.WithSocketPath(sp),
			emitter.WithSessionID(sessionID),
			emitter.WithIdentity(emitter.Identity{
				IssuerName:   id.IssuerName,
				IssuerModel:  id.IssuerModel,
				OperatorID:   id.OperatorID,
				OperatorName: id.OperatorName,
			}),
		)
		if initErr != nil {
			log.Fatalf("mcp-proxy: emitter init: %v", initErr)
		}
		defer em.Close()
		log.Printf("mcp-proxy: emitter targeting daemon socket %s", sp)
	} else {
		log.Printf("mcp-proxy: --socket is empty; receipts will NOT be emitted to the daemon")
	}

	// Load policy rules.
	var rules []policy.Rule
	if *rulesPath != "" {
		var err error
		rules, err = policy.LoadRules(*rulesPath)
		if err != nil {
			log.Printf("mcp-proxy: load rules: %v", err)
			return 1
		}
	} else {
		rules = policy.DefaultRules()
	}
	engine := policy.NewEngine(rules)

	// Approval channels for pause actions.
	approvalToken := generateToken(32)
	approvals := audit.NewApprovalManager()
	approvalURL := ""

	// Pending tool call requests (keyed by JSON-RPC id). We only need to
	// carry the tool name and the already-marshaled argument bytes from the
	// request to the response so we can populate the daemon emitter event
	// on completion. Storing the bytes (rather than the unmarshaled map)
	// keeps the block/pause/success emit paths identical and avoids a
	// second `json.Marshal` per call.
	type pendingCall struct {
		toolName       string
		argJSON        json.RawMessage
		idempotencyKey string
		correlationID  string
	}
	pendingCalls := make(map[string]*pendingCall)
	var pendingMu sync.Mutex

	// Start HTTP server for approvals only when the operator explicitly opts in
	// via -http <addr>. "none" is the default — no listener, no port, no
	// collision between concurrent sessions. httpSrv is the handle serve() uses
	// to cancel and await the approval server during wind-down; it stays nil
	// when no listener runs so the shutdown wait below is a no-op in the default
	// STDIO-only flow.
	//
	// The approval server shuts down on a dedicated context derived from the
	// signal ctx. Cancelling httpCancel — which serve() always does once Run
	// returns, on the clean stdin-EOF path as well as the signal path — drives
	// the graceful Shutdown(grace) without requiring an OS signal.
	var httpSrv *approvalServer
	httpCtx, httpCancel := context.WithCancel(ctx)
	defer httpCancel()
	approverDisabled := strings.EqualFold(strings.TrimSpace(*httpAddr), "none")
	if !approverDisabled && *httpAddr != "" {
		ln, err := net.Listen("tcp", *httpAddr)
		if err != nil {
			fmt.Fprint(os.Stderr, formatBindFailure(*httpAddr, err))
			return 1
		}
		approvalURL = "http://" + ln.Addr().String()
		// Human-readable line (one copy-pasteable string, no log timestamp prefix).
		fmt.Fprintf(os.Stderr, "mcp-proxy: approvals at %s (token: %s)\n", approvalURL, approvalToken)
		// Machine-readable line — minimal discovery primitive for future tooling.
		endpointJSON, err := json.Marshal(map[string]string{
			"event": "approval_endpoint",
			"url":   approvalURL,
			"token": approvalToken,
		})
		if err != nil {
			log.Printf("mcp-proxy: marshal approval endpoint discovery payload: %v", err)
			endpointJSON = []byte(`{"event":"approval_endpoint"}`)
		}
		fmt.Fprintln(os.Stderr, string(endpointJSON))

		httpSrv = serveApprovals(httpCtx, ln, buildApprovalMux(approvals, approvalToken))
	}

	// Boot-time summary: one line covers the bulk of "why did my call fail?"
	// debugging. A WARN variant fires when the approver is absent but the
	// ruleset needs one, which is the #1 silent-failure mode. Explicit
	// -http=none is NOT treated as misconfiguration.
	emitStartupBanner(engine.Describe(), approvalURL, approverDisabled, httpExplicit)

	// `raw` is unused now that the daemon owns persistence/redaction; the
	// parameter is kept (named `_`) because proxy.HandlerFn dictates the
	// signature.
	handler := func(direction string, _ []byte, msg *proxy.Message) *proxy.HandlerResult {
		jsonrpcID := ""
		if msg != nil {
			jsonrpcID = msg.IDString()
		}

		// Client → Server: intercept tool calls.
		if direction == "client_to_server" && msg != nil && msg.IsToolCall() {
			params, _ := msg.ParseToolCallParams()
			if params != nil {
				toolName := proxy.StripMCPPrefix(params.Name)
				opType := audit.ClassifyOperation(toolName)
				riskScore, _ := audit.ScoreRisk(toolName, params.Arguments)

				decision := engine.Evaluate(policy.EvalContext{
					ToolName:      toolName,
					ServerName:    *serverName,
					OperationType: opType,
					RiskScore:     riskScore,
				})

				argJSON, marshalErr := json.Marshal(params.Arguments)
				if marshalErr != nil {
					// Defensive: params.Arguments came out of json.Unmarshal
					// (proxy.Message), so re-marshaling cannot realistically
					// fail. Log and emit nil input rather than dropping the
					// receipt entirely.
					log.Printf("mcp-proxy: marshal arguments for daemon: %v; emitting nil input", marshalErr)
					argJSON = nil
				}

				pendingMu.Lock()
				pendingCalls[jsonrpcID] = &pendingCall{
					toolName:       toolName,
					argJSON:        argJSON,
					idempotencyKey: jsonrpcID,
					correlationID:  params.ToolUseID(),
				}
				pendingMu.Unlock()

				if decision.Action == "block" {
					log.Printf("mcp-proxy: BLOCKED %s (rule: %s, risk: %d)", toolName, decision.RuleName, riskScore)
					emitPolicyEvent(toolName, decision.RuleName, riskScore, "block", approvalURL, "blocked", 0)
					pendingMu.Lock()
					blockedCorrelationID := pendingCalls[jsonrpcID].correlationID
					delete(pendingCalls, jsonrpcID)
					pendingMu.Unlock()
					emitToContext(em, *serverName, toolName, argJSON, nil, fmt.Sprintf("blocked by policy: %s", decision.Reason), "denied", jsonrpcID, blockedCorrelationID)
					return &proxy.HandlerResult{
						Block:          true,
						ClientResponse: proxy.MakeErrorResponse(msg.ID, -32001, fmt.Sprintf("blocked by policy: %s", decision.Reason)),
					}
				}

				if decision.Action == "pause" {
					approvalID := generateToken(16)
					log.Printf("mcp-proxy: PAUSED %s (rule: %s, risk: %d) — approval id: %s", toolName, decision.RuleName, riskScore, approvalID)
					waitStart := time.Now()
					var approvalStatus audit.ApprovalStatus
					if approvalURL == "" {
						// No approver wired up — fail fast instead of timing out.
						approvalStatus = audit.ApprovalNoApprover
					} else {
						approvalStatus = approvals.WaitForApproval(ctx, approvalID, *approvalWait)
					}
					approvalWaitUs := time.Since(waitStart).Microseconds()
					if approvalStatus != audit.ApprovalApproved {
						log.Printf("mcp-proxy: DENIED %s (%s)", toolName, approvalStatus)
						emitPolicyEvent(toolName, decision.RuleName, riskScore, "pause", approvalURL, string(approvalStatus), approvalWaitUs/1000)
						code, message := approvalRejectionResponse(toolName, decision.RuleName, riskScore, approvalID, approvalStatus, *approvalWait)
						pendingMu.Lock()
						deniedCorrelationID := pendingCalls[jsonrpcID].correlationID
						delete(pendingCalls, jsonrpcID)
						pendingMu.Unlock()
						emitToContext(em, *serverName, toolName, argJSON, nil, message, "denied", jsonrpcID, deniedCorrelationID)
						return &proxy.HandlerResult{
							Block: true,
							ClientResponse: proxy.MakeErrorResponseWithData(
								msg.ID,
								code,
								message,
								map[string]any{
									"status":                  string(approvalStatus),
									"tool_name":               toolName,
									"rule_name":               decision.RuleName,
									"risk_score":              riskScore,
									"approval_id":             approvalID,
									"approval_url":            approvalURL,
									"approval_timeout_ms":     (*approvalWait).Milliseconds(),
									"approval_required":       true,
									"approval_token_required": true,
								},
							),
						}
					}
					log.Printf("mcp-proxy: APPROVED %s", toolName)
					emitPolicyEvent(toolName, decision.RuleName, riskScore, "pause", approvalURL, "approved", approvalWaitUs/1000)
				}

				if decision.Action == "flag" {
					log.Printf("mcp-proxy: FLAGGED %s (rule: %s, risk: %d)", toolName, decision.RuleName, riskScore)
				}
			}
		}

		// Server → Client: pair response with request and emit to daemon.
		if direction == "server_to_client" && msg != nil && msg.IsResponse() {
			pendingMu.Lock()
			pc, ok := pendingCalls[jsonrpcID]
			if ok {
				delete(pendingCalls, jsonrpcID)
			}
			pendingMu.Unlock()

			if ok {
				resultStr := ""
				errorStr := ""
				if msg.Result != nil {
					resultStr = string(msg.Result)
				}
				if msg.Error != nil {
					errorStr = string(msg.Error)
				}

				// Forward the completed tool call to the daemon (ADR-0010). The
				// daemon is the sole receipt writer: it owns redaction, hashing,
				// signing, and persistence. We pass raw input/output JSON so the
				// daemon's redactor sees the same bytes it will hash.
				//
				// decision is always "allowed" here: reaching this branch means
				// the proxy did NOT block the call. Upstream success-vs-failure
				// is communicated via errorStr; the daemon derives
				// outcome.status from both decision and the presence of a
				// non-empty error (allowed+error → failure).
				var outputRaw json.RawMessage
				if resultStr != "" && json.Valid([]byte(resultStr)) {
					outputRaw = json.RawMessage(resultStr)
				}
				emitToContext(em, *serverName, pc.toolName, pc.argJSON, outputRaw, errorStr, "allowed", pc.idempotencyKey, pc.correlationID)
			}
		}

		return nil // Forward normally.
	}

	p := proxy.New(command, commandArgs, handler)
	log.Printf("mcp-proxy: session %s, server %s", sessionID, *serverName)

	// Run the proxy in a goroutine so we can watch the approval server's health
	// concurrently. If the approval HTTP listener dies mid-session (a
	// non-ErrServerClosed Serve failure while the run loop is still blocked),
	// awaitSessionEnd cancels the session so Run unblocks promptly and the proxy
	// stops advertising an approval URL it can no longer honour — instead of
	// leaving callers to time out in WaitForApproval (#691).
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- p.Run(ctx) }()
	outcome := awaitSessionEnd(runErrCh, httpSrv, stop, httpCancel)
	log.Printf("mcp-proxy: session %s ended", sessionID)

	// A mid-session approval-server death is fatal: surface the wrapped error and
	// exit non-zero. Checked before the signal branch because the fail-fast path
	// cancels the session ctx itself, which would otherwise look like a signal.
	if outcome.serverDied {
		log.Printf("mcp-proxy: approval server: %v", outcome.httpErr)
		return 1
	}
	// When a signal cancelled ctx, Run returned because we killed the upstream;
	// the resulting Wait error is expected, not a failure. Log a single clear
	// shutdown line and return so the deferred emitter Close() runs last.
	if ctx.Err() != nil {
		log.Printf("mcp-proxy: shutting down (signal received)")
		return 0
	}
	// Surface a fatal error by returning a non-zero exit code so deferred
	// cleanup (emitter Close) runs first; main() performs the os.Exit. A
	// non-ErrServerClosed Serve failure — propagated out of the goroutine via
	// waitForHTTPShutdown rather than crashing it — is reported the same way as
	// a Run failure.
	if outcome.runErr != nil {
		log.Printf("mcp-proxy: %v", outcome.runErr)
		return 1
	}
	if outcome.httpErr != nil {
		log.Printf("mcp-proxy: approval server: %v", outcome.httpErr)
		return 1
	}
	return 0
}

// shutdownOutcome reports how a proxy session ended so serve() can choose the
// exit code and shutdown log line.
type shutdownOutcome struct {
	runErr     error // result of p.Run; nil on a clean stdin-EOF
	httpErr    error // non-ErrServerClosed approval-server Serve failure, if any
	serverDied bool  // the approval server failed while the session was still live
}

// awaitSessionEnd coordinates the end of a proxy session. It blocks until
// either the run loop finishes (signal or stdin-EOF) or the approval HTTP
// server dies mid-session, whichever happens first, then winds the other side
// down and reports the outcome. runErrCh receives exactly one value — the
// result of p.Run. stopSession cancels the session context; httpCancel and
// httpSrv drive and await the approval server's graceful shutdown.
//
// The approval handle's errCh is buffered (size 1) and carries exactly one
// value, so this function reads it AT MOST once: on the run-completed branch it
// leaves errCh for waitForHTTPShutdown to read; on the server-died branch it
// consumes that value directly and must NOT also call waitForHTTPShutdown,
// which would block re-reading an already-drained channel.
//
// When httpSrv is nil (the -http-off STDIO-only flow) the server-done channel
// is nil and never fires, so the only path is run-completed and the helper is a
// thin pass-through.
func awaitSessionEnd(runErrCh <-chan error, httpSrv *approvalServer, stopSession, httpCancel context.CancelFunc) shutdownOutcome {
	var serverDone <-chan struct{}
	if httpSrv != nil {
		serverDone = httpSrv.done
	}

	select {
	case runErr := <-runErrCh:
		// Normal end (signal or stdin-EOF). Wind the approval server down and
		// await it exactly as before: httpCancel drives the graceful
		// Shutdown(grace); waitForHTTPShutdown reads the single errCh value (a
		// no-op when no approval server runs).
		httpCancel()
		return shutdownOutcome{runErr: runErr, httpErr: waitForHTTPShutdown(httpSrv)}
	case <-serverDone:
		// The approval server's Serve returned while the session was still live.
		// Its errCh already holds the single Serve result; read it once here.
		// During a live session this is genuinely a mid-session failure: the
		// clean ErrServerClosed (nil) path only fires after httpCancel, which the
		// run-completed branch above is the sole caller of. Guard on a non-nil
		// error anyway so a clean stop never gets misreported as a death.
		httpErr := <-httpSrv.errCh
		// Unblock Run so the session tears down promptly rather than waiting for
		// an independent end (signal/EOF).
		stopSession()
		runErr := <-runErrCh
		return shutdownOutcome{runErr: runErr, httpErr: httpErr, serverDied: httpErr != nil}
	}
}

// waitForHTTPShutdown blocks until the approval HTTP server has finished
// shutting down, bounded by the grace window plus a small margin so a wedged
// listener can never hang process exit. srv is nil when no approval server was
// started (the default STDIO-only flow), in which case this returns nil
// immediately. On a clean stop it returns the Serve result: nil for the
// ErrServerClosed path, or the underlying error when the listener died
// unexpectedly. A grace-window timeout returns nil — the wedged listener is
// logged but must not block process exit.
func waitForHTTPShutdown(srv *approvalServer) error {
	if srv == nil {
		return nil
	}
	select {
	case <-srv.done:
		return <-srv.errCh
	case <-time.After(httpShutdownGrace + time.Second):
		log.Printf("mcp-proxy: approval server did not stop within grace window")
		return nil
	}
}

func buildApprovalDeniedMessage(toolName, ruleName string, riskScore int, approvalID string, status audit.ApprovalStatus, timeout time.Duration) string {
	switch status {
	case audit.ApprovalDenied:
		return fmt.Sprintf("tool call denied by approval workflow: tool=%s rule=%s risk=%d approval_id=%s", toolName, ruleName, riskScore, approvalID)
	case audit.ApprovalTimedOut:
		return fmt.Sprintf("tool call approval timed out after %s: tool=%s rule=%s risk=%d approval_id=%s", timeout, toolName, ruleName, riskScore, approvalID)
	case audit.ApprovalNoApprover:
		return fmt.Sprintf("tool call rejected: no approver configured for pause rule %q (pass -http=ADDR to enable, or -http=none to acknowledge): tool=%s risk=%d", ruleName, toolName, riskScore)
	default:
		return fmt.Sprintf("tool call denied by approval workflow: tool=%s rule=%s risk=%d approval_id=%s", toolName, ruleName, riskScore, approvalID)
	}
}

// approvalRejectionResponse returns the JSON-RPC error code and message for a
// non-approved pause outcome. -32002 covers the approved-channel cases (deny /
// timeout). -32003 is used for the no-approver case so clients can distinguish
// "configuration error" from "user rejected" and surface a different prompt.
func approvalRejectionResponse(toolName, ruleName string, riskScore int, approvalID string, status audit.ApprovalStatus, timeout time.Duration) (int, string) {
	code := -32002
	if status == audit.ApprovalNoApprover {
		code = -32003
	}
	return code, buildApprovalDeniedMessage(toolName, ruleName, riskScore, approvalID, status, timeout)
}

// formatBindFailure builds the actionable error printed when -http binds to a
// busy address. Extracted so the test asserts against the real string the
// operator sees rather than re-implementing the format.
func formatBindFailure(addr string, err error) string {
	return fmt.Sprintf(
		"mcp-proxy: cannot bind approval listener on %s: %v\n"+
			"  Fix: use -http 127.0.0.1:0 for a random free port, or -http=none to disable the listener.\n",
		addr, err)
}

// emitStartupBanner prints a one-line policy/approver summary on stderr plus a
// machine-readable JSON companion line. The banner always prints; what varies
// by configuration is the level (INFO vs WARN) and the trailing suffix:
//
//   - Approver wired (approvalURL set): INFO, no suffix.
//   - Default off (approverDisabled, httpExplicit=false) with pause rules:
//     INFO with " — approver off by default; pass -http <addr> to enable".
//   - Explicit -http=none (approverDisabled, httpExplicit=true): INFO, no
//     suffix — operator made an informed choice, no nudge needed.
//   - No approver and not explicitly disabled with pause rules loaded
//     (approverDisabled=false, approvalURL=""): WARN, suffix flags the
//     misconfiguration. Should be unreachable in normal operation since the
//     default value of -http is "none".
//
// "require approval" is reserved for pause rules; block rules are enforced
// without user interaction and are reported separately.
func emitStartupBanner(summary policy.Summary, approvalURL string, approverDisabled bool, httpExplicit bool) {
	pauseCount := len(summary.PauseRules)
	blockCount := len(summary.BlockRules)

	approverState := approvalURL
	switch {
	case approverDisabled:
		approverState = "disabled"
	case approverState == "":
		approverState = "NONE"
	}

	level := "INFO"
	suffix := ""
	// Warn only on the accidental case: pause rules loaded, no approver,
	// and operator didn't explicitly opt out.
	// Default "none" (httpExplicit=false) is NOT a misconfiguration — emit a
	// soft info hint instead. Explicit -http=none stays silent.
	if approvalURL == "" && pauseCount > 0 {
		if !approverDisabled {
			// approverDisabled=false here means neither default-none nor explicit-none;
			// this branch should not normally be reached, but guard it anyway.
			level = "WARN"
			suffix = " — pause rules will fail (set -http=ADDR to enable approver, or -http=none to acknowledge)"
		} else if !httpExplicit {
			// Default none: emit a soft info hint, not a WARN.
			suffix = " — approver off by default; pass -http <addr> to enable"
		}
		// Explicit -http=none: no suffix, no WARN.
	}

	pauseDesc := ""
	if pauseCount > 0 {
		pauseDesc = fmt.Sprintf(" (%s)", strings.Join(summary.PauseRules, ", "))
	}
	blockDesc := ""
	if blockCount > 0 {
		blockDesc = fmt.Sprintf(", %d block (%s)", blockCount, strings.Join(summary.BlockRules, ", "))
	}

	rulesSuffix := ""
	if summary.TotalRules != summary.EnabledRules {
		rulesSuffix = fmt.Sprintf(" (%d disabled)", summary.TotalRules-summary.EnabledRules)
	}
	fmt.Fprintf(os.Stderr,
		"mcp-proxy: [%s] policy: %d rules enabled%s, %d require approval%s%s; approver: %s%s\n",
		level, summary.EnabledRules, rulesSuffix, pauseCount, pauseDesc, blockDesc, approverState, suffix,
	)

	// Machine-readable companion line for tooling.
	payload := map[string]any{
		"event":             "policy_banner",
		"level":             level,
		"rules_loaded":      summary.EnabledRules,
		"pause_rules":       summary.PauseRules,
		"block_rules":       summary.BlockRules,
		"approver_url":      approvalURL,
		"approver_set":      approvalURL != "",
		"approver_disabled": approverDisabled,
	}
	if b, err := json.Marshal(payload); err == nil {
		fmt.Fprintln(os.Stderr, string(b))
	}
}

// emitToContext forwards one tool-call event to the daemon emitter (ADR-0010,
// fire-and-forget). The emitter returns nil on transient failures (no daemon,
// broken socket); the only errors emerging here are caller bugs that no retry
// could fix — closed emitter, empty channel, invalid decision, malformed
// Input/Output JSON. We log them via log.Printf so misuse surfaces in proxy
// logs rather than crashing the request flow.
//
// The Channel is hard-coded to "mcp" because every event from this proxy
// originates from an MCP server tool call; serverName populates Tool.Server
// (the upstream MCP server identifier, e.g. "github") and toolName populates
// Tool.Name. Together the daemon assembles them into action.type
// "mcp.<server>.<tool>". input and output are raw JSON bytes; either may be
// nil to signal "no payload" (the daemon will skip hashing in that case).
// errStr carries the error payload string (raw JSON-RPC error object JSON for
// upstream errors, a policy message for denied calls; empty for success).
// decision must be "allowed", "denied", or "pending".
//
// idempotencyKey is the wrapped JSON-RPC request id of the tool call. The
// daemon stamps it onto action.idempotency_key (spec §7.3.6) so that retries
// of the same logical operation share a value and auditors can tell a
// legitimate retry from a duplicated emission. Empty when no id was present;
// the emitter omits the field from the frame in that case.
//
// correlationID is the Claude Code tool_use_id from _meta, used to link this
// proxy post-action receipt to the hook pre-check receipt for the same
// logical tool invocation. Empty when not available (non-Claude-Code clients).
func emitToContext(em *emitter.DaemonEmitter, serverName, toolName string, input, output json.RawMessage, errStr, decision, idempotencyKey, correlationID string) {
	if em == nil {
		return
	}
	if err := em.Emit(context.Background(), emitter.Event{
		Channel:        "mcp",
		Tool:           emitter.Tool{Server: serverName, Name: toolName},
		Input:          input,
		Output:         output,
		Error:          errStr,
		Decision:       decision,
		IdempotencyKey: idempotencyKey,
		CorrelationID:  correlationID,
	}); err != nil {
		log.Printf("mcp-proxy: emitter: %v", err)
	}
}

// emitPolicyEvent writes one structured key=value log line per pause/block
// outcome. Cheap to grep, cheap to parse, small enough to ship to SIEMs.
// String values are %q-quoted so rule/tool names with spaces or "=" remain
// unambiguous when parsed.
func emitPolicyEvent(tool, rule string, risk int, action, approverURL, outcome string, durationMs int64) {
	approver := approverURL
	if approver == "" {
		approver = "NONE"
	}
	log.Printf("mcp-proxy: policy_event tool=%q rule=%q risk=%d action=%q approver=%q outcome=%q duration_ms=%d",
		tool, rule, risk, action, approver, outcome, durationMs)
}

// userHomeDir is overridable in tests so xdgDataHome and noteLegacyAuditDB can
// be exercised deterministically (clearing $HOME isn't enough on Unix —
// os.UserHomeDir can still resolve via /etc/passwd).
var userHomeDir = os.UserHomeDir

// xdgDataHome returns the XDG_DATA_HOME directory or its default
// ($HOME/.local/share). Returns "" when XDG_DATA_HOME is unset and the
// user's home directory cannot be determined.
//
// Per the XDG Base Directory spec, $XDG_DATA_HOME must be an absolute path;
// a relative value is treated as invalid and ignored, falling back to the
// $HOME/.local/share default. This protects against a misconfigured
// environment silently relocating files under the working directory of
// whichever process happened to start the proxy.
func xdgDataHome() string {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome != "" && filepath.IsAbs(dataHome) {
		return dataHome
	}
	home, err := userHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Join(home, ".local", "share")
}

// noteLegacyAuditDB prints a one-line nudge to stderr at startup if the
// legacy proxy-owned audit DB is still on disk. Before v0.9.0 the proxy
// maintained its own SQLite store at $XDG_DATA_HOME/agent-receipts/audit.db;
// the daemon is now the sole writer and the file is safe to delete. The
// proxy does not remove it automatically — operators may want to inspect or
// archive it.
//
// Uses fmt.Fprintf rather than log.Printf so the [INFO] tag is not wrapped
// by the standard log timestamp prefix (matching emitStartupBanner's style).
// Errors from os.Stat other than ErrNotExist (e.g. a permissions error on
// the parent directory) still warrant a soft notice so operators in that
// state are not silently denied the warning.
func noteLegacyAuditDB() {
	dh := xdgDataHome()
	if dh == "" {
		return
	}
	legacy := filepath.Join(dh, "agent-receipts", "audit.db")
	_, err := os.Stat(legacy)
	switch {
	case err == nil:
		fmt.Fprintf(os.Stderr,
			"mcp-proxy: [INFO] legacy audit DB at %s is no longer used; safe to delete. Receipts now live in the daemon's store (see `agent-receipts list`).\n",
			legacy)
	case !errors.Is(err, fs.ErrNotExist):
		fmt.Fprintf(os.Stderr,
			"mcp-proxy: [INFO] could not check for legacy audit DB at %s: %v (the file may exist but be unreadable; the daemon's store is authoritative regardless).\n",
			legacy, err)
	}
}

// envOr returns the value of the named environment variable, or fallback when
// the variable is unset or empty.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func generateToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("mcp-proxy: crypto/rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func buildApprovalMux(approvals *audit.ApprovalManager, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tool-calls/", func(w http.ResponseWriter, r *http.Request) {
		// Validate bearer token.
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 5 {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		id := parts[3]
		action := parts[4]

		switch {
		case r.Method == "POST" && action == "approve":
			if approvals.Approve(id) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"status":"approved"}`)
			} else {
				http.Error(w, "no pending approval", http.StatusNotFound)
			}
		case r.Method == "POST" && action == "deny":
			if approvals.Deny(id) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"status":"denied"}`)
			} else {
				http.Error(w, "no pending approval", http.StatusNotFound)
			}
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})
	return mux
}

// approvalServer is the handle serve() holds onto the running approval HTTP
// server. done closes once Serve has returned (the server is fully stopped);
// errCh (buffered, size 1) then carries the Serve result: nil on the clean
// ErrServerClosed exit, or the underlying error when the listener died
// unexpectedly. Surfacing the error this way — rather than log.Fatalf inside
// the goroutine — lets serve()'s deferred cleanup (e.g. the daemon emitter
// Close) run before the process exits, mirroring how collector.Run propagates
// its ListenAndServe error back to its caller.
type approvalServer struct {
	done  <-chan struct{}
	errCh <-chan error
}

// serveApprovals runs the approval HTTP server on ln and wires graceful
// shutdown to ctx. The caller awaits and tears down the server via
// waitForHTTPShutdown.
//
// On ctx cancel the server stops accepting and drains in-flight requests for up
// to httpShutdownGrace; if that window expires it is forced closed. Serve's
// ErrServerClosed is the clean-exit signal and is not treated as a failure; any
// other Serve error is propagated to the caller via the returned handle's errCh
// instead of crashing the process, so deferred cleanup still runs.
func serveApprovals(ctx context.Context, ln net.Listener, handler http.Handler) *approvalServer {
	srv := &http.Server{Handler: handler}
	done := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		defer close(done)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("serve on %s: %w", ln.Addr(), err)
			return
		}
		errCh <- nil
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("mcp-proxy: forced approval-server shutdown after %s: %v", httpShutdownGrace, err)
			_ = srv.Close()
		}
	}()

	return &approvalServer{done: done, errCh: errCh}
}
