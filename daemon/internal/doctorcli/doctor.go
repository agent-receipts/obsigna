// Package doctorcli implements the `obsigna doctor` subcommand: an
// end-to-end health check of the receipts pipeline (emitter → socket → daemon
// → SQLite → verify) described by ADR-0010. It exists because the failure
// modes the pipeline can drift into are subtle — tool calls succeed, individual
// signatures verify, yet the documented path is silently broken. `doctor` makes
// "agent-receipts is working on this host" an actively-checkable property
// rather than an assumption (issue #539).
//
// Logic lives here, away from cmd/agent-receipts/main.go, so tests can drive
// the subcommand directly with arbitrary args / captured I/O without shelling
// out to a built binary, and so individual checks can be unit-tested against
// fixtures.
package doctorcli

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/sdk/go/emitter"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
	"github.com/agent-receipts/ar/sdk/go/taxonomy"
)

// Exit codes are part of the CLI contract — CI healthchecks pivot on them.
// Keep these stable.
const (
	ExitOK         = 0 // all checks ok (or only warnings without --warn-as-error)
	ExitUnhealthy  = 1 // at least one check failed (or warned under --warn-as-error)
	ExitUsageError = 2 // bad flags
)

// Status is the outcome of a single check.
type Status string

const (
	StatusOK   Status = "ok"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
)

// Result is one check's structured outcome. Reason is always present; Fix is a
// suggested remediation command/hint, omitted when there is nothing actionable.
type Result struct {
	Check  string `json:"check"`
	Status Status `json:"status"`
	Reason string `json:"reason"`
	Fix    string `json:"fix,omitempty"`
}

// Report is the full doctor run, emitted verbatim under --json.
type Report struct {
	OK     bool     `json:"ok"`
	Checks []Result `json:"checks"`
}

// allowedDBPerm mirrors daemon.allowedDBPerm (0640): the maximum permission set
// the receipt DB may carry per ADR-0010 § Read interface. Replicated here
// (the daemon constant is unexported) so doctor flags a DB whose perms drifted
// looser than the daemon would tolerate.
const allowedDBPerm os.FileMode = 0o640

// roundtripChannel and roundtripTool are the fixed markers stamped on the
// synthetic round-trip event so it is visibly synthetic in the chain. The
// daemon derives action.type as "<channel>.<tool.name>", which yields
// taxonomy.DiagnosticRoundtripActionType — see that constant.
const (
	roundtripChannel = "doctor"
	roundtripTool    = "agent-receipts-doctor.roundtrip"
)

// config holds resolved paths shared across checks.
type config struct {
	socketPath string
	dbPath     string
	pubKeyPath string
	chainID    string
}

// Run executes the doctor subcommand. Returns one of the Exit* constants;
// cmd/agent-receipts/main.go forwards it to os.Exit.
//
// envLookup is split out so tests can inject a deterministic environment. Pass
// os.Getenv for the production caller.
func Run(args []string, stdout, stderr io.Writer, envLookup func(string) string) int {
	if envLookup == nil {
		envLookup = os.Getenv
	}
	envOr := func(key, fallback string) string {
		if v := envLookup(key); v != "" {
			return v
		}
		return fallback
	}

	keyPath := envOr("AGENTRECEIPTS_KEY", daemon.DefaultKeyPath())
	defaultPubKey := envOr("AGENTRECEIPTS_PUBLIC_KEY", daemon.DefaultPublicKeyPath(keyPath))

	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socketPath := fs.String("socket", envOr("AGENTRECEIPTS_SOCKET", daemon.DefaultSocketPath()), "Unix-domain socket path the daemon listens on (env: AGENTRECEIPTS_SOCKET)")
	dbPath := fs.String("db", envOr("AGENTRECEIPTS_DB", daemon.DefaultDBPath()), "SQLite receipt-store path (env: AGENTRECEIPTS_DB)")
	pubKeyPath := fs.String("public-key", defaultPubKey, "PEM-encoded SPKI public key path (env: AGENTRECEIPTS_PUBLIC_KEY)")
	chainID := fs.String("chain-id", "", "Chain id to inspect; when unset, doctor auto-detects the daemon's active root chain from the store and falls back to today's UTC date if the store is empty (env: AGENTRECEIPTS_CHAIN_ID)")
	asJSON := fs.Bool("json", false, "Emit structured JSON instead of human-readable lines")
	noRoundtrip := fs.Bool("no-roundtrip", false, "Skip the synthetic round-trip check (no event is written to the chain)")
	warnAsError := fs.Bool("warn-as-error", false, "Exit non-zero when any check warns, not only on failures")
	roundtripTimeout := fs.Duration("roundtrip-timeout", 3*time.Second, "How long to wait for the synthetic event to land in the DB")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsageError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "obsigna doctor: unexpected positional argument(s): %v\n", fs.Args())
		return ExitUsageError
	}

	// Resolve the chain id to inspect. An explicit flag wins, then the env var,
	// then the daemon's active root chain discovered from the store. The bare
	// UTC date is only a last-resort fallback for an empty store: the daemon
	// pins its chain id at startup (config or per-OS default) and rolls a "-N"
	// suffix across restarts, so today's date rarely names the live chain.
	resolvedChainID := *chainID
	if resolvedChainID == "" {
		resolvedChainID = envLookup("AGENTRECEIPTS_CHAIN_ID")
	}
	if resolvedChainID == "" {
		resolvedChainID = resolveChainID(*dbPath)
	}

	cfg := config{
		socketPath: *socketPath,
		dbPath:     *dbPath,
		pubKeyPath: *pubKeyPath,
		chainID:    resolvedChainID,
	}

	results := runChecks(cfg, envLookup, *noRoundtrip, *roundtripTimeout)

	report := Report{Checks: results, OK: !hasFailures(results, *warnAsError)}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "obsigna doctor: encode JSON: %v\n", err)
			return ExitUsageError
		}
	} else {
		writeHuman(stdout, results, *warnAsError)
	}

	if report.OK {
		return ExitOK
	}
	return ExitUnhealthy
}

// runChecks executes every check in pipeline order and returns their results.
func runChecks(cfg config, envLookup func(string) string, noRoundtrip bool, roundtripTimeout time.Duration) []Result {
	results := []Result{
		checkDaemonProcess(cfg.socketPath),
		checkSocket(cfg.socketPath),
		checkEmitterDialPath(cfg.socketPath, envLookup),
		checkDBPermissions(cfg.dbPath),
		checkSchema(cfg.dbPath, cfg.pubKeyPath),
		checkPeerCredCapture(),
		checkChainHead(cfg.dbPath, cfg.pubKeyPath, cfg.chainID),
	}
	if noRoundtrip {
		results = append(results, Result{
			Check:  "round-trip",
			Status: StatusWarn,
			Reason: "skipped (--no-roundtrip); the load-bearing check that a real event traverses the full pipeline did not run",
		})
	} else {
		results = append(results, checkRoundtrip(cfg.socketPath, cfg.dbPath, cfg.chainID, roundtripTimeout))
	}
	return results
}

// hasFailures reports whether the run should exit non-zero: any fail always
// counts; warnings count only under warnAsError.
func hasFailures(results []Result, warnAsError bool) bool {
	for _, r := range results {
		if r.Status == StatusFail {
			return true
		}
		if warnAsError && r.Status == StatusWarn {
			return true
		}
	}
	return false
}

// checkDaemonProcess (check 1) confirms a daemon is reachable on the socket.
// The "sole writer / started by expected unit" facets of ADR-0010 are not
// asserted here directly — the round-trip check is the authoritative proof that
// the listening process owns the write path; this check just establishes the
// daemon is up and answering on the path the emitter would dial.
func checkDaemonProcess(socketPath string) Result {
	const name = "daemon process"
	if socketPath == "" {
		return Result{Check: name, Status: StatusFail, Reason: "no socket path resolved (set AGENTRECEIPTS_SOCKET or --socket)"}
	}
	conn, err := net.DialTimeout("unix", socketPath, 200*time.Millisecond)
	if err != nil {
		return Result{
			Check:  name,
			Status: StatusFail,
			Reason: fmt.Sprintf("no daemon listening on %s (%v)", socketPath, err),
			Fix:    "start the daemon: obsigna daemon run",
		}
	}
	_ = conn.Close()
	return Result{Check: name, Status: StatusOK, Reason: fmt.Sprintf("daemon reachable on %s", socketPath)}
}

// checkSocket (check 2) confirms the socket exists, is a socket, and is not
// world-accessible. Connectability is covered by checkDaemonProcess.
func checkSocket(socketPath string) Result {
	const name = "socket"
	if socketPath == "" {
		return Result{Check: name, Status: StatusFail, Reason: "no socket path resolved"}
	}
	info, err := os.Lstat(socketPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("%s does not exist", socketPath), Fix: "start the daemon: obsigna daemon run"}
		}
		return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("stat %s: %v", socketPath, err)}
	}
	if info.Mode()&os.ModeSocket == 0 {
		return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("%s exists but is not a socket (mode %s)", socketPath, info.Mode())}
	}
	perm := info.Mode().Perm()
	owner := ownerString(info)
	// The daemon binds the socket 0660 (group governs who may emit). World bits
	// would let any local user connect — flag but do not fail, since the
	// peer-credential trust boundary still holds.
	if perm&0o007 != 0 {
		return Result{
			Check:  name,
			Status: StatusWarn,
			Reason: fmt.Sprintf("%s is world-accessible (mode %04o, %s); expected 0660", socketPath, perm, owner),
			Fix:    fmt.Sprintf("chmod 0660 %s", socketPath),
		}
	}
	return Result{Check: name, Status: StatusOK, Reason: fmt.Sprintf("%s present, mode %04o, %s", socketPath, perm, owner)}
}

// checkEmitterDialPath (check 3) confirms the path an emitter on this host
// would dial matches the path doctor is treating as the daemon's listening
// path. Drift here is the classic "tool calls succeed but nothing is recorded"
// failure. Falls back to a warning rather than a hard fail because the emitter
// side is only inferred from env/defaults, not a discovered emitter config.
func checkEmitterDialPath(socketPath string, envLookup func(string) string) Result {
	const name = "emitter dial path"
	// emitter.DefaultSocketPath consults AGENTRECEIPTS_SOCKET first, then the
	// per-OS default — exactly what an SDK emitter with no explicit override
	// resolves. Drive it through the injected env so tests are deterministic.
	dialPath := envLookup("AGENTRECEIPTS_SOCKET")
	source := "AGENTRECEIPTS_SOCKET"
	if dialPath == "" {
		dialPath = emitter.DefaultSocketPath()
		source = "per-OS default"
	}
	if dialPath == "" {
		return Result{Check: name, Status: StatusWarn, Reason: "could not infer the emitter dial path on this platform; set AGENTRECEIPTS_SOCKET so emitter and daemon agree"}
	}
	if dialPath != socketPath {
		return Result{
			Check:  name,
			Status: StatusWarn,
			Reason: fmt.Sprintf("an emitter would dial %s (%s) but the daemon is being checked on %s; events may never reach the daemon", dialPath, source, socketPath),
			Fix:    "set AGENTRECEIPTS_SOCKET to one value for both the daemon and its emitters",
		}
	}
	return Result{Check: name, Status: StatusOK, Reason: fmt.Sprintf("emitter and daemon agree on %s (%s)", dialPath, source)}
}

// checkDBPermissions (check 4) confirms the receipt DB — and its WAL/SHM
// siblings — are no looser than 0640 per ADR-0010 § Read interface. The daemon
// (tightenDBFiles) holds the same ceiling over <db>, <db>-wal, and <db>-shm; a
// world-readable WAL still leaks recent receipt content even when the main file
// is locked down, so doctor checks all three.
func checkDBPermissions(dbPath string) Result {
	const name = "db permissions"
	if dbPath == "" {
		return Result{Check: name, Status: StatusFail, Reason: "no DB path resolved (set AGENTRECEIPTS_DB or --db)"}
	}
	info, err := os.Lstat(dbPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("%s does not exist (has the daemon ever run?)", dbPath), Fix: "start the daemon: obsigna daemon run"}
		}
		return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("stat %s: %v", dbPath, err)}
	}
	if !info.Mode().IsRegular() {
		return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("%s is not a regular file (mode %s)", dbPath, info.Mode())}
	}
	perm := info.Mode().Perm()
	owner := ownerString(info)
	if perm&^allowedDBPerm != 0 {
		return Result{
			Check:  name,
			Status: StatusFail,
			Reason: fmt.Sprintf("%s has mode %04o (looser than 0640); receipts are exposed to other users", dbPath, perm),
			Fix:    fmt.Sprintf("chmod 0640 %s", dbPath),
		}
	}
	// WAL/SHM siblings: missing is fine (non-WAL mode, or a quiescent DB that
	// already checkpointed), but a present sibling that is non-regular or looser
	// than 0640 is the same leak as a loose main file.
	for _, suffix := range []string{"-wal", "-shm"} {
		sib := dbPath + suffix
		si, err := os.Lstat(sib)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("stat %s: %v", sib, err)}
		}
		if !si.Mode().IsRegular() {
			return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("%s is not a regular file (mode %s)", sib, si.Mode())}
		}
		if si.Mode().Perm()&^allowedDBPerm != 0 {
			return Result{
				Check:  name,
				Status: StatusFail,
				Reason: fmt.Sprintf("%s has mode %04o (looser than 0640); recent receipts in the WAL are exposed to other users", sib, si.Mode().Perm()),
				Fix:    fmt.Sprintf("chmod 0640 %s", sib),
			}
		}
	}
	return Result{Check: name, Status: StatusOK, Reason: fmt.Sprintf("%s mode %04o, %s (WAL/SHM siblings within 0640)", dbPath, perm, owner)}
}

// checkSchema (check 5) confirms the DB is readable and the daemon-published
// public key parses, and reports the key fingerprint and receipt count. The
// SQLite store has no explicit schema-version row; a successful Stats() query
// confirms the receipts table and its columns are present and queryable.
func checkSchema(dbPath, pubKeyPath string) Result {
	const name = "schema/version"
	if dbPath == "" {
		return Result{Check: name, Status: StatusFail, Reason: "no DB path resolved"}
	}
	s, err := store.OpenReadOnly(dbPath)
	if err != nil {
		return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("open store %s: %v", dbPath, err)}
	}
	defer s.Close()
	stats, err := s.Stats()
	if err != nil {
		return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("query store schema: %v", err)}
	}

	fingerprint, err := publicKeyFingerprint(pubKeyPath)
	if err != nil {
		return Result{
			Check:  name,
			Status: StatusFail,
			Reason: fmt.Sprintf("public key %s: %v", pubKeyPath, err),
			Fix:    "ensure the daemon has published its public key (it does so on every startup)",
		}
	}
	return Result{
		Check:  name,
		Status: StatusOK,
		Reason: fmt.Sprintf("schema present, %d receipt(s) across %d chain(s), signing key %s", stats.Total, stats.Chains, fingerprint),
	}
}

// checkPeerCredCapture (check 6) reports the OS peer-credential primitive
// available on this host. doctor runs on the same host as the daemon, so the
// platform gate is the capability report. Unsupported platforms fail: without
// peer-cred capture the audit trail's identity attestation is meaningless.
func checkPeerCredCapture() Result {
	const name = "peer credentials"
	switch runtime.GOOS {
	case "linux":
		return Result{Check: name, Status: StatusOK, Reason: "linux: SO_PEERCRED available for OS-attested peer identity"}
	case "darwin":
		return Result{Check: name, Status: StatusOK, Reason: "darwin: LOCAL_PEERCRED + LOCAL_PEEREPID available for OS-attested peer identity"}
	default:
		return Result{
			Check:  name,
			Status: StatusFail,
			Reason: fmt.Sprintf("%s: no supported peer-credential primitive; the daemon does not run here (Phase 1 supports linux and darwin)", runtime.GOOS),
		}
	}
}

// checkChainHead (check 7) verifies the stored chain end-to-end using the same
// code path as `agent-receipts verify`. It surfaces the verifier's "unknown"
// termination status as a warning rather than treating it as fine (issue #475):
// an unknown head means the chain was never cleanly terminated.
//
// The full chain is verified rather than only the tail N receipts: hash-link
// verification is meaningless without the prefix, so a partial-tail check could
// not actually establish integrity.
func checkChainHead(dbPath, pubKeyPath, chainID string) Result {
	const name = "chain head"
	if dbPath == "" {
		return Result{Check: name, Status: StatusFail, Reason: "no DB path resolved"}
	}
	pubPEM, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("read public key %s: %v", pubKeyPath, err)}
	}
	s, err := store.OpenReadOnly(dbPath)
	if err != nil {
		return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("open store %s: %v", dbPath, err)}
	}
	defer s.Close()
	result, err := s.VerifyStoredChain(chainID, string(pubPEM))
	if err != nil {
		return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("verify chain %q: %v", chainID, err)}
	}
	if !result.Valid {
		reason := fmt.Sprintf("chain %q BROKEN at receipt %d", chainID, result.BrokenAt)
		if result.Error != "" {
			reason += ": " + result.Error
		}
		return Result{Check: name, Status: StatusFail, Reason: reason}
	}
	if result.Length == 0 {
		return Result{Check: name, Status: StatusWarn, Reason: fmt.Sprintf("chain %q has no receipts yet; nothing to verify", chainID)}
	}
	if result.Status == "unknown" {
		return Result{
			Check:  name,
			Status: StatusWarn,
			Reason: fmt.Sprintf("chain %q verifies (%d receipts) but its head is not a clean terminator (status=unknown); a daemon crash or kill leaves the chain open", chainID, result.Length),
		}
	}
	reason := fmt.Sprintf("chain %q VALID (%d receipts), status %s", chainID, result.Length, result.Status)
	if result.IncompleteToolRoundtrip {
		reason += "; advisory: final tool call has no result receipt"
	}
	if result.IncompleteSession {
		reason += "; advisory: PTY session open/close imbalance"
	}
	return Result{Check: name, Status: StatusOK, Reason: reason}
}

// checkRoundtrip (check 8) is the load-bearing check. It emits a synthetic
// event through the documented emitter→socket→daemon→SQLite path and confirms
// it lands in the DB with a fresh OS-attested peer credential matching this
// process. This distinguishes "the SDK can write a row to SQLite" from "the
// pipeline ADR-0010 describes is intact": only a real traversal produces a
// peer credential the daemon attested for *our* PID/UID.
//
// The synthetic event is deliberately visible in the chain: the daemon derives
// its action.type as "<channel>.<tool.name>", so channel "doctor" + tool
// "agent-receipts-doctor.roundtrip" yields action.type
// "doctor.agent-receipts-doctor.roundtrip" (taxonomy.DiagnosticRoundtripActionType,
// a low-risk diagnostic self-check) — that is the value operators filter on. A
// "test mode" that bypassed the chain would defeat the property being tested.
func checkRoundtrip(socketPath, dbPath, chainID string, timeout time.Duration) Result {
	const name = "round-trip"
	if socketPath == "" || dbPath == "" {
		return Result{Check: name, Status: StatusFail, Reason: "socket and DB paths are both required for the round-trip check"}
	}

	sessionID := "doctor-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(socketPath),
		emitter.WithSessionID(sessionID),
		emitter.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
	if err != nil {
		return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("construct emitter: %v", err)}
	}
	defer em.Close()

	emitCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err = em.Emit(emitCtx, emitter.Event{
		Channel:  roundtripChannel,
		Tool:     emitter.Tool{Name: roundtripTool},
		Decision: "allowed",
	})
	if err != nil {
		return Result{
			Check:  name,
			Status: StatusFail,
			Reason: fmt.Sprintf("synthetic event did not reach the daemon: %v", err),
			Fix:    "confirm the daemon is listening on the same socket path",
		}
	}

	wantPID := int32(os.Getpid())
	wantUID := uint32(os.Getuid())
	wantExe, _ := os.Executable()

	found, err := pollForRoundtrip(dbPath, chainID, sessionID, timeout)
	if err != nil {
		return Result{Check: name, Status: StatusFail, Reason: err.Error()}
	}
	if found == nil {
		return Result{
			Check:  name,
			Status: StatusFail,
			Reason: fmt.Sprintf("synthetic event was accepted by the daemon but did not land in %s within %s; the daemon may not be the sole writer of this DB", dbPath, timeout),
		}
	}

	pc := found.CredentialSubject.Action.PeerCredential
	return evalRoundtripPeer(runtime.GOOS, pc, found.CredentialSubject.Chain.Sequence, wantPID, wantUID, wantExe)
}

// evalRoundtripPeer judges a round-trip receipt's captured peer credential
// against the doctor process's identity. Split out (with goos as a parameter)
// so the darwin-specific branch is unit-testable on any host.
//
//   - PID and UID must match → ok (the fresh, daemon-attested identity).
//   - darwin pid=0 with a matching UID → warn, not fail: macOS LOCAL_PEEREPID
//     reads the live peer pcb and returns ENOTCONN if the peer detaches between
//     accept() and the daemon's getsockopt, recorded as pid=0 (see
//     peercred_darwin.go). The UID still comes from LOCAL_PEERCRED (captured at
//     connect time), so a UID match means the event did traverse the pipeline;
//     we just could not pin the PID. Treating this as a hard "mismatch" would
//     make doctor flaky on macOS for a known, benign race.
//   - any other PID/UID mismatch → fail (a credential not freshly attested for
//     this process).
//   - exe_path differing when both are known → warn: PID+UID already prove
//     freshness, and exe resolution can legitimately differ across the OS
//     primitives doctor and the daemon use.
func evalRoundtripPeer(goos string, pc *receipt.PeerCredential, seq int, wantPID int32, wantUID uint32, wantExe string) Result {
	const name = "round-trip"
	if pc == nil {
		return Result{Check: name, Status: StatusFail, Reason: fmt.Sprintf("round-trip receipt (seq %d) has no peer credential; peer-cred capture is not working", seq)}
	}
	uidMatch := pc.UID != nil && *pc.UID == wantUID

	if goos == "darwin" && pc.PID == 0 && uidMatch {
		return Result{
			Check:  name,
			Status: StatusWarn,
			Reason: fmt.Sprintf("synthetic event landed at seq %d (uid=%d matches) but the daemon recorded pid=0 — the macOS LOCAL_PEEREPID race left the PID unresolved; the pipeline is intact, the fresh PID just could not be confirmed", seq, wantUID),
		}
	}

	if pc.PID != wantPID || !uidMatch {
		gotUID := "nil"
		if pc.UID != nil {
			gotUID = strconv.FormatUint(uint64(*pc.UID), 10)
		}
		return Result{
			Check:  name,
			Status: StatusFail,
			Reason: fmt.Sprintf("peer credential mismatch: receipt records pid=%d uid=%s but doctor is pid=%d uid=%d; the recorded credential was not freshly attested for this process", pc.PID, gotUID, wantPID, wantUID),
		}
	}
	if wantExe != "" && pc.ExePath != "" && pc.ExePath != wantExe {
		return Result{
			Check:  name,
			Status: StatusWarn,
			Reason: fmt.Sprintf("synthetic event landed at seq %d with a fresh peer credential (pid=%d, uid=%d), but exe_path %q differs from doctor's %q", seq, pc.PID, wantUID, pc.ExePath, wantExe),
		}
	}
	return Result{
		Check:  name,
		Status: StatusOK,
		Reason: fmt.Sprintf("synthetic event traversed the full pipeline and landed at seq %d with a fresh peer credential (pid=%d, uid=%d)", seq, pc.PID, wantUID),
	}
}

// pollForRoundtrip polls the DB until a receipt matching the doctor session id
// and the doctor.agent-receipts-doctor.roundtrip action type
// (taxonomy.DiagnosticRoundtripActionType) appears, or the timeout elapses.
// Returns (nil, nil) when nothing landed in time (not an error — the caller
// reports it as a failed round-trip with pipeline context).
func pollForRoundtrip(dbPath, chainID, sessionID string, timeout time.Duration) (*receipt.AgentReceipt, error) {
	deadline := time.Now().Add(timeout)
	actionType := taxonomy.DiagnosticRoundtripActionType
	for {
		s, err := store.OpenReadOnly(dbPath)
		if err != nil {
			return nil, fmt.Errorf("open store %s: %w", dbPath, err)
		}
		cid := chainID
		limit := 50
		receipts, qErr := s.QueryReceipts(store.Query{
			ChainID:     &cid,
			ActionType:  &actionType,
			Limit:       &limit,
			NewestFirst: true,
		})
		_ = s.Close()
		if qErr != nil {
			return nil, fmt.Errorf("query store %s: %w", dbPath, qErr)
		}
		for i := range receipts {
			if receipts[i].Issuer.SessionID == sessionID {
				return &receipts[i], nil
			}
		}
		if time.Now().After(deadline) {
			return nil, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// resolveChainID picks the chain id doctor inspects when the operator did not
// name one explicitly: the daemon's active root chain if the store has one,
// otherwise today's UTC date. The date fallback only matters for a brand-new,
// empty store — once any receipt exists, detectActiveRootChain names the live
// chain the daemon is actually appending to (see daemon advanceChainID).
func resolveChainID(dbPath string) string {
	if cid := detectActiveRootChain(dbPath); cid != "" {
		return cid
	}
	return time.Now().UTC().Format("2006-01-02")
}

// detectActiveRootChain returns the chain id of the most recently written root
// receipt — the chain the daemon is actively appending to — or "" when the
// store is empty/unreadable. The store excludes agent sub-chains and orders by
// write recency (see store.LatestRootChainID); doctor's chain-head and
// round-trip checks must target that root chain. Read-only access keeps doctor
// safe to run against a live daemon (the sole writer).
func detectActiveRootChain(dbPath string) string {
	if dbPath == "" {
		return ""
	}
	s, err := store.OpenReadOnly(dbPath)
	if err != nil {
		return ""
	}
	defer s.Close()
	chainID, found, err := s.LatestRootChainID()
	if err != nil || !found {
		return ""
	}
	return chainID
}

// publicKeyFingerprint parses an Ed25519 SPKI public key from a PEM file and
// returns a short "sha256:<hex>" fingerprint over the DER bytes. It rejects
// non-Ed25519 keys: Ed25519 is the only signing algorithm the protocol
// supports, so a different key type means the published key could never have
// signed the chain — reporting a fingerprint for it would be misleading.
func publicKeyFingerprint(path string) (string, error) {
	pubPEM, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return "", errors.New("PEM decode failed (no PUBLIC KEY block)")
	}
	if block.Type != "PUBLIC KEY" {
		return "", fmt.Errorf("PEM block type is %q, want PUBLIC KEY", block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse SPKI public key: %w", err)
	}
	if _, ok := parsed.(ed25519.PublicKey); !ok {
		return "", fmt.Errorf("public key is %T, want ed25519.PublicKey (Ed25519 is the only supported algorithm)", parsed)
	}
	sum := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:8]), nil
}

// writeHuman renders the report as one line per check plus a summary line.
func writeHuman(w io.Writer, results []Result, warnAsError bool) {
	fmt.Fprintln(w, "obsigna doctor — pipeline health")
	fmt.Fprintln(w)
	var ok, warn, fail int
	for _, r := range results {
		switch r.Status {
		case StatusOK:
			ok++
		case StatusWarn:
			warn++
		case StatusFail:
			fail++
		}
		fmt.Fprintf(w, "[%-4s] %-18s %s\n", r.Status, r.Check, r.Reason)
		if r.Fix != "" {
			fmt.Fprintf(w, "         fix: %s\n", r.Fix)
		}
	}
	fmt.Fprintln(w)
	verdict := "PASS"
	if fail > 0 || (warnAsError && warn > 0) {
		verdict = "FAIL"
	}
	fmt.Fprintf(w, "doctor: %s (%d ok, %d warn, %d fail)\n", verdict, ok, warn, fail)
}
