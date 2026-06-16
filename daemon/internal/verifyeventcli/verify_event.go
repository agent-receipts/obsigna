// Package verifyeventcli implements the `obsigna receipt verify-event`
// subcommand: end-to-end pipeline-provenance evidence for a single historical
// receipt. Where `verify` answers "is this chain internally consistent?",
// verify-event answers the narrower question that matters most for trust: "was
// this specific receipt produced by the path ADR-0010 describes — emitter →
// daemon → chain — as opposed to being written to SQLite by some other path?"
//
// It composes the existing chain checks (signature, hash linkage, sequence
// contiguity — #479) with the daemon-captured peer credential (#511) that
// ADR-0010 § Permissions and trust calls the load-bearing evidence: the agent's
// self-asserted identity is untrusted; peer attestation is what makes the audit
// meaningful. verify-event is the verifier-side counterpart that actually uses
// that field.
//
// Deliberately narrow scope: it does NOT attest that the audited action
// happened in the world (no protocol can), nor that the emitter binary is
// trustworthy beyond its exe_path matching an operator allowlist. Binary
// integrity attestation is a separate, ADR-grade decision.
//
// The store is opened read-only so verify-event is safe to run against a live
// daemon's database or a forensic snapshot, and it never emits — unlike
// `doctor`'s synthetic round-trip, this is a cheap historical read.
//
// Logic lives here, away from cmd/agent-receipts/main.go, so tests can drive
// the subcommand directly with captured I/O without shelling out to a binary.
package verifyeventcli

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// Exit codes are part of the CLI contract — CI gates and triage scripts pivot
// on them. Keep these stable.
//
// ExitNoProvenance (3) is the distinction the Max incident exposed and the
// reason this subcommand exists: a receipt can verify cryptographically yet
// carry no evidence that it traversed the documented pipeline. A CI gate that
// requires provenance treats 3 as a failure; one that only requires
// cryptographic validity treats 0 and 3 alike. Splitting them into separate
// codes is what lets operators choose.
const (
	ExitOK           = 0 // verified AND pipeline-provenance confirmed
	ExitVerifyFailed = 1 // a check failed — the receipt is suspect, investigate
	ExitUsageError   = 2 // bad flags / unreadable DB or key / no receipt selected
	ExitNoProvenance = 3 // verifies cryptographically but lacks peer-credential evidence
)

// checkStatus is the outcome of one provenance check.
type checkStatus string

const (
	statusPass checkStatus = "pass" // check held
	statusFail checkStatus = "fail" // check failed — receipt is suspect
	statusWarn checkStatus = "warn" // operator-policy concern, not a protocol failure
	statusNA   checkStatus = "n/a"  // check could not run (e.g. evidence absent by design)
)

// check is one structured provenance check result.
type check struct {
	Name   string      `json:"name"`
	Status checkStatus `json:"status"`
	Detail string      `json:"detail,omitempty"`
}

// Check names are constants so verdict logic keys off an identifier rather than
// a presentation string — renaming a check can't silently change which check
// deriveVerdict treats as the peer-credential signal.
const (
	checkSignatureName       = "signature"
	checkHashLinkageName     = "hash linkage"
	checkPeerCredentialName  = "peer credential"
	checkEmitterIdentityName = "emitter identity"
	checkSchemaVersionName   = "schema version"
	checkChainContextName    = "chain context"
)

// verdict is the per-receipt provenance conclusion.
type verdict string

const (
	verdictConfirmed    verdict = "verified_provenance_confirmed"   // crypto holds and the pipeline produced it
	verdictNoProvenance verdict = "verified_no_provenance_evidence" // crypto holds but no peer-credential evidence
	verdictFailed       verdict = "failed"                          // a check failed — suspect
)

// eventResult is the full verify-event result for one receipt.
type eventResult struct {
	ReceiptID string  `json:"receipt_id"`
	ChainID   string  `json:"chain_id"`
	Sequence  int     `json:"sequence"`
	Checks    []check `json:"checks"`
	Verdict   verdict `json:"verdict"`
}

// jsonOutput wraps the per-receipt results for --json. A wrapper (rather than a
// bare array) leaves room to grow without breaking parsers that key off
// "results".
type jsonOutput struct {
	Results []eventResult `json:"results"`
}

// Run executes the verify-event subcommand with the given args (sans the
// program name and "verify-event" token), writing human-readable output to
// stdout and diagnostics to stderr. Returns one of the Exit* constants.
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

	fs := flag.NewFlagSet("receipt verify-event", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: obsigna receipt verify-event (--id <id> | --chain-head | --since <dur>) [flags]")
		fmt.Fprintln(stderr, "\nVerify that a specific historical receipt was produced by the documented")
		fmt.Fprintln(stderr, "emitter→daemon→chain pipeline, not written to the store by another path.")
		fmt.Fprintln(stderr, "\nExactly one selector is required:")
		fmt.Fprintln(stderr, "  --id <id>       a single receipt by its receipt id")
		fmt.Fprintln(stderr, "  --chain-head    the most recent receipt in the chain")
		fmt.Fprintln(stderr, "  --since <dur>   every receipt issued within the trailing window (e.g. 10m, 24h)")
		fmt.Fprintln(stderr, "\nFlags:")
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "\nExit codes: 0 verified+provenance, 1 check failed, 2 usage error, 3 verified but no provenance evidence")
	}
	dbPath := fs.String("db", envOr("AGENTRECEIPTS_DB", daemon.DefaultDBPath()), "SQLite receipt-store path (env: AGENTRECEIPTS_DB)")
	pubKeyPath := fs.String("public-key", defaultPubKey, "PEM-encoded SPKI public key path (env: AGENTRECEIPTS_PUBLIC_KEY)")
	chainID := fs.String("chain-id", envLookup("AGENTRECEIPTS_CHAIN_ID"), "Chain id (env: AGENTRECEIPTS_CHAIN_ID); with --chain-head it selects the chain (required only if the store holds more than one); with --since it is an optional filter (default: all chains)")
	id := fs.String("id", "", "Select the receipt with this receipt id")
	chainHead := fs.Bool("chain-head", false, "Select the most recent receipt in the chain")
	since := fs.String("since", "", "Select every receipt issued within the trailing duration window (e.g. 10m, 24h)")
	allowlistRaw := fs.String("emitter-allowlist", envLookup("AGENTRECEIPTS_EMITTER_ALLOWLIST"), "Comma-separated exe_path allowlist of expected emitters (env: AGENTRECEIPTS_EMITTER_ALLOWLIST); mismatches warn, never fail")
	asJSON := fs.Bool("json", false, "Emit machine-readable JSON instead of human-readable text")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsageError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "obsigna receipt verify-event: unexpected positional argument(s): %v (use a selector flag)\n", fs.Args())
		return ExitUsageError
	}

	// Exactly one selector. Zero is the common scripting mistake (operator
	// forgot what to verify); more than one is ambiguous.
	selectors := 0
	if *id != "" {
		selectors++
	}
	if *chainHead {
		selectors++
	}
	if *since != "" {
		selectors++
	}
	if selectors == 0 {
		fmt.Fprintln(stderr, "obsigna receipt verify-event: a selector is required (--id, --chain-head, or --since)")
		return ExitUsageError
	}
	if selectors > 1 {
		fmt.Fprintln(stderr, "obsigna receipt verify-event: selectors --id, --chain-head and --since are mutually exclusive")
		return ExitUsageError
	}

	if *dbPath == "" {
		fmt.Fprintln(stderr, "obsigna receipt verify-event: --db is required (no AGENTRECEIPTS_DB and no home directory)")
		return ExitUsageError
	}
	if *pubKeyPath == "" {
		fmt.Fprintln(stderr, "obsigna receipt verify-event: --public-key is required (set AGENTRECEIPTS_PUBLIC_KEY directly, or AGENTRECEIPTS_KEY so its <KeyPath>.pub default can be derived)")
		return ExitUsageError
	}

	pubPEM, err := os.ReadFile(*pubKeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "obsigna receipt verify-event: read public key: %v\n", err)
		return ExitUsageError
	}
	// Validate key shape upfront so a malformed key surfaces as a usage error
	// rather than being routed through per-receipt signature failures, which
	// would falsely implicate the receipts.
	if err := validatePublicKeyPEM(pubPEM); err != nil {
		fmt.Fprintf(stderr, "obsigna receipt verify-event: invalid public key at %s: %v\n", *pubKeyPath, err)
		return ExitUsageError
	}

	allowlist := parseAllowlist(*allowlistRaw)

	s, err := store.OpenReadOnly(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "obsigna receipt verify-event: open store: %v\n", err)
		return ExitUsageError
	}
	defer s.Close()

	targets, code := resolveTargets(s, *id, *chainHead, *since, *chainID, stderr)
	if code != ExitOK {
		return code
	}

	// Verify each distinct chain once, then read per-receipt results out of the
	// cached ChainVerification — VerifyChain is O(n) in signatures, so this
	// avoids re-verifying the chain once per target when --since matches several.
	chainCache := map[string]chainCtx{}
	results := make([]eventResult, 0, len(targets))
	for _, t := range targets {
		ctx, ok := chainCache[t.chainID]
		if !ok {
			chain, err := s.GetChain(t.chainID)
			if err != nil {
				fmt.Fprintf(stderr, "obsigna receipt verify-event: read chain %q: %v\n", t.chainID, err)
				return ExitUsageError
			}
			cv := receipt.VerifyChain(chain, string(pubPEM))
			ctx = chainCtx{
				chain:          chain,
				cv:             cv,
				indexByID:      indexByID(chain),
				firstLinkBreak: firstLinkBreak(cv),
				structuralErr:  structuralErr(cv),
			}
			chainCache[t.chainID] = ctx
		}
		idx, ok := ctx.indexByID[t.receiptID]
		if !ok {
			// The receipt resolved from the store but is absent from its own
			// chain load — only possible under concurrent deletion or a store
			// inconsistency. Treat as a usage-level read error, not a verdict.
			fmt.Fprintf(stderr, "obsigna receipt verify-event: receipt %q not found in chain %q\n", t.receiptID, t.chainID)
			return ExitUsageError
		}
		results = append(results, evaluate(ctx, idx, allowlist))
	}

	if *asJSON {
		return writeJSON(stdout, stderr, results)
	}
	writeHuman(stdout, results)
	return exitCode(results)
}

// chainCtx caches a loaded chain and its single verification pass, plus values
// derived from it once so a multi-target --since batch doesn't recompute them
// per receipt: the first hash-linkage break (-1 if none) and any whole-chain
// structural-integrity error not already attributed to a per-receipt check.
type chainCtx struct {
	chain          []receipt.AgentReceipt
	cv             receipt.ChainVerification
	indexByID      map[string]int
	firstLinkBreak int
	structuralErr  string
}

// target is one selected receipt awaiting verification.
type target struct {
	receiptID string
	chainID   string
}

// resolveTargets turns the chosen selector into the set of receipts to verify.
// Exactly one of id / chainHead / since is set (the caller enforces this).
func resolveTargets(s *store.Store, id string, chainHead bool, since, chainID string, stderr io.Writer) ([]target, int) {
	switch {
	case id != "":
		r, err := s.GetByID(id)
		if err != nil {
			fmt.Fprintf(stderr, "obsigna receipt verify-event: read receipt %q: %v\n", id, err)
			return nil, ExitUsageError
		}
		if r == nil {
			fmt.Fprintf(stderr, "obsigna receipt verify-event: no receipt with id %q\n", id)
			return nil, ExitUsageError
		}
		return []target{{receiptID: r.ID, chainID: r.CredentialSubject.Chain.ChainID}}, ExitOK

	case chainHead:
		resolved, code := resolveChainID(s, chainID, stderr)
		if code != ExitOK {
			return nil, code
		}
		r, err := s.GetChainTailReceipt(resolved)
		if err != nil {
			fmt.Fprintf(stderr, "obsigna receipt verify-event: read chain head %q: %v\n", resolved, err)
			return nil, ExitUsageError
		}
		if r == nil {
			fmt.Fprintf(stderr, "obsigna receipt verify-event: chain %q holds no receipts\n", resolved)
			return nil, ExitUsageError
		}
		return []target{{receiptID: r.ID, chainID: resolved}}, ExitOK

	default: // since
		d, err := time.ParseDuration(since)
		if err != nil {
			fmt.Fprintf(stderr, "obsigna receipt verify-event: invalid --since duration %q: %v\n", since, err)
			return nil, ExitUsageError
		}
		if d <= 0 {
			fmt.Fprintf(stderr, "obsigna receipt verify-event: --since must be positive, got %q\n", since)
			return nil, ExitUsageError
		}
		cutoff := time.Now().UTC().Add(-d).Format(time.RFC3339)
		q := store.Query{After: &cutoff}
		if chainID != "" {
			q.ChainID = &chainID
		}
		rs, err := s.QueryReceipts(q)
		if err != nil {
			fmt.Fprintf(stderr, "obsigna receipt verify-event: query receipts: %v\n", err)
			return nil, ExitUsageError
		}
		if len(rs) == 0 {
			fmt.Fprintf(stderr, "obsigna receipt verify-event: no receipts issued within %s\n", since)
			return nil, ExitUsageError
		}
		targets := make([]target, len(rs))
		for i, r := range rs {
			targets[i] = target{receiptID: r.ID, chainID: r.CredentialSubject.Chain.ChainID}
		}
		return targets, ExitOK
	}
}

// resolveChainID mirrors showcli: an explicit chain id is used verbatim;
// otherwise the sole chain is used silently and ambiguity is a usage error.
func resolveChainID(s *store.Store, requested string, stderr io.Writer) (string, int) {
	if requested != "" {
		return requested, ExitOK
	}
	chains, err := s.DistinctChainIDs()
	if err != nil {
		fmt.Fprintf(stderr, "obsigna receipt verify-event: enumerate chains: %v\n", err)
		return "", ExitUsageError
	}
	switch len(chains) {
	case 0:
		fmt.Fprintln(stderr, "obsigna receipt verify-event: store holds no receipts")
		return "", ExitUsageError
	case 1:
		return chains[0], ExitOK
	default:
		fmt.Fprintf(stderr, "obsigna receipt verify-event: store holds %d chains; pass --chain-id to select one. Available chains:\n", len(chains))
		for _, c := range chains {
			fmt.Fprintf(stderr, "  %s\n", c)
		}
		return "", ExitUsageError
	}
}

// evaluate runs the six provenance checks for the receipt at chain index idx
// and derives its verdict.
func evaluate(ctx chainCtx, idx int, allowlist []string) eventResult {
	r := ctx.chain[idx]
	checks := []check{
		checkSignature(ctx.cv, idx),
		checkHashLinkage(ctx.firstLinkBreak, idx),
		checkPeerPresent(r),
		checkEmitterIdentity(r, allowlist),
		checkSchemaVersion(r),
		checkChainContext(ctx.cv, ctx.structuralErr, idx),
	}
	return eventResult{
		ReceiptID: r.ID,
		ChainID:   r.CredentialSubject.Chain.ChainID,
		Sequence:  r.CredentialSubject.Chain.Sequence,
		Checks:    checks,
		Verdict:   deriveVerdict(checks),
	}
}

// checkSignature reports whether the target receipt's Ed25519 signature
// verifies under the supplied public key (check #1).
func checkSignature(cv receipt.ChainVerification, idx int) check {
	if cv.Receipts[idx].SignatureValid {
		return check{Name: checkSignatureName, Status: statusPass, Detail: "Ed25519 signature verifies"}
	}
	return check{Name: checkSignatureName, Status: statusFail, Detail: "signature does not verify under the supplied public key"}
}

// firstLinkBreak returns the index of the first receipt whose hash link does
// not hold, or -1 if the whole chain's linkage is intact.
func firstLinkBreak(cv receipt.ChainVerification) int {
	for j := range cv.Receipts {
		if !cv.Receipts[j].HashLinkValid {
			return j
		}
	}
	return -1
}

// checkHashLinkage reports whether the target is anchored in an unbroken chain:
// every link from the daemon's startup baseline (index 0, previous_receipt_hash
// nil) up to the chain head must hold (check #2). A break before the target
// means it does not chain back to the baseline; a break after means it is not
// reachable from a trustworthy head. Either way the target's provenance is
// suspect, so the whole chain's linkage must be intact. firstBreak is the
// chain's first broken-link index (-1 if none), precomputed once per chain.
func checkHashLinkage(firstBreak, idx int) check {
	if firstBreak == -1 {
		return check{Name: checkHashLinkageName, Status: statusPass, Detail: "chains back to the startup baseline and is reachable from the chain head"}
	}
	if firstBreak <= idx {
		return check{Name: checkHashLinkageName, Status: statusFail, Detail: fmt.Sprintf("broken hash link at index %d — receipt does not chain back to the startup baseline", firstBreak)}
	}
	return check{Name: checkHashLinkageName, Status: statusFail, Detail: fmt.Sprintf("broken hash link at index %d — receipt is not reachable from a trustworthy chain head", firstBreak)}
}

// checkPeerPresent reports on the daemon-captured peer credential (check #3).
// Absent is NOT a failure: receipts predating peer-credential capture verify
// cryptographically but carry no pipeline-provenance evidence (n/a). Present
// but malformed IS a failure — corrupt evidence is worse than none. A
// recognized platform (linux/darwin — the only kinds the daemon captures) must
// carry uid/gid; an unrecognized platform is reported n/a rather than confirmed,
// since the verifier cannot interpret its peer-credential semantics and must not
// vouch for provenance it can't validate.
func checkPeerPresent(r receipt.AgentReceipt) check {
	pc := r.CredentialSubject.Action.PeerCredential
	if pc == nil {
		return check{Name: checkPeerCredentialName, Status: statusNA, Detail: "receipt predates peer-credential evidence; pipeline-provenance verification not available"}
	}
	if pc.Platform == "" {
		return check{Name: checkPeerCredentialName, Status: statusFail, Detail: "peer credential present but malformed: missing platform"}
	}
	if pc.Platform != "linux" && pc.Platform != "darwin" {
		return check{Name: checkPeerCredentialName, Status: statusNA, Detail: fmt.Sprintf("unrecognized peer platform %q; cannot interpret peer-credential semantics, pipeline-provenance not verifiable", pc.Platform)}
	}
	if pc.UID == nil || pc.GID == nil {
		return check{Name: checkPeerCredentialName, Status: statusFail, Detail: fmt.Sprintf("peer credential present but malformed: %s peer without uid/gid", pc.Platform)}
	}
	return check{Name: checkPeerCredentialName, Status: statusPass, Detail: fmt.Sprintf("daemon-attested %s peer (pid %d)", pc.Platform, pc.PID)}
}

// checkEmitterIdentity compares the captured exe_path against an operator
// allowlist (check #4). This is operator policy, not protocol: a mismatch warns
// (it never fails), and with no allowlist configured the observed path is
// surfaced informationally. An absent peer credential or unresolved exe_path
// leaves nothing to check.
func checkEmitterIdentity(r receipt.AgentReceipt, allowlist []string) check {
	pc := r.CredentialSubject.Action.PeerCredential
	if pc == nil {
		return check{Name: checkEmitterIdentityName, Status: statusNA, Detail: "no peer credential; emitter identity not checked"}
	}
	if pc.ExePath == "" {
		return check{Name: checkEmitterIdentityName, Status: statusNA, Detail: "no exe_path captured; emitter identity not checked"}
	}
	if len(allowlist) == 0 {
		return check{Name: checkEmitterIdentityName, Status: statusNA, Detail: fmt.Sprintf("no emitter allowlist configured; observed exe_path %s", pc.ExePath)}
	}
	for _, allowed := range allowlist {
		if pc.ExePath == allowed {
			return check{Name: checkEmitterIdentityName, Status: statusPass, Detail: fmt.Sprintf("exe_path %s matches the emitter allowlist", pc.ExePath)}
		}
	}
	return check{Name: checkEmitterIdentityName, Status: statusWarn, Detail: fmt.Sprintf("exe_path %s is not in the emitter allowlist [%s]", pc.ExePath, strings.Join(allowlist, ", "))}
}

// checkSchemaVersion reports whether the receipt's schema version is one this
// verifier understands (check #5). Compatibility is by major version: a
// matching major is compatible (a differing minor/patch is noted but not
// failed); a differing or missing major is a failure, since the verifier cannot
// assert anything about a schema it does not model.
func checkSchemaVersion(r receipt.AgentReceipt) check {
	if r.Version == "" {
		return check{Name: checkSchemaVersionName, Status: statusFail, Detail: "receipt carries no schema version"}
	}
	known := majorVersion(receipt.Version)
	got := majorVersion(r.Version)
	if got == "" {
		return check{Name: checkSchemaVersionName, Status: statusFail, Detail: fmt.Sprintf("unparseable schema version %q", r.Version)}
	}
	if got != known {
		return check{Name: checkSchemaVersionName, Status: statusFail, Detail: fmt.Sprintf("schema version %s is not known to this verifier (understands %s.x)", r.Version, known)}
	}
	if r.Version != receipt.Version {
		return check{Name: checkSchemaVersionName, Status: statusPass, Detail: fmt.Sprintf("schema version %s is compatible with this verifier's %s", r.Version, receipt.Version)}
	}
	return check{Name: checkSchemaVersionName, Status: statusPass, Detail: fmt.Sprintf("schema version %s", r.Version)}
}

// checkChainContext reports that the target's sequence position is contiguous
// with its neighbours (check #6, cross-checking #479): no gap immediately
// before (the target's own sequence relative to its predecessor) and none
// immediately after (its successor's sequence). It also surfaces whole-chain
// structural-integrity violations that the per-receipt signature/hash/sequence
// booleans don't capture — chain_id splice, receipt-after-terminal, or a
// chain.status schema invariant (spec §7.3.2–7.3.4) — via structuralErr, so a
// chain VerifyChain rejected can't yield an all-pass, provenance-confirmed
// verdict.
func checkChainContext(cv receipt.ChainVerification, structuralErr string, idx int) check {
	if !cv.Receipts[idx].SequenceValid {
		return check{Name: checkChainContextName, Status: statusFail, Detail: fmt.Sprintf("sequence gap at or before index %d", idx)}
	}
	if idx+1 < len(cv.Receipts) && !cv.Receipts[idx+1].SequenceValid {
		return check{Name: checkChainContextName, Status: statusFail, Detail: fmt.Sprintf("sequence gap immediately after index %d", idx)}
	}
	if structuralErr != "" {
		return check{Name: checkChainContextName, Status: statusFail, Detail: "chain integrity violation: " + structuralErr}
	}
	return check{Name: checkChainContextName, Status: statusPass, Detail: "sequence position is contiguous with its neighbours"}
}

// structuralErr returns a whole-chain integrity error that VerifyChain reports
// via cv.Valid/cv.Error but the per-receipt signature/hash/sequence booleans do
// not reflect — chain_id mismatch, receipt-after-terminal, or a chain.status
// schema invariant. It returns "" when the chain verifies, or when the failure
// is already attributable to a per-receipt check (so the dedicated signature /
// hash linkage / chain-context-sequence checks own the report and this doesn't
// double-count). Computed once per chain.
func structuralErr(cv receipt.ChainVerification) string {
	if cv.Valid {
		return ""
	}
	for _, rv := range cv.Receipts {
		if !rv.SignatureValid || !rv.HashLinkValid || !rv.SequenceValid {
			return ""
		}
	}
	return cv.Error
}

// deriveVerdict reduces the six checks to a provenance conclusion. Any failed
// check makes the receipt suspect. Otherwise the peer-credential check decides:
// present (pass) means the pipeline produced it; absent (n/a) means it verifies
// cryptographically but carries no provenance evidence. Warnings (emitter
// allowlist) never downgrade a confirmed verdict — they are operator policy.
func deriveVerdict(checks []check) verdict {
	peerAbsent := false
	for _, c := range checks {
		if c.Status == statusFail {
			return verdictFailed
		}
		if c.Name == checkPeerCredentialName && c.Status == statusNA {
			peerAbsent = true
		}
	}
	if peerAbsent {
		return verdictNoProvenance
	}
	return verdictConfirmed
}

// exitCode reduces all per-receipt verdicts to a single process exit code,
// reporting the worst case: any failure outranks any missing-provenance, which
// outranks confirmed.
func exitCode(results []eventResult) int {
	code := ExitOK
	for _, r := range results {
		switch r.Verdict {
		case verdictFailed:
			return ExitVerifyFailed
		case verdictNoProvenance:
			code = ExitNoProvenance
		}
	}
	return code
}

func writeHuman(stdout io.Writer, results []eventResult) {
	for _, r := range results {
		fmt.Fprintf(stdout, "Receipt %s (chain %s, seq %d):\n", r.ReceiptID, r.ChainID, r.Sequence)
		for _, c := range r.Checks {
			fmt.Fprintf(stdout, "  [%-4s] %s", strings.ToUpper(string(c.Status)), c.Name)
			if c.Detail != "" {
				fmt.Fprintf(stdout, " — %s", c.Detail)
			}
			fmt.Fprintln(stdout)
		}
		fmt.Fprintf(stdout, "  => %s\n", verdictLine(r.Verdict))
	}
}

func verdictLine(v verdict) string {
	switch v {
	case verdictConfirmed:
		return "VERIFIED — pipeline-provenance confirmed"
	case verdictNoProvenance:
		return "VERIFIED (cryptographically) — no pipeline-provenance evidence"
	default:
		return "FAILED — receipt is suspect; investigate"
	}
}

func writeJSON(stdout, stderr io.Writer, results []eventResult) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(jsonOutput{Results: results}); err != nil {
		if errors.Is(err, syscall.EPIPE) || errors.Is(err, io.ErrClosedPipe) {
			return exitCode(results)
		}
		fmt.Fprintf(stderr, "obsigna receipt verify-event: encode JSON: %v\n", err)
		return ExitUsageError
	}
	return exitCode(results)
}

// indexByID maps each receipt's id to its position in the chain slice.
func indexByID(chain []receipt.AgentReceipt) map[string]int {
	m := make(map[string]int, len(chain))
	for i, r := range chain {
		m[r.ID] = i
	}
	return m
}

// parseAllowlist splits a comma-separated exe_path list, trimming whitespace
// and dropping empties, and returns a sorted, de-duplicated slice.
func parseAllowlist(raw string) []string {
	if raw == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// majorVersion returns the leading numeric component of a dotted version
// string ("0.4.0" → "0"). It requires the dotted form: a string with no '.'
// (e.g. "0" or "garbage") is not a valid schema version and returns "", so
// checkSchemaVersion rejects it as unparseable rather than treating a bare
// major as compatible.
func majorVersion(v string) string {
	if i := strings.IndexByte(v, '.'); i >= 0 {
		return v[:i]
	}
	return ""
}

// validatePublicKeyPEM rejects PEM bytes that don't decode to an Ed25519 SPKI
// public key, so a malformed key surfaces as a usage error rather than being
// routed through per-receipt signature failures (which would falsely implicate
// the receipts).
func validatePublicKeyPEM(pubPEM []byte) error {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return errors.New("PEM decode failed (no PUBLIC KEY block)")
	}
	if block.Type != "PUBLIC KEY" {
		return fmt.Errorf("PEM block type is %q, want PUBLIC KEY", block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse SPKI public key: %w", err)
	}
	if _, ok := parsed.(ed25519.PublicKey); !ok {
		return fmt.Errorf("public key is %T, want ed25519.PublicKey", parsed)
	}
	return nil
}
