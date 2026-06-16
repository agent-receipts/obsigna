// Package daemon assembles the obsigna-daemon's components — chain state, key
// source, receipt store, frame socket — into a single Run entrypoint.
// cmd/obsigna-daemon/main.go wraps Run with flag/env parsing and signal
// handling.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/chain"
	"github.com/agent-receipts/ar/daemon/internal/keysource"
	"github.com/agent-receipts/ar/daemon/internal/pipeline"
	"github.com/agent-receipts/ar/daemon/internal/socket"
	"github.com/agent-receipts/ar/sdk/go/emitter"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// Config is the daemon's startup configuration. Resolve from flags/env in
// cmd/obsigna-daemon/main.go and pass to Run.
type Config struct {
	// SocketPath is the Unix-domain socket the daemon listens on.
	SocketPath string

	// UnsafeSocketPath permits a SocketPath outside the per-platform safe set
	// (see checkSocketPath). When false (the default), Run refuses to start on
	// an unsafe explicit override; when true, Run starts and warns periodically.
	// Set from --unsafe-socket-path. TCP addresses are rejected regardless.
	UnsafeSocketPath bool

	// DBPath is the SQLite receipt-store path.
	DBPath string

	// KeyPath is the PEM-encoded Ed25519 private key path. Mode must be 0600.
	KeyPath string

	// PublicKeyPath is where the daemon publishes the matching SPKI public
	// key in PEM form, mode 0644, on every startup. Read-side tools
	// (`agent-receipts verify`) load it without needing access to KeyPath or
	// the daemon's signing surface. Defaults to KeyPath + ".pub" when empty.
	PublicKeyPath string

	// ForensicPublicKeyPath is the path to the X25519 forensic public key
	// (32 raw bytes) used to encrypt action parameters (ADR-0012, HPKE envelope).
	// When set, incoming tool parameters are encrypted before signing and
	// attached as action.parameters_disclosure. When empty, parameters are
	// hashed only (the default, privacy-preserving). The private key is held
	// offline by the forensic responder. Set from --forensic-public-key.
	ForensicPublicKeyPath string

	// ChainID is the chain id all incoming frames are written under. Phase 1
	// supports one chain per daemon process.
	ChainID string

	// IssuerID is embedded in receipts as issuer.id, e.g.
	// "did:agent-receipts-daemon:<host>".
	IssuerID string

	// VerificationMethodID goes into proof.verificationMethod.
	VerificationMethodID string

	// AnchorLogPath, when set, is an append-only external-witness log that
	// rotation events are written to before the local chain commits (ADR-0015
	// anchor-first ordering). Empty disables anchoring — the operator keeps the
	// chain-integrity guarantees but forgoes the post-compromise integrity
	// guarantee. Set from --anchor-log (env: AGENTRECEIPTS_ANCHOR_LOG).
	AnchorLogPath string

	// Logger receives daemon log lines. Defaults to log.Default().
	Logger *log.Logger

	// TraceLog optionally receives daemon trace lines for test debugging.
	// When nil, tracing is silent. Tests can pass a buffer to inspect
	// what frames were received, receipts signed, etc.
	TraceLog io.Writer

	// ParameterDisclosure selects which actions have their parameters encrypted
	// into the parameters_disclosure envelope (ADR-0012). Value space mirrors the
	// OpenClaw plugin: "false"/"off"/"" (default, hash only), "true"/"all",
	// "high" (high- and critical-risk actions), or a comma-separated allowlist of
	// action types. Disclosure also requires ForensicPublicKeyPath — without a
	// key there is nothing to encrypt to. Parsed via
	// pipeline.ParseDisclosurePolicy at startup.
	ParameterDisclosure string

	// RedactPatternsPath is an optional path to a YAML file of additional
	// redaction patterns applied to receipt body fields after hashing. When
	// empty, only the built-in patterns are used. File format:
	//
	//   patterns:
	//     - name: my-secret
	//       pattern: 'MY_SECRET_[A-Z0-9]+'
	RedactPatternsPath string

	// ShutdownDeadline is the total time budget for emitting interrupted-chain
	// terminators on SIGTERM/SIGINT. Defaults to 200ms when zero.
	ShutdownDeadline time.Duration
}

// DefaultSocketPath returns the per-OS default socket path. Phase 1 resolves
// Q1 of issue #236; the macOS default was reworked again for issue #545:
//   - macOS: $XDG_DATA_HOME/agent-receipts/events.sock — per-user,
//     unprivileged. Defaults to $HOME/.local/share/agent-receipts/events.sock
//     when XDG_DATA_HOME is unset, co-located with receipts.db and the
//     signing key.
//   - Linux with $XDG_RUNTIME_DIR set: $XDG_RUNTIME_DIR/agentreceipts/
//     events.sock — per-user, unprivileged.
//   - Linux fallback (no $XDG_RUNTIME_DIR): /run/agentreceipts/events.sock —
//     this is the system-install path and requires privileged directory
//     creation/write. Unprivileged users on systems without
//     $XDG_RUNTIME_DIR should set AGENTRECEIPTS_SOCKET explicitly.
//   - Other platforms: empty string (the daemon refuses to start outside
//     Linux/macOS, see Run).
//
// The OS resolution is delegated to emitter.DefaultSocketPath so the daemon
// and the SDK's emitter cannot drift on what counts as the per-user default
// socket path. emitter.DefaultSocketPath additionally honours
// AGENTRECEIPTS_SOCKET when set — that branch is a no-op for the daemon
// binary, which independently consults AGENTRECEIPTS_SOCKET in main before
// calling this function, but it keeps any library consumer aligned with the
// emitter without needing to re-implement the env-var fallback.
func DefaultSocketPath() string {
	return emitter.DefaultSocketPath()
}

// xdgDataHome returns the XDG_DATA_HOME directory or its default
// ($HOME/.local/share). Returns "" when XDG_DATA_HOME is unset and the
// user's home directory cannot be determined.
//
// Per the XDG Base Directory spec, $XDG_DATA_HOME must be an absolute path;
// a relative value is treated as invalid and ignored, falling back to the
// $HOME/.local/share default. This protects against a misconfigured
// environment silently relocating the receipt store under the working
// directory of whichever process happened to start the daemon.
func xdgDataHome() string {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome != "" && filepath.IsAbs(dataHome) {
		return dataHome
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share")
}

// DefaultDBPath returns the per-user SQLite path used when AGENTRECEIPTS_DB
// is not set. Uses XDG_DATA_HOME (defaults to ~/.local/share on Linux/macOS).
func DefaultDBPath() string {
	dh := xdgDataHome()
	if dh == "" {
		return ""
	}
	return filepath.Join(dh, "agent-receipts", "receipts.db")
}

// DefaultKeyPath returns the per-user signing-key path used when
// AGENTRECEIPTS_KEY is not set. Uses XDG_DATA_HOME (defaults to ~/.local/share on Linux/macOS).
func DefaultKeyPath() string {
	dh := xdgDataHome()
	if dh == "" {
		return ""
	}
	return filepath.Join(dh, "agent-receipts", "signing.key")
}

// DefaultPublicKeyPath returns the default published public-key path: the
// same directory as keyPath with the suffix ".pub". Empty when keyPath is
// empty so cmd/main.go can surface a clearer "Config.KeyPath is required"
// error from validateConfig instead of a less-helpful PublicKeyPath one.
func DefaultPublicKeyPath(keyPath string) string {
	if keyPath == "" {
		return ""
	}
	return keyPath + ".pub"
}

// DefaultIssuerID and DefaultVerificationMethodID are the identity defaults a
// local daemon signs under when no issuer/verification-method is configured.
// They are exported so any tool that builds a Config for the same local install
// — the daemon's own config resolution and `obsigna keys rotate` — shares one
// source of truth: the issuer DID and verification method are embedded in every
// signed receipt, so two callers defaulting them differently would fork chain
// identity for the same operator.
const (
	DefaultIssuerID             = "did:agent-receipts-daemon:local"
	DefaultVerificationMethodID = DefaultIssuerID + "#k1"
)

// DefaultForensicKeyPath returns the default forensic private-key path,
// co-located with the signing key and receipt store. Empty when the XDG data
// home cannot be resolved, matching the other Default*Path helpers.
func DefaultForensicKeyPath() string {
	dh := xdgDataHome()
	if dh == "" {
		return ""
	}
	return filepath.Join(dh, "agent-receipts", "forensic.key")
}

// DefaultForensicPublicKeyPath returns the default forensic public-key path:
// keyPath with the ".pub" suffix. Empty when keyPath is empty.
func DefaultForensicPublicKeyPath(keyPath string) string {
	if keyPath == "" {
		return ""
	}
	return keyPath + ".pub"
}

// GenerateForensicKey creates a new X25519 forensic key pair (ADR-0012) and
// writes the raw 32-byte private key to keyPath (mode 0600) and the raw 32-byte
// public key to publicKeyPath (mode 0644). It returns the public key's canonical
// fingerprint (ADR-0015, sha256:<hex>) for display so an operator can confirm
// the key the daemon will encrypt to matches the private key they keep for
// recovery.
//
// Like GenerateKey, it refuses to overwrite or follow a symlink at either path,
// and rolls back the private key if the public-key write fails. The two keys
// have deliberately separate lifecycles: the public key goes in daemon config;
// the private key is kept offline by the forensic responder and never given to
// the daemon.
func GenerateForensicKey(keyPath, publicKeyPath string) (string, error) {
	if keyPath == "" {
		return "", errors.New("keyPath is required")
	}
	if publicKeyPath == "" {
		publicKeyPath = DefaultForensicPublicKeyPath(keyPath)
	}
	if keyPath == publicKeyPath {
		return "", fmt.Errorf("keyPath and publicKeyPath must differ; both are %s", keyPath)
	}

	fk, err := receipt.GenerateForensicKeyPair()
	if err != nil {
		return "", fmt.Errorf("generate forensic key pair: %w", err)
	}
	fingerprint, err := receipt.ForensicKeyFingerprint(fk.PublicKey)
	if err != nil {
		return "", fmt.Errorf("fingerprint forensic public key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(keyPath), 0o750); err != nil {
		return "", fmt.Errorf("create forensic key dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(publicKeyPath), 0o750); err != nil {
		return "", fmt.Errorf("create forensic public-key dir: %w", err)
	}

	if err := writeNewSecretFile(keyPath, fk.PrivateKey, 0o600); err != nil {
		return "", fmt.Errorf("write forensic private key %s: %w", keyPath, err)
	}
	if err := writeNewSecretFile(publicKeyPath, fk.PublicKey, 0o644); err != nil {
		_ = os.Remove(keyPath)
		return "", fmt.Errorf("write forensic public key %s: %w", publicKeyPath, err)
	}

	return fingerprint, nil
}

// GenerateKey creates a new Ed25519 key pair and saves the private key to
// keyPath (mode 0600) and public key to publicKeyPath (mode 0644). Refuses
// to overwrite an existing file at either path, and refuses to follow a
// symlink at either path. Use this explicitly via --init; never call it as
// a side-effect of starting the daemon — silently regenerating a missing
// key would invalidate every receipt previously signed by the operator's
// real key.
//
// Atomicity: both files are created with O_CREATE|O_EXCL|O_NOFOLLOW so an
// attacker who plants a symlink (or any other dirent) at either path
// between the directory creation and the file open trips O_EXCL — we never
// write through the symlink target. If the public-key write fails after
// the private-key write succeeded, the private-key file is removed so the
// caller doesn't end up with a half-initialised on-disk state.
//
// The mode passed to OpenFile may be narrowed by the process umask; an
// explicit fchmod after open ensures the on-disk mode matches what the
// caller asked for.
func GenerateKey(keyPath, publicKeyPath string) error {
	if keyPath == "" {
		return errors.New("keyPath is required")
	}
	if publicKeyPath == "" {
		publicKeyPath = DefaultPublicKeyPath(keyPath)
	}
	if keyPath == publicKeyPath {
		return fmt.Errorf("keyPath and publicKeyPath must differ; both are %s", keyPath)
	}

	// Generate the key pair before touching the filesystem so a generation
	// failure leaves no half-state behind.
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}

	// Create both parent directories at 0o750, matching publishPublicKey's
	// dir mode (daemon.go's existing convention). Default deployments place
	// the public key alongside the private key, so the second MkdirAll is
	// usually a no-op against the dir we just made; we still call it so an
	// operator who passes --public-key /elsewhere doesn't see a bare ENOENT
	// from the OpenFile below.
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o750); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(publicKeyPath), 0o750); err != nil {
		return fmt.Errorf("create public-key dir: %w", err)
	}

	if err := writeNewSecretFile(keyPath, []byte(kp.PrivateKey), 0o600); err != nil {
		return fmt.Errorf("write private key %s: %w", keyPath, err)
	}

	if err := writeNewSecretFile(publicKeyPath, []byte(kp.PublicKey), 0o644); err != nil {
		// Roll back so the operator can re-run --init from a clean state
		// instead of being stuck with a private key whose public half is
		// missing or wrong.
		_ = os.Remove(keyPath)
		return fmt.Errorf("write public key %s: %w", publicKeyPath, err)
	}

	return nil
}

// writeNewSecretFile creates a file at path containing data with the given
// mode. It refuses to overwrite an existing file (O_EXCL) and refuses to
// follow a symlink at the path (O_NOFOLLOW), closing the TOCTOU window
// where a Stat-then-Write pair could be tricked into writing through a
// symlink an attacker plants between the two syscalls.
//
// fchmod after the write ensures the on-disk permissions match mode even
// when the process umask would otherwise narrow them; on failure the
// partially-written file is removed so a retry sees a clean slate.
func writeNewSecretFile(path string, data []byte, mode os.FileMode) error {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, mode)
	if err != nil {
		if isSymlinkLoop(err) {
			return fmt.Errorf("refusing to follow symlink at %s", path)
		}
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = fh.Close()
			_ = os.Remove(path)
		}
	}()

	if _, err := fh.Write(data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	// fchmod via the open fd, not path-based Chmod, so the mode applies to
	// the inode we just created — no symlink-target chmod risk even if the
	// directory entry is replaced after we write.
	if err := fh.Chmod(mode); err != nil {
		return fmt.Errorf("chmod %o: %w", mode, err)
	}
	closed = true
	if err := fh.Close(); err != nil {
		// Close-time errors (NFS commit failure, disk-full, quota
		// exceeded) can lose data we just "wrote". Remove the file so the
		// caller can retry from a clean state.
		_ = os.Remove(path)
		return fmt.Errorf("close: %w", err)
	}
	return nil
}

// Run starts the daemon and blocks until ctx is cancelled. It returns the
// first fatal error or nil on graceful shutdown.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	// Phase 1 supports Linux and macOS. Check this BEFORE validateConfig so an
	// unsupported-platform run gets a clear error, rather than the misleading
	// "Config.SocketPath is required" that DefaultSocketPath's empty return
	// would otherwise produce on those platforms. Windows ships in a follow-up
	// issue per #236.
	switch runtime.GOOS {
	case "linux", "darwin":
	default:
		return fmt.Errorf("obsigna-daemon: unsupported platform %q (Phase 1 supports linux and darwin only)", runtime.GOOS)
	}
	if err := validateConfig(&cfg); err != nil {
		return err
	}

	// Enforce the safe-socket-location policy (issue #538) on the resolved
	// path — default or explicit override — before binding. A TCP address or
	// an unsafe override without --unsafe-socket-path refuses to start here;
	// an unsafe override with the flag starts but warns on a 60s cadence for
	// the daemon's lifetime.
	unsafeSocket, err := checkSocketPath(cfg.SocketPath, cfg.UnsafeSocketPath)
	if err != nil {
		return err
	}
	if unsafeSocket {
		// Bind the warning goroutine to a context cancelled when Run returns,
		// not to the caller's ctx. A later startup error returns from Run
		// without the caller necessarily cancelling ctx; without this the
		// warning loop would outlive the failed start and keep logging.
		warnCtx, cancelWarn := context.WithCancel(ctx)
		defer cancelWarn()
		go warnUnsafeSocketPath(warnCtx, cfg.Logger, cfg.SocketPath, unsafeSocketWarnInterval)
	}

	// Apply a restrictive process umask BEFORE opening the SQLite store so any
	// files SQLite creates (DB itself, and especially the lazily-created WAL
	// and SHM sidecars on first write) inherit owner+group-only permissions.
	// tightenDBFiles below remains as belt-and-braces for files that already
	// exist or for sidecars that get re-created later, but umask catches the
	// new-file case at the source so we don't have a window where a file is
	// briefly world-readable between create and chmod.
	applyRestrictiveUmask()

	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o750); err != nil {
		return fmt.Errorf("create db dir: %w", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Receipts may include peer attestation and operator-supplied disclosures;
	// world-readable is wrong by default. tightenDBFiles chmods the DB and any
	// WAL/SHM siblings down to 0640 when they're looser, preserves operator-set
	// tighter modes (e.g. 0600), and only refuses to start when the post-chmod
	// perms are still wider than 0640 — see its doc comment for details.
	if err := tightenDBFiles(cfg.DBPath); err != nil {
		return err
	}

	ks := keysource.NewFile(cfg.KeyPath, cfg.VerificationMethodID)
	if err := ks.Init(); err != nil {
		return fmt.Errorf("init keysource: %w", err)
	}
	defer func() { _ = ks.Teardown() }()

	if err := publishPublicKey(ks, cfg.PublicKeyPath); err != nil {
		return err
	}
	cfg.Logger.Printf("published public key to %s", cfg.PublicKeyPath)

	state, err := chain.LoadFromStore(st, cfg.ChainID)
	if err != nil {
		return err
	}
	cfg.Logger.Printf("loaded chain %s, next seq=%d", cfg.ChainID, state.NextSeq())

	// If the chain already has a terminal receipt, advance to the next chain ID
	// rather than refusing to start. A terminal tail is normal after any daemon
	// shutdown (graceful or not) — blocking restart would require manual config
	// edits for routine restarts. The loop cap of 32 is a safety guard; in
	// normal operation it runs at most once (advanced chains are always fresh).
	for range 32 {
		if state.NextSeq() <= 1 {
			break
		}
		tail, tailErr := st.GetChainTailReceipt(cfg.ChainID)
		if tailErr != nil {
			return fmt.Errorf("check chain tail: %w", tailErr)
		}
		if tail == nil || tail.CredentialSubject.Chain.Terminal == nil || !*tail.CredentialSubject.Chain.Terminal {
			break
		}
		next := advanceChainID(cfg.ChainID)
		cfg.Logger.Printf("chain %q tail (seq %d) is terminal (status=%q); continuing as %q",
			cfg.ChainID, tail.CredentialSubject.Chain.Sequence,
			tail.CredentialSubject.Chain.Status, next)
		cfg.ChainID = next
		state, err = chain.LoadFromStore(st, cfg.ChainID)
		if err != nil {
			return err
		}
		cfg.Logger.Printf("loaded chain %s, next seq=%d", cfg.ChainID, state.NextSeq())
	}
	// Post-loop guard: if the resolved chain is still terminal after exhausting
	// the advance cap, refuse to start rather than appending after a terminal
	// receipt (spec §7.3.2). This is a defensive belt-and-suspenders check —
	// in normal operation the loop always breaks on the first fresh chain.
	if state.NextSeq() > 1 {
		tail, tailErr := st.GetChainTailReceipt(cfg.ChainID)
		if tailErr != nil {
			return fmt.Errorf("check chain tail: %w", tailErr)
		}
		if tail != nil && tail.CredentialSubject.Chain.Terminal != nil && *tail.CredentialSubject.Chain.Terminal {
			return fmt.Errorf(
				"chain %q tail (seq %d) is already terminal (chain.status=%q) after advancing %d times; "+
					"use a new --chain-id or a fresh --db to start a new chain",
				cfg.ChainID,
				tail.CredentialSubject.Chain.Sequence,
				tail.CredentialSubject.Chain.Status,
				32,
			)
		}
	}

	// Resolve the forensic disclosure configuration (ADR-0012): a disclosure
	// policy (which actions disclose) plus the forensic public key (the
	// encryption target). The two are coupled — a policy without a key has
	// nothing to encrypt to, and a key without a policy never fires.
	policy, err := pipeline.ParseDisclosurePolicy(cfg.ParameterDisclosure)
	if err != nil {
		return fmt.Errorf("parameter disclosure policy: %w", err)
	}

	var forensicPublicKey []byte
	if cfg.ForensicPublicKeyPath != "" {
		forensicPublicKey, err = os.ReadFile(cfg.ForensicPublicKeyPath)
		if err != nil {
			return fmt.Errorf("load forensic public key from %s: %w", cfg.ForensicPublicKeyPath, err)
		}
		if len(forensicPublicKey) != 32 {
			return fmt.Errorf("forensic public key must be 32 raw bytes, got %d from %s", len(forensicPublicKey), cfg.ForensicPublicKeyPath)
		}
	}

	switch {
	case policy.Enabled() && len(forensicPublicKey) == 0:
		return fmt.Errorf("parameter disclosure %q requires a forensic public key (--forensic-public-key); without one there is nothing to encrypt to", cfg.ParameterDisclosure)
	case policy.Enabled():
		fp, _ := receipt.ForensicKeyFingerprint(forensicPublicKey)
		cfg.Logger.Printf("Parameter disclosure ACTIVE: policy=%s, forensic key %s — matching parameters will be HPKE-encrypted to that key (recoverable only with the private key)", policy.String(), fp)
	case len(forensicPublicKey) > 0:
		cfg.Logger.Printf("NOTICE: a forensic public key is set but parameter disclosure policy is off; no parameters will be disclosed. Set --parameter-disclosure (true|high|<action-types>) to enable.")
	}

	pp := pipeline.New(state, ks, st, cfg.IssuerID)
	pp.TraceLog = cfg.TraceLog
	pp.ErrorLog = cfg.Logger.Printf
	pp.DisclosurePolicy = policy
	pp.ForensicPublicKey = forensicPublicKey

	// Always enable redaction with the built-in patterns. If the operator
	// supplied a patterns file, load and merge the custom patterns.
	customPatterns, err := loadCustomRedactPatterns(cfg.RedactPatternsPath, cfg.Logger)
	if err != nil {
		return err
	}
	pp.Redactor = pipeline.NewRedactor(customPatterns)

	ln, err := socket.Listen(socket.Options{
		Path:     cfg.SocketPath,
		Handler:  func(ctx context.Context, f socket.Frame) error { return pp.Process(f) },
		ErrorLog: cfg.Logger.Printf,
	})
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()
	cfg.Logger.Printf("obsigna-daemon listening on %s (chain=%s, db=%s)", ln.Path(), cfg.ChainID, cfg.DBPath)

	if err := ln.Serve(ctx); err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	// The listener is closed and all in-flight handlers have exited.
	// Emit interrupted-chain terminators for any open chains before the
	// deferred st.Close() commits the WAL. Use a fresh context — the caller's
	// ctx is already cancelled.
	terminateCtx, terminateCancel := context.WithTimeout(context.Background(), cfg.shutdownDeadline())
	defer terminateCancel()
	if err := pp.EmitTerminator(terminateCtx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			cfg.Logger.Printf("level=warn terminator: deadline expired, chain %s will be classified as 'unknown' by verifier", cfg.ChainID)
		} else {
			cfg.Logger.Printf("level=warn terminator: %v (chain %s may be classified as 'unknown' by verifier)", err, cfg.ChainID)
			return fmt.Errorf("emit terminator: %w", err)
		}
	}

	cfg.Logger.Printf("obsigna-daemon shutdown complete")
	return nil
}

// shutdownDeadline returns the configured shutdown deadline, or 200ms if unset.
func (cfg Config) shutdownDeadline() time.Duration {
	if cfg.ShutdownDeadline > 0 {
		return cfg.ShutdownDeadline
	}
	return 200 * time.Millisecond
}

// allowedDBPerm is the maximum permission set the daemon will allow on the
// receipt DB and its WAL/SHM siblings: 0640 (owner rw, group r, world none).
// "Looser than allowedDBPerm" means any bit set outside that mask, so we use a
// bitmask check instead of a numeric `>` comparison — modes like 0604
// (rw----r--, world-readable) are numerically less than 0640 but still leak
// receipts to other users on the host. Bitmask catches all such cases.
const allowedDBPerm os.FileMode = 0o640

// looserThanAllowed reports whether mode has any permission bit set outside
// the allowedDBPerm mask. mode is the Perm()-only portion (file-type bits
// already stripped).
func looserThanAllowed(mode os.FileMode) bool {
	return mode&^allowedDBPerm != 0
}

// tightenDBFiles ensures the SQLite database and any WAL/SHM siblings are no
// looser than 0640 (owner rw, group r, world none). Run AFTER store.Open so
// the freshly-created files exist. SQLite creates DB files using the process
// umask, which on most systems means world-readable 0644 by default — left
// alone, that would persist sensitive receipt content.
//
// Behaviour:
//   - File missing → skip (legitimate for WAL/SHM in non-WAL mode).
//   - File present but a symlink, FIFO, device, etc. → refuse. A pre-created
//     symlink at <db>-wal could otherwise redirect chmod to an unexpected
//     target, and a non-regular file would silently bypass the perm check.
//   - File present with any bit looser than 0640 → chmod down to 0640
//     (preserves operator-set tighter modes such as 0600 untouched).
//   - File present with perms still looser than 0640 after chmod (e.g.
//     filesystem silently ignored chmod, or a race rewrote a looser mode)
//     → refuse.
func tightenDBFiles(dbPath string) error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := dbPath + suffix
		// Lstat (not Stat) so a symlink at <db>-wal etc. is observed AS a
		// symlink and refused, rather than silently followed and chmod'd at
		// some unexpected target.
		info, err := os.Lstat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("stat %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("daemon: %s exists but is not a regular file (mode %s); refusing to chmod or use it as a SQLite path", path, info.Mode())
		}
		if looserThanAllowed(info.Mode().Perm()) {
			if err := os.Chmod(path, allowedDBPerm); err != nil {
				return fmt.Errorf("chmod %s %o: %w", path, allowedDBPerm, err)
			}
			info, err = os.Lstat(path)
			if err != nil {
				return fmt.Errorf("re-stat %s after chmod: %w", path, err)
			}
		}
		if looserThanAllowed(info.Mode().Perm()) {
			return fmt.Errorf("daemon: receipts DB %s has perms %o after chmod attempt (looser than %o); refusing to start", path, info.Mode().Perm(), allowedDBPerm)
		}
	}
	return nil
}

// publishPublicKey writes the keysource's PEM-encoded public key to path with
// mode 0644 so independent verifiers can load it without needing access to
// the private key path or the daemon's signing surface (this realises the
// "agent-receipts verify reads DB and public key directly via filesystem"
// acceptance criterion of issue #236).
//
// Behaviour:
//   - File missing → write the current public key with mode 0644.
//   - File present and identical to the current public key → no-op (perms
//     converged to 0644 if a stricter umask had narrowed them at create time,
//     e.g. 0640).
//   - File present and differs from the current public key → refuse. A
//     mismatch means either the private key changed (rotation, restored from
//     backup) or the published file was tampered with; silently overwriting
//     would invalidate verifiers' trust in receipts they already accepted.
//     Operator must remove the stale file deliberately.
//   - File present but a symlink, FIFO, device, etc. → refuse. A pre-created
//     symlink would otherwise let an attacker with write access to the parent
//     redirect the chmod / write to an arbitrary target.
//
// All file operations use O_NOFOLLOW + an fstat on the open fd, and the
// fresh-write path uses O_CREATE|O_EXCL, so an attacker who can race-replace
// the path between the existence check and the write/chmod cannot trick the
// daemon into writing through or chmod'ing a symlink target.
func publishPublicKey(ks keysource.KeySource, path string) error {
	if path == "" {
		return errors.New("Config.PublicKeyPath is required")
	}
	pubPEM, err := ks.PublicKey()
	if err != nil {
		return fmt.Errorf("read public key from keysource: %w", err)
	}

	// Lstat first so non-regular files (symlinks, FIFOs, devices, dirs)
	// short-circuit without any open syscall — opening a FIFO RDONLY would
	// block the daemon at startup waiting for a writer.
	info, lstatErr := os.Lstat(path)
	switch {
	case lstatErr == nil:
		if !info.Mode().IsRegular() {
			return fmt.Errorf(
				"daemon: public-key path %s exists but is not a regular file (mode %s); refusing to overwrite",
				path, info.Mode(),
			)
		}
		return reconcileExistingPublicKey(path, pubPEM)

	case errors.Is(lstatErr, fs.ErrNotExist):
		// Fall through to the fresh-write path below.

	default:
		return fmt.Errorf("stat public-key path %s: %w", path, lstatErr)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create public-key dir: %w", err)
	}
	// O_CREATE|O_EXCL + O_NOFOLLOW: refuses to follow a symlink AND refuses
	// any pre-existing file. An attacker who creates a symlink (or any other
	// dirent) at path between the Lstat ENOENT above and this Open will trip
	// O_EXCL — the dirent exists — so the daemon never writes through it.
	// That closes the fresh-write half of the Lstat→Open TOCTOU window.
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o644)
	if err != nil {
		if isSymlinkLoop(err) {
			return fmt.Errorf("daemon: public-key path %s appeared as a symlink between existence check and create; refusing", path)
		}
		return fmt.Errorf("create public-key file %s: %w", path, err)
	}
	// Writable handle: a deferred Close() that ignores the error can mask a
	// Close-time write failure (NFS commit failure, disk-full, quota
	// exceeded) and silently lose the public key bytes we just wrote. Track
	// closed state so the deferred best-effort Close on early-error paths
	// doesn't double-close, and surface a clean Close() error to the caller
	// on the success path.
	closed := false
	defer func() {
		if !closed {
			_ = fh.Close()
		}
	}()
	if _, err := fh.Write([]byte(pubPEM)); err != nil {
		return fmt.Errorf("write public-key file %s: %w", path, err)
	}
	// fchmod via the open fd, not path-based Chmod, so the mode applies to
	// the inode we just created — no symlink-target chmod risk even if the
	// directory entry is replaced after we write.
	if err := fh.Chmod(0o644); err != nil {
		return fmt.Errorf("chmod %s 0644: %w", path, err)
	}
	closed = true
	if err := fh.Close(); err != nil {
		return fmt.Errorf("close public-key file %s: %w", path, err)
	}
	return nil
}

// reconcileExistingPublicKey handles the case where Lstat saw a regular file
// at path. It then no-ops, fchmod's, or refuses based on whether the on-disk
// contents match the current keysource.
//
// The open uses O_NOFOLLOW so a regular-file→symlink swap between Lstat and
// Open trips ELOOP and is refused; it adds O_NONBLOCK so a regular-file→FIFO
// swap can't park the daemon at startup waiting for a writer. The fstat-on-fd
// after Open re-rejects any non-regular file that slipped past Lstat (FIFO,
// device, …); it does NOT compare st_ino/st_dev against the earlier Lstat
// result — the file-permission and content checks are what we rely on, not
// inode identity.
func reconcileExistingPublicKey(path, wantPubPEM string) error {
	// O_NONBLOCK is a no-op on regular files (Linux/Darwin) but prevents an
	// O_RDONLY open from blocking on a FIFO that a racing attacker might
	// substitute for the regular file we Lstat'd.
	fh, err := os.OpenFile(path, os.O_RDONLY|oNoFollow|oNonblock, 0)
	if err != nil {
		if isSymlinkLoop(err) {
			return fmt.Errorf("daemon: public-key path %s changed to a symlink between check and open; refusing", path)
		}
		return fmt.Errorf("open public-key file %s: %w", path, err)
	}
	defer fh.Close()
	info, err := fh.Stat()
	if err != nil {
		return fmt.Errorf("fstat public-key file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf(
			"daemon: public-key path %s opened as non-regular (mode %s); refusing",
			path, info.Mode(),
		)
	}
	// 16 KiB cap matches keysource.MaxKeyFileBytes; PEM-encoded SPKI public
	// keys are ~120 bytes, so anything larger is a misconfiguration we'd
	// rather refuse loudly than parse defensively.
	existing, err := io.ReadAll(io.LimitReader(fh, 16*1024))
	if err != nil {
		return fmt.Errorf("read existing public-key file %s: %w", path, err)
	}
	if string(existing) != wantPubPEM {
		return fmt.Errorf(
			"daemon: public-key file %s differs from current keysource public key; refusing to overwrite. Remove the file deliberately if the signing key was rotated or restored from backup",
			path,
		)
	}
	if info.Mode().Perm() != 0o644 {
		// fchmod via the open fd: the mode applies to this inode regardless
		// of any directory-entry swap that happened after Lstat.
		if err := fh.Chmod(0o644); err != nil {
			return fmt.Errorf("chmod %s 0644: %w", path, err)
		}
	}
	return nil
}

// advanceChainID returns the next chain ID when the current chain is terminal.
// It appends or increments a numeric suffix separated by "-":
//
//	"foo"          → "foo-2"
//	"foo-2"        → "foo-3"
//	"2026-06-03"   → "2026-06-03-2"   (date component "03" has a leading zero,
//	                                    so it is never mistaken for a counter)
//	"2026-06-03-2" → "2026-06-03-3"
//
// The no-leading-zeros guard (suffix == strconv.Itoa(n)) is what distinguishes
// a counter suffix added by this function from a date component like "03".
func advanceChainID(id string) string {
	if i := strings.LastIndex(id, "-"); i >= 0 {
		suffix := id[i+1:]
		if n, err := strconv.Atoi(suffix); err == nil && n >= 2 && suffix == strconv.Itoa(n) {
			return id[:i+1] + strconv.Itoa(n+1)
		}
	}
	return id + "-2"
}

func validateConfig(cfg *Config) error {
	if cfg.SocketPath == "" {
		return errors.New("Config.SocketPath is required")
	}
	if cfg.DBPath == "" {
		return errors.New("Config.DBPath is required")
	}
	if cfg.KeyPath == "" {
		return errors.New("Config.KeyPath is required")
	}
	if cfg.PublicKeyPath == "" {
		cfg.PublicKeyPath = DefaultPublicKeyPath(cfg.KeyPath)
	}
	if cfg.ChainID == "" {
		return errors.New("Config.ChainID is required")
	}
	if cfg.IssuerID == "" {
		return errors.New("Config.IssuerID is required")
	}
	if cfg.VerificationMethodID == "" {
		return errors.New("Config.VerificationMethodID is required")
	}
	if cfg.ShutdownDeadline < 0 {
		return fmt.Errorf("Config.ShutdownDeadline must be non-negative; got %v", cfg.ShutdownDeadline)
	}
	return nil
}

// loadCustomRedactPatterns loads additional redaction patterns from a YAML
// file. Returns nil (no custom patterns) when path is empty. A non-empty path
// that fails to parse is a startup error — misconfigured redaction would
// silently allow secrets into receipts, which is worse than refusing to start.
func loadCustomRedactPatterns(path string, logger *log.Logger) ([]*regexp.Regexp, error) {
	if path == "" {
		return nil, nil
	}
	patterns, err := pipeline.LoadPatternFile(path)
	if err != nil {
		return nil, fmt.Errorf("load redact patterns: %w", err)
	}
	logger.Printf("loaded %d custom redaction pattern(s) from %s", len(patterns), path)
	return patterns, nil
}
