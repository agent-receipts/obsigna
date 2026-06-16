// Package keyscli implements the `obsigna keys` subcommands — generate, pubkey,
// and rotate — that manage the daemon's Ed25519 signing key from the read-side
// CLI. The heavy lifting lives in the daemon package (daemon.GenerateKey,
// daemon.RotateKey) and internal/keysource; this package only resolves the
// key-relevant configuration (defaults < config file < env < flags, mirroring
// the daemon's own precedence for the fields these verbs touch) and renders the
// CLI surface. Keeping it here, away from cmd/obsigna/main.go, lets tests drive
// each verb directly with captured I/O and an injected environment.
//
// The verbs are the obsigna home for what `obsigna-daemon --init` and
// `--rotate` do today; the daemon binary keeps those flags untouched (ADR-0030,
// ADR-0015).
package keyscli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/daemon/internal/keysource"
)

// Exit codes are part of the CLI contract — keep them stable and aligned with
// the other subcommand packages (verifycli, listcli): 0 ok, 2 usage error. 1 is
// an operational failure (key already exists, store unreadable, rotation
// refused because a daemon is live, …).
const (
	ExitOK         = 0
	ExitError      = 1
	ExitUsageError = 2
)

// pubkeyVerificationMethod is a placeholder fed to keysource.NewFile so Init's
// "verification method required" guard passes. `keys pubkey` only derives the
// public half of the key and never signs, so the value is never embedded in a
// receipt — it exists solely to reuse keysource's TOCTOU-safe, permission-checked
// key loader instead of re-parsing PKCS#8 by hand.
const pubkeyVerificationMethod = "did:obsigna:pubkey"

// RunGenerate implements `obsigna keys generate`: create a fresh Ed25519 signing
// key pair, refusing to overwrite existing files. Mirrors `obsigna-daemon
// --init`.
func RunGenerate(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	getenv = orOsGetenv(getenv)
	// The config error is deferred until after flag parsing so `--help` still
	// works when the config file is malformed or AGENTRECEIPTS_CONFIG names a
	// missing file — help must not depend on a readable config. On error base is
	// the zero Config; the flag defaults are then empty, which is harmless
	// because cfgErr short-circuits before they are used.
	base, cfgErr := baseConfig(getenv)

	fs := flag.NewFlagSet("keys generate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", base.KeyPath, "Ed25519 PEM private key output path, mode 0600 (env: AGENTRECEIPTS_KEY)")
	pubPath := fs.String("public-key", base.PublicKeyPath, "Public key output path as PEM, mode 0644 (default: <key>.pub) (env: AGENTRECEIPTS_PUBLIC_KEY)")
	if code, done := parse(fs, args, stderr, "keys generate"); done {
		return code
	}
	if cfgErr != nil {
		fmt.Fprintf(stderr, "obsigna keys generate: %v\n", cfgErr)
		return ExitUsageError
	}
	if *keyPath == "" {
		fmt.Fprintln(stderr, "obsigna keys generate: --key is required (no AGENTRECEIPTS_KEY and no home directory)")
		return ExitUsageError
	}

	pub := *pubPath
	if pub == "" {
		pub = daemon.DefaultPublicKeyPath(*keyPath)
	}
	if err := daemon.GenerateKey(*keyPath, pub); err != nil {
		fmt.Fprintf(stderr, "obsigna keys generate: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(stdout, "generated signing key: %s\n", *keyPath)
	fmt.Fprintf(stdout, "public key: %s\n", pub)
	return ExitOK
}

// RunPubkey implements `obsigna keys pubkey`: print the SPKI public key derived
// from the signing key at --key. New verb (no legacy equivalent) — useful for
// distributing the verifier key without exposing the private half or relying on
// a previously published .pub file.
func RunPubkey(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	getenv = orOsGetenv(getenv)
	// Config error deferred past parse so `--help` works regardless of config
	// validity (see RunGenerate).
	base, cfgErr := baseConfig(getenv)

	fs := flag.NewFlagSet("keys pubkey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", base.KeyPath, "Ed25519 PEM private key path to derive the public key from (env: AGENTRECEIPTS_KEY)")
	if code, done := parse(fs, args, stderr, "keys pubkey"); done {
		return code
	}
	if cfgErr != nil {
		fmt.Fprintf(stderr, "obsigna keys pubkey: %v\n", cfgErr)
		return ExitUsageError
	}
	if *keyPath == "" {
		fmt.Fprintln(stderr, "obsigna keys pubkey: --key is required (no AGENTRECEIPTS_KEY and no home directory)")
		return ExitUsageError
	}

	ks := keysource.NewFile(*keyPath, pubkeyVerificationMethod)
	if err := ks.Init(); err != nil {
		fmt.Fprintf(stderr, "obsigna keys pubkey: %v\n", err)
		return ExitError
	}
	defer func() { _ = ks.Teardown() }()
	pemStr, err := ks.PublicKey()
	if err != nil {
		fmt.Fprintf(stderr, "obsigna keys pubkey: %v\n", err)
		return ExitError
	}
	// PublicKey() returns a PEM block already terminated by a newline.
	fmt.Fprint(stdout, pemStr)
	return ExitOK
}

// RunRotate implements `obsigna keys rotate`: append a key_rotated receipt
// signed by the current key, archive the current public key, and swap in a new
// key (ADR-0015). Mirrors `obsigna-daemon --rotate`; the daemon must be
// stopped first (daemon.RotateKey refuses while the socket is reachable).
func RunRotate(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	getenv = orOsGetenv(getenv)
	// Config error deferred past parse so `--help` works regardless of config
	// validity (see RunGenerate).
	base, cfgErr := baseConfig(getenv)

	fs := flag.NewFlagSet("keys rotate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", base.KeyPath, "Ed25519 PEM private key path (env: AGENTRECEIPTS_KEY)")
	pubPath := fs.String("public-key", base.PublicKeyPath, "Published public-key path (default: <key>.pub) (env: AGENTRECEIPTS_PUBLIC_KEY)")
	dbPath := fs.String("db", base.DBPath, "SQLite receipt-store path (env: AGENTRECEIPTS_DB)")
	chainID := fs.String("chain-id", base.ChainID, "Chain id to write the rotation under (env: AGENTRECEIPTS_CHAIN_ID)")
	issuerID := fs.String("issuer-id", base.IssuerID, "Receipt issuer.id (env: AGENTRECEIPTS_ISSUER_ID)")
	vmID := fs.String("verification-method", base.VerificationMethodID, "proof.verificationMethod (env: AGENTRECEIPTS_VERIFICATION_METHOD)")
	anchorLog := fs.String("anchor-log", base.AnchorLogPath, "Append-only external-witness log for the rotation event, ADR-0015 (env: AGENTRECEIPTS_ANCHOR_LOG)")
	socketPath := fs.String("socket", base.SocketPath, "Daemon socket path; rotation is refused if a daemon is reachable here (env: AGENTRECEIPTS_SOCKET)")
	if code, done := parse(fs, args, stderr, "keys rotate"); done {
		return code
	}
	if cfgErr != nil {
		fmt.Fprintf(stderr, "obsigna keys rotate: %v\n", cfgErr)
		return ExitUsageError
	}
	// Validate the inputs that can be empty (no flag/env and no resolvable home)
	// here, as a usage error, rather than letting daemon.RotateKey report them as
	// operational errors — this keeps the package's exit-code contract consistent
	// with generate/pubkey (missing required path => ExitUsageError, not ExitError).
	if *keyPath == "" {
		fmt.Fprintln(stderr, "obsigna keys rotate: --key is required (no AGENTRECEIPTS_KEY and no home directory)")
		return ExitUsageError
	}
	if *dbPath == "" {
		fmt.Fprintln(stderr, "obsigna keys rotate: --db is required (no AGENTRECEIPTS_DB and no home directory)")
		return ExitUsageError
	}

	cfg := daemon.Config{
		KeyPath:              *keyPath,
		PublicKeyPath:        *pubPath,
		DBPath:               *dbPath,
		ChainID:              *chainID,
		IssuerID:             *issuerID,
		VerificationMethodID: *vmID,
		AnchorLogPath:        *anchorLog,
		SocketPath:           *socketPath,
	}
	summary, err := daemon.RotateKey(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "obsigna keys rotate: %v\n", err)
		return ExitError
	}

	pubKeyPath := cfg.PublicKeyPath
	if pubKeyPath == "" {
		pubKeyPath = daemon.DefaultPublicKeyPath(cfg.KeyPath)
	}
	fmt.Fprintf(stdout, "rotated signing key on chain %s (seq %d)\n", summary.ChainID, summary.Sequence)
	fmt.Fprintf(stdout, "  key_rotated receipt: %s\n", summary.ReceiptID)
	fmt.Fprintf(stdout, "  outgoing key:        %s\n", summary.OldFingerprint)
	fmt.Fprintf(stdout, "  incoming key:        %s\n", summary.NewFingerprint)
	fmt.Fprintf(stdout, "  archived public key: %s\n", summary.ArchivedPublicKey)
	if summary.AnchoredTo != "" {
		fmt.Fprintf(stdout, "  anchored to:         %s\n", summary.AnchoredTo)
	} else {
		fmt.Fprintf(stdout, "  anchored to:         (none — set --anchor-log for post-compromise integrity)\n")
	}
	fmt.Fprintf(stdout, "\nRestart the daemon to sign with the new key. `obsigna verify`\n")
	fmt.Fprintf(stdout, "checks the rotated chain when pointed at the published key %s —\n", pubKeyPath)
	fmt.Fprintf(stdout, "it resolves the archived genesis key and traverses the rotation automatically.\n")
	return ExitOK
}

// parse runs fs.Parse and maps its outcome to a CLI result. The bool return is
// true when the caller should stop (help printed, or a parse error); false when
// parsing succeeded and the caller should continue. A trailing positional
// argument is rejected — these verbs take only flags.
func parse(fs *flag.FlagSet, args []string, stderr io.Writer, name string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return ExitOK, true
		}
		return ExitUsageError, true
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "obsigna %s: unexpected positional argument(s): %v\n", name, fs.Args())
		return ExitUsageError, true
	}
	return ExitOK, false
}

func orOsGetenv(getenv func(string) string) func(string) string {
	if getenv == nil {
		return os.Getenv
	}
	return getenv
}

// baseConfig assembles the key-relevant configuration from defaults, then the
// TOML config file (default path or AGENTRECEIPTS_CONFIG), then AGENTRECEIPTS_*
// environment variables — the same low-to-high precedence the daemon applies,
// restricted to the fields these verbs use. Callers register flags with these
// values as defaults so an explicit flag still wins (the top precedence layer).
//
// Unlike the daemon, keyscli does not accept a --config flag; it honours the
// default config path and AGENTRECEIPTS_CONFIG so a standard install's
// daemon.toml is respected, which is what avoids `keys rotate` silently
// targeting the wrong store. A --config flag can follow once the daemon's
// two-pass config scanner is shared.
func baseConfig(getenv func(string) string) (daemon.Config, error) {
	cfg := daemon.Config{
		KeyPath:              daemon.DefaultKeyPath(),
		DBPath:               daemon.DefaultDBPath(),
		SocketPath:           daemon.DefaultSocketPath(),
		ChainID:              time.Now().UTC().Format("2006-01-02"),
		IssuerID:             daemon.DefaultIssuerID,
		VerificationMethodID: daemon.DefaultVerificationMethodID,
	}

	fc, err := loadConfigFile(getenv)
	if err != nil {
		return daemon.Config{}, err
	}
	applyFileConfig(&cfg, fc)
	applyEnv(&cfg, getenv)
	return cfg, nil
}

// loadConfigFile resolves the TOML config path (AGENTRECEIPTS_CONFIG, else the
// default path) and loads it. An explicit AGENTRECEIPTS_CONFIG naming a missing
// file is an error; a missing file at the default path is tolerated (nil, nil).
func loadConfigFile(getenv func(string) string) (*daemon.FileConfig, error) {
	path := getenv("AGENTRECEIPTS_CONFIG")
	required := path != ""
	if path == "" {
		path = daemon.DefaultConfigPath()
		if path == "" {
			return nil, nil
		}
	}
	return daemon.LoadConfigFile(path, required)
}

// applyFileConfig overlays the key-relevant fields of a FileConfig onto cfg.
// Only keys present in the file (non-nil pointers) are applied, so an absent key
// leaves the default/env value untouched. No-op when fc is nil.
func applyFileConfig(cfg *daemon.Config, fc *daemon.FileConfig) {
	if fc == nil {
		return
	}
	if fc.Key != nil {
		cfg.KeyPath = *fc.Key
	}
	if fc.PublicKey != nil {
		cfg.PublicKeyPath = *fc.PublicKey
	}
	if fc.DB != nil {
		cfg.DBPath = *fc.DB
	}
	if fc.ChainID != nil {
		cfg.ChainID = *fc.ChainID
	}
	if fc.IssuerID != nil {
		cfg.IssuerID = *fc.IssuerID
	}
	if fc.VerificationMethod != nil {
		cfg.VerificationMethodID = *fc.VerificationMethod
	}
	if fc.Socket != nil {
		cfg.SocketPath = *fc.Socket
	}
}

// applyEnv overlays AGENTRECEIPTS_* variables onto cfg. An unset (empty)
// variable leaves the existing value in place.
func applyEnv(cfg *daemon.Config, getenv func(string) string) {
	if v := getenv("AGENTRECEIPTS_KEY"); v != "" {
		cfg.KeyPath = v
	}
	if v := getenv("AGENTRECEIPTS_PUBLIC_KEY"); v != "" {
		cfg.PublicKeyPath = v
	}
	if v := getenv("AGENTRECEIPTS_DB"); v != "" {
		cfg.DBPath = v
	}
	if v := getenv("AGENTRECEIPTS_CHAIN_ID"); v != "" {
		cfg.ChainID = v
	}
	if v := getenv("AGENTRECEIPTS_ISSUER_ID"); v != "" {
		cfg.IssuerID = v
	}
	if v := getenv("AGENTRECEIPTS_VERIFICATION_METHOD"); v != "" {
		cfg.VerificationMethodID = v
	}
	if v := getenv("AGENTRECEIPTS_SOCKET"); v != "" {
		cfg.SocketPath = v
	}
	if v := getenv("AGENTRECEIPTS_ANCHOR_LOG"); v != "" {
		cfg.AnchorLogPath = v
	}
}
