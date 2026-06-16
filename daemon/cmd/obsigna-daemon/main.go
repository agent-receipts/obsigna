// Command obsigna-daemon runs the receipts daemon: a single OS-user process
// that owns the Ed25519 signing key and the SQLite receipt store, and receives
// fire-and-forget event frames from emitters over a Unix-domain socket. See
// ADR-0010 for design and ADR-0031 for why the daemon is its own minimal binary
// (a lean import graph that never reaches the operator CLI surface, launched via
// `obsigna daemon run` which execs straight into this image to keep the
// attestation tuple — /proc/self/exe, parent PID, start time — intact).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agent-receipts/ar/daemon"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
// Falls back to the module version from Go's build info (set automatically
// for binaries installed with `go install`), then to "dev". Mirrors the
// resolveVersion pattern in mcp-proxy/cmd/obsigna-mcp/main.go so operators
// see a useful string from `--version` in any install scenario.
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

// resolved is the outcome of merging the config file, environment, and flags.
// The action fields are mutually exclusive top-level requests that short-circuit
// before the daemon starts; cfg is the merged daemon configuration.
type resolved struct {
	cfg             daemon.Config
	showVersion     bool
	showProtocol    bool
	initKeys        bool
	initForensicKey bool
	rotate          bool
	forensicKeyPath string
	printConfig     bool
}

func main() {
	r, err := resolveConfig(os.Args[1:], os.Getenv, os.Stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "obsigna-daemon: %v\n", err)
		os.Exit(1)
	}

	if r.showVersion {
		fmt.Printf("obsigna-daemon %s\n", resolveVersion())
		return
	}

	if r.showProtocol {
		// Machine-readable spoken-range surface for ADR-0024 Gate #8. The gate
		// reads this from the released binary and asserts it intersects the
		// range each released SDK declares it can emit.
		out, err := json.Marshal(daemon.SpokenProtocolVersion())
		if err != nil {
			fmt.Fprintf(os.Stderr, "obsigna-daemon --protocol-version: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(out))
		return
	}

	if r.initKeys {
		if r.cfg.PublicKeyPath == "" {
			r.cfg.PublicKeyPath = daemon.DefaultPublicKeyPath(r.cfg.KeyPath)
		}
		if err := daemon.GenerateKey(r.cfg.KeyPath, r.cfg.PublicKeyPath); err != nil {
			fmt.Fprintf(os.Stderr, "obsigna-daemon --init: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("generated signing key: %s\n", r.cfg.KeyPath)
		fmt.Printf("public key: %s\n", r.cfg.PublicKeyPath)
		return
	}

	if r.initForensicKey {
		if r.cfg.ForensicPublicKeyPath == "" {
			r.cfg.ForensicPublicKeyPath = daemon.DefaultForensicPublicKeyPath(r.forensicKeyPath)
		}
		fingerprint, err := daemon.GenerateForensicKey(r.forensicKeyPath, r.cfg.ForensicPublicKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "obsigna-daemon --init-forensic-key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("generated forensic private key: %s (keep this offline; the daemon never reads it)\n", r.forensicKeyPath)
		fmt.Printf("forensic public key:           %s\n", r.cfg.ForensicPublicKeyPath)
		fmt.Printf("fingerprint (kid):             %s\n", fingerprint)
		fmt.Printf("\nTo enable disclosure, start the daemon with:\n")
		fmt.Printf("  --forensic-public-key %s --parameter-disclosure <true|high|action.types>\n", r.cfg.ForensicPublicKeyPath)
		return
	}

	// Apply the <--key>.pub default now that resolution has finalised KeyPath.
	// daemon.validateConfig also covers this path for library callers; doing
	// it here too keeps the startup log line ("published public key to ...")
	// printing the same path the daemon writes to.
	if r.cfg.PublicKeyPath == "" {
		r.cfg.PublicKeyPath = daemon.DefaultPublicKeyPath(r.cfg.KeyPath)
	}

	if r.rotate {
		summary, err := daemon.RotateKey(r.cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "obsigna-daemon --rotate: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("rotated signing key on chain %s (seq %d)\n", summary.ChainID, summary.Sequence)
		fmt.Printf("  key_rotated receipt: %s\n", summary.ReceiptID)
		fmt.Printf("  outgoing key:        %s\n", summary.OldFingerprint)
		fmt.Printf("  incoming key:        %s\n", summary.NewFingerprint)
		fmt.Printf("  archived public key: %s\n", summary.ArchivedPublicKey)
		if summary.AnchoredTo != "" {
			fmt.Printf("  anchored to:         %s\n", summary.AnchoredTo)
		} else {
			fmt.Printf("  anchored to:         (none — set --anchor-log for post-compromise integrity)\n")
		}
		fmt.Printf("\nRestart the daemon to sign with the new key. `obsigna verify`\n")
		fmt.Printf("checks the rotated chain when pointed at the published key %s —\n", r.cfg.PublicKeyPath)
		fmt.Printf("it resolves the archived genesis key and traverses the rotation automatically.\n")
		return
	}

	if r.printConfig {
		printConfig(os.Stdout, r.cfg)
		return
	}

	logger := log.New(os.Stderr, "obsigna-daemon ", log.LstdFlags|log.Lmicroseconds)
	r.cfg.Logger = logger

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := daemon.Run(ctx, r.cfg); err != nil {
		fmt.Fprintf(os.Stderr, "obsigna-daemon: %v\n", err)
		os.Exit(1)
	}
}

// resolveConfig merges configuration from three layers, lowest priority first:
//
//  1. the TOML config file (default path or --config), then
//  2. environment variables (AGENTRECEIPTS_*), then
//  3. command-line flags.
//
// A higher layer overrides a lower one. The file is the lowest-priority layer:
// a key absent from the file leaves the env/default value untouched, and any
// env var or explicit flag overrides a file value.
//
// getenv and errOut are injected so the merge is unit-testable without touching
// the process environment or global flag state.
func resolveConfig(args []string, getenv func(string) string, errOut io.Writer) (resolved, error) {
	fs := flag.NewFlagSet("obsigna-daemon", flag.ContinueOnError)
	fs.SetOutput(errOut)

	configPath := fs.String("config", "", "Path to a TOML config file (default: $XDG_DATA_HOME/agent-receipts/daemon.toml; ignored if absent)")
	initKeys := fs.Bool("init", false, "Generate a new signing key pair and exit (must not exist)")
	initForensicKey := fs.Bool("init-forensic-key", false, "Generate a new X25519 forensic key pair (ADR-0012) and exit. Writes the private key to --forensic-key and the public key to --forensic-public-key (must not exist)")
	rotate := fs.Bool("rotate", false, "Rotate the signing key (ADR-0015): append a key_rotated receipt signed by the current key, archive the current public key, and swap in a new key, then exit. Stop the daemon first.")
	showVersion := fs.Bool("version", false, "Print version and exit")
	showProtocol := fs.Bool("protocol-version", false, "Print the daemon's spoken wire-protocol version range as JSON and exit")
	printConfigFlag := fs.Bool("print-config", false, "Print the resolved config (file < env < flags) and exit")

	// Layer 1 + 2: start from per-OS defaults, then overlay the config file
	// (if any), then environment variables. The resulting values become the
	// flag defaults, so an explicit flag (layer 3) overrides them on Parse.
	cfg := daemon.Config{
		SocketPath:           daemon.DefaultSocketPath(),
		DBPath:               daemon.DefaultDBPath(),
		KeyPath:              daemon.DefaultKeyPath(),
		ChainID:              time.Now().UTC().Format("2006-01-02"),
		IssuerID:             daemon.DefaultIssuerID,
		VerificationMethodID: daemon.DefaultVerificationMethodID,
		ShutdownDeadline:     200 * time.Millisecond,
	}

	fc, err := loadConfigLayer(args, getenv)
	if err != nil {
		return resolved{}, err
	}
	applyFileConfig(&cfg, fc)

	if err := envOverlay(&cfg, getenv); err != nil {
		return resolved{}, err
	}

	fs.StringVar(&cfg.SocketPath, "socket", cfg.SocketPath, "Unix-domain socket path (env: AGENTRECEIPTS_SOCKET)")
	fs.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite receipt-store path (env: AGENTRECEIPTS_DB)")
	fs.StringVar(&cfg.KeyPath, "key", cfg.KeyPath, "Ed25519 PEM private key path, mode 0600 (env: AGENTRECEIPTS_KEY)")
	fs.StringVar(&cfg.PublicKeyPath, "public-key", cfg.PublicKeyPath, "Path to publish the SPKI public key as PEM, mode 0644 (default: <--key>.pub) (env: AGENTRECEIPTS_PUBLIC_KEY)")
	fs.StringVar(&cfg.ForensicPublicKeyPath, "forensic-public-key", cfg.ForensicPublicKeyPath, "Path to the X25519 forensic public key (32 raw bytes) for HPKE parameter encryption (ADR-0012). When set, tool parameters are encrypted before signing (env: AGENTRECEIPTS_FORENSIC_PUBLIC_KEY)")
	forensicKeyPath := fs.String("forensic-key", daemon.DefaultForensicKeyPath(), "Forensic private-key output path for --init-forensic-key (raw 32 bytes, mode 0600). Not read at runtime — the daemon never holds the private key")
	fs.StringVar(&cfg.ChainID, "chain-id", cfg.ChainID, "Chain id to write under (env: AGENTRECEIPTS_CHAIN_ID)")
	fs.StringVar(&cfg.IssuerID, "issuer-id", cfg.IssuerID, "Receipt issuer.id (env: AGENTRECEIPTS_ISSUER_ID)")
	fs.StringVar(&cfg.VerificationMethodID, "verification-method", cfg.VerificationMethodID, "proof.verificationMethod (env: AGENTRECEIPTS_VERIFICATION_METHOD)")
	fs.StringVar(&cfg.AnchorLogPath, "anchor-log", cfg.AnchorLogPath, "Append-only external-witness log for rotation events (ADR-0015). When set, --rotate writes the rotation event here before committing locally; a write failure aborts the rotation. (env: AGENTRECEIPTS_ANCHOR_LOG)")
	fs.StringVar(&cfg.ParameterDisclosure, "parameter-disclosure", cfg.ParameterDisclosure, "Which actions encrypt their parameters into parameters_disclosure (ADR-0012): false|true|high|<comma-separated action types>. Requires --forensic-public-key. (env: AGENTRECEIPTS_PARAMETER_DISCLOSURE)")
	fs.BoolVar(&cfg.UnsafeSocketPath, "unsafe-socket-path", cfg.UnsafeSocketPath, "Permit a --socket/AGENTRECEIPTS_SOCKET path outside the per-platform safe set (logs a warning; does not override TCP rejection) (env: AGENTRECEIPTS_UNSAFE_SOCKET_PATH)")
	fs.StringVar(&cfg.RedactPatternsPath, "redact-patterns", cfg.RedactPatternsPath, "Path to a YAML file of additional redaction patterns (merged with built-in defaults) (env: AGENTRECEIPTS_REDACT_PATTERNS)")
	fs.DurationVar(&cfg.ShutdownDeadline, "shutdown-deadline", cfg.ShutdownDeadline, "Best-effort time budget for emitting interrupted-chain terminators on SIGTERM/SIGINT (cannot preempt in-progress SQLite I/O)")

	// scanConfigFlag (via loadConfigLayer) is the source of truth for --config:
	// it has already consumed the value, so we never read *configPath. The flag
	// is registered on fs only so Parse accepts --config and -h lists it.
	_ = configPath

	// Layer 3: explicit flags override file+env.
	if err := fs.Parse(args); err != nil {
		return resolved{}, err
	}

	return resolved{
		cfg:             cfg,
		showVersion:     *showVersion,
		showProtocol:    *showProtocol,
		initKeys:        *initKeys,
		initForensicKey: *initForensicKey,
		rotate:          *rotate,
		forensicKeyPath: *forensicKeyPath,
		printConfig:     *printConfigFlag,
	}, nil
}

// loadConfigLayer resolves the config-file path (--config flag or the default
// XDG path) and loads it. An explicit --config naming a missing file is an
// error; a missing file at the default path is tolerated (returns a nil
// FileConfig).
func loadConfigLayer(args []string, getenv func(string) string) (*daemon.FileConfig, error) {
	// First pass: read only --config so we know which file to load before
	// registering the rest of the flags (whose defaults depend on the file).
	// We can't use flag.Parse here — it stops at the first unknown flag — so we
	// scan args directly.
	configPath, explicit := scanConfigFlag(args)
	if !explicit {
		if v := getenv("AGENTRECEIPTS_CONFIG"); v != "" {
			configPath = v
			explicit = true
		}
	}

	if explicit && configPath == "" {
		// --config (or AGENTRECEIPTS_CONFIG) was given with no value. Falling
		// back to the default path here would either error against a path the
		// operator never named or silently load the default as if explicit;
		// both are confusing, so reject it outright.
		return nil, errors.New("--config requires a path")
	}

	path := configPath
	required := explicit
	if path == "" {
		path = daemon.DefaultConfigPath()
		if path == "" {
			// No XDG data home and no home dir: skip the file layer entirely.
			return nil, nil
		}
	}

	fc, err := daemon.LoadConfigFile(path, required)
	if err != nil {
		return nil, err
	}
	return fc, nil
}

// scanConfigFlag extracts the --config value from args, accepting both the
// "--config path" (separate token) and "--config=path" forms with one or two
// leading dashes. The second return is whether the flag was present at all, so
// the caller can distinguish "explicit --config" (missing file is an error)
// from "no --config" (fall back to the default path, where a missing file is
// fine). Stops at "--" so it never reads past the flag terminator.
//
// This is the source of truth for --config: it loads the file before any other
// flag is registered. When --config is repeated it returns the LAST occurrence,
// matching Go's flag package (last-wins) so the file we load agrees with what
// fs.Parse would record for the registered --config flag.
func scanConfigFlag(args []string) (string, bool) {
	value := ""
	found := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		switch {
		case a == "--config" || a == "-config":
			found = true
			if i+1 < len(args) {
				value = args[i+1]
				i++
			} else {
				value = ""
			}
		case strings.HasPrefix(a, "--config="):
			value, found = strings.TrimPrefix(a, "--config="), true
		case strings.HasPrefix(a, "-config="):
			value, found = strings.TrimPrefix(a, "-config="), true
		}
	}
	return value, found
}

// applyFileConfig overlays a FileConfig onto cfg. Only keys present in the file
// (non-nil pointers) are applied; absent keys leave cfg untouched so the
// default (and later env/flag) value survives. No-op when fc is nil.
func applyFileConfig(cfg *daemon.Config, fc *daemon.FileConfig) {
	if fc == nil {
		return
	}
	if fc.Socket != nil {
		cfg.SocketPath = *fc.Socket
	}
	if fc.DB != nil {
		cfg.DBPath = *fc.DB
	}
	if fc.Key != nil {
		cfg.KeyPath = *fc.Key
	}
	if fc.PublicKey != nil {
		cfg.PublicKeyPath = *fc.PublicKey
	}
	if fc.ForensicPublicKey != nil {
		cfg.ForensicPublicKeyPath = *fc.ForensicPublicKey
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
	if fc.ParameterDisclosure != nil {
		cfg.ParameterDisclosure = fc.ParameterDisclosure.Value
	}
	if fc.UnsafeSocketPath != nil {
		cfg.UnsafeSocketPath = *fc.UnsafeSocketPath
	}
	if fc.RedactPatterns != nil {
		cfg.RedactPatternsPath = *fc.RedactPatterns
	}
	if fc.ShutdownDeadline != nil {
		cfg.ShutdownDeadline = fc.ShutdownDeadline.Duration
	}
}

// envOverlay applies AGENTRECEIPTS_* environment variables over cfg. An unset
// (empty) variable leaves the existing value — already merged from defaults and
// the file — in place. A malformed boolean variable is rejected with an error
// rather than silently degrading to false: env outranks the file, so coercing
// e.g. AGENTRECEIPTS_UNSAFE_SOCKET_PATH=banana to false would quietly clobber a
// file's unsafe_socket_path = true. This mirrors the config loader's
// "reject malformed config rather than silently degrade" stance.
func envOverlay(cfg *daemon.Config, getenv func(string) string) error {
	if v := getenv("AGENTRECEIPTS_SOCKET"); v != "" {
		cfg.SocketPath = v
	}
	if v := getenv("AGENTRECEIPTS_DB"); v != "" {
		cfg.DBPath = v
	}
	if v := getenv("AGENTRECEIPTS_KEY"); v != "" {
		cfg.KeyPath = v
	}
	if v := getenv("AGENTRECEIPTS_PUBLIC_KEY"); v != "" {
		cfg.PublicKeyPath = v
	}
	if v := getenv("AGENTRECEIPTS_FORENSIC_PUBLIC_KEY"); v != "" {
		cfg.ForensicPublicKeyPath = v
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
	if v := getenv("AGENTRECEIPTS_ANCHOR_LOG"); v != "" {
		cfg.AnchorLogPath = v
	}
	if v := getenv("AGENTRECEIPTS_PARAMETER_DISCLOSURE"); v != "" {
		cfg.ParameterDisclosure = v
	}
	if v := getenv("AGENTRECEIPTS_UNSAFE_SOCKET_PATH"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid AGENTRECEIPTS_UNSAFE_SOCKET_PATH %q: want a boolean (1/0, true/false)", v)
		}
		cfg.UnsafeSocketPath = b
	}
	if v := getenv("AGENTRECEIPTS_REDACT_PATTERNS"); v != "" {
		cfg.RedactPatternsPath = v
	}
	return nil
}

// printConfig writes the resolved config in TOML-ish key=value form, mirroring
// the config-file keys so the output doubles as a starting daemon.toml. The
// signing-key path is printed (it is a filesystem path, not key material — the
// daemon never logs the key bytes), matching how --init already echoes it.
func printConfig(w io.Writer, cfg daemon.Config) {
	fmt.Fprintf(w, "socket = %q\n", cfg.SocketPath)
	fmt.Fprintf(w, "db = %q\n", cfg.DBPath)
	fmt.Fprintf(w, "key = %q\n", cfg.KeyPath)
	fmt.Fprintf(w, "public_key = %q\n", cfg.PublicKeyPath)
	fmt.Fprintf(w, "forensic_public_key = %q\n", cfg.ForensicPublicKeyPath)
	fmt.Fprintf(w, "chain_id = %q\n", cfg.ChainID)
	fmt.Fprintf(w, "issuer_id = %q\n", cfg.IssuerID)
	fmt.Fprintf(w, "verification_method = %q\n", cfg.VerificationMethodID)
	fmt.Fprintf(w, "parameter_disclosure = %q\n", cfg.ParameterDisclosure)
	fmt.Fprintf(w, "redact_patterns = %q\n", cfg.RedactPatternsPath)
	fmt.Fprintf(w, "unsafe_socket_path = %t\n", cfg.UnsafeSocketPath)
	fmt.Fprintf(w, "shutdown_deadline = %q\n", cfg.ShutdownDeadline.String())
}
