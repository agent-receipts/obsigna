// Package disclosecli implements the `obsigna receipt disclose <seq>` subcommand:
// decrypt the parameters_disclosure envelope of a single stored receipt using
// the operator's X25519 forensic private key and print the recovered plaintext.
//
// Logic lives here, away from cmd/agent-receipts/main.go, so tests can drive
// the subcommand directly with arbitrary args / captured I/O without shelling
// out to a built binary.
package disclosecli

import (
	"bytes"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"text/tabwriter"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

const (
	ExitOK           = 0 // parameters decrypted and printed (or no disclosure on receipt)
	ExitNotFound     = 1 // no receipt at the requested sequence
	ExitUsageError   = 2 // bad flags / unreadable DB / ambiguous chain
	ExitDecryptError = 3 // key missing, wrong recipient, or HPKE failure
)

// Run executes the disclose subcommand with the given args (sans the program
// name and "disclose" subcommand token), writing output to stdout and
// diagnostics to stderr. Returns one of the Exit* constants.
//
// envLookup is split out so tests can inject a deterministic environment
// without touching the real process env. Pass os.Getenv for the production
// caller.
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

	fs := flag.NewFlagSet("receipt disclose", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: obsigna receipt disclose <seq> [flags]")
		fmt.Fprintln(stderr, "\nDecrypt the parameters_disclosure envelope of a single stored receipt")
		fmt.Fprintln(stderr, "using the operator's X25519 forensic private key.")
		fmt.Fprintln(stderr, "\nThe key may be supplied as a raw 32-byte file, hex (64 chars),")
		fmt.Fprintln(stderr, "standard or URL-safe base64, or a PKCS#8 PEM-wrapped X25519 key.")
		fmt.Fprintln(stderr, "\nFlags:")
		fs.PrintDefaults()
	}

	dbPath := fs.String("db", envOr("AGENTRECEIPTS_DB", daemon.DefaultDBPath()),
		"SQLite receipt-store path (env: AGENTRECEIPTS_DB)")
	chainID := fs.String("chain-id", envLookup("AGENTRECEIPTS_CHAIN_ID"),
		"Chain id to read from (env: AGENTRECEIPTS_CHAIN_ID); required only when the store holds more than one chain")
	keyPath := fs.String("key", envOr("AGENTRECEIPTS_FORENSIC_KEY", daemon.DefaultForensicKeyPath()),
		"Forensic private-key path (raw 32-byte X25519, hex, base64, or PKCS#8 PEM) (env: AGENTRECEIPTS_FORENSIC_KEY)")
	asJSON := fs.Bool("json", false, "Output decrypted parameters as JSON")

	var rest []string
	remaining := args
	for {
		if err := fs.Parse(remaining); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return ExitOK
			}
			return ExitUsageError
		}
		if fs.NArg() == 0 {
			break
		}
		rest = append(rest, fs.Arg(0))
		remaining = fs.Args()[1:]
	}

	if len(rest) == 0 {
		fmt.Fprintln(stderr, "obsigna receipt disclose: missing <seq> argument (the chain sequence number, 1-indexed)")
		return ExitUsageError
	}
	if len(rest) > 1 {
		fmt.Fprintf(stderr, "obsigna receipt disclose: unexpected positional argument(s): %v (only one <seq> is accepted)\n", rest[1:])
		return ExitUsageError
	}
	seq, err := strconv.Atoi(rest[0])
	if err != nil || seq < 1 {
		fmt.Fprintf(stderr, "obsigna receipt disclose: <seq> must be a positive integer, got %q\n", rest[0])
		return ExitUsageError
	}

	if *dbPath == "" {
		fmt.Fprintln(stderr, "obsigna receipt disclose: --db is required (no AGENTRECEIPTS_DB and no home directory)")
		return ExitUsageError
	}
	if *keyPath == "" {
		fmt.Fprintln(stderr, "obsigna receipt disclose: --key is required (no AGENTRECEIPTS_FORENSIC_KEY and no home directory)")
		return ExitDecryptError
	}

	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "obsigna receipt disclose: read key %q: %v\n", *keyPath, err)
		return ExitDecryptError
	}
	// The on-disk bytes hold key material too; wipe them alongside the parsed
	// key. Best-effort — the Go runtime may still retain copies — but it keeps
	// the raw buffer from sitting around for the rest of Run.
	defer zeroSlice(raw)
	privKey, err := parseForensicPrivateKey(raw)
	if err != nil {
		fmt.Fprintf(stderr, "obsigna receipt disclose: invalid forensic key: %v\n", err)
		return ExitDecryptError
	}
	defer zeroSlice(privKey)

	s, err := store.OpenReadOnly(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "obsigna receipt disclose: open store: %v\n", err)
		return ExitUsageError
	}
	defer s.Close()

	resolved, code := resolveChainID(s, *chainID, stderr)
	if code != ExitOK {
		return code
	}

	r, err := s.GetByChainSequence(resolved, seq)
	if err != nil {
		fmt.Fprintf(stderr, "obsigna receipt disclose: read chain %q: %v\n", resolved, err)
		return ExitUsageError
	}
	if r == nil {
		fmt.Fprintf(stderr, "obsigna receipt disclose: no receipt at sequence %d in chain %q\n", seq, resolved)
		return ExitNotFound
	}

	env := r.CredentialSubject.Action.ParametersDisclosure
	if env == nil {
		fmt.Fprintf(stderr, "obsigna receipt disclose: receipt at sequence %d has no parameters_disclosure\n", seq)
		return ExitOK
	}

	params, err := receipt.DecryptDisclosure(env, privKey)
	if err != nil {
		// Classify: if our key's fingerprint matches a recipient kid the envelope
		// is corrupt; otherwise we're the wrong key holder.
		pub, pubErr := receipt.ForensicPublicFromPrivate(privKey)
		if pubErr == nil {
			fp, fpErr := receipt.ForensicKeyFingerprint(pub)
			if fpErr == nil {
				for _, rcpt := range env.Recipients {
					if rcpt.KID == fp {
						fmt.Fprintf(stderr, "obsigna receipt disclose: decryption failed (envelope may be corrupt): %v\n", err)
						return ExitDecryptError
					}
				}
			}
		}
		fmt.Fprintf(stderr, "obsigna receipt disclose: key does not match any recipient in the envelope\n")
		return ExitDecryptError
	}

	if *asJSON {
		return writeJSON(stdout, stderr, params)
	}
	return writeHuman(stdout, params)
}

func writeJSON(stdout, stderr io.Writer, params map[string]any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(params); err != nil {
		if errors.Is(err, syscall.EPIPE) || errors.Is(err, io.ErrClosedPipe) {
			return ExitOK
		}
		fmt.Fprintf(stderr, "obsigna receipt disclose: encode JSON: %v\n", err)
		return ExitUsageError
	}
	return ExitOK
}

func writeHuman(stdout io.Writer, params map[string]any) int {
	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	// Sort keys for stable output.
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		v := params[k]
		var s string
		switch val := v.(type) {
		case string:
			s = val
		default:
			b, _ := json.Marshal(val)
			s = string(b)
		}
		fmt.Fprintf(w, "%s:\t%s\n", k, s)
	}
	if err := w.Flush(); err != nil {
		if errors.Is(err, syscall.EPIPE) || errors.Is(err, io.ErrClosedPipe) {
			return ExitOK
		}
		return ExitUsageError
	}
	return ExitOK
}

// resolveChainID returns the chain id to read from. When requested is non-empty
// it is used verbatim. Otherwise the store must hold exactly one chain.
func resolveChainID(s *store.Store, requested string, stderr io.Writer) (string, int) {
	if requested != "" {
		return requested, ExitOK
	}
	chains, err := s.DistinctChainIDs()
	if err != nil {
		fmt.Fprintf(stderr, "obsigna receipt disclose: enumerate chains: %v\n", err)
		return "", ExitUsageError
	}
	switch len(chains) {
	case 0:
		fmt.Fprintln(stderr, "obsigna receipt disclose: store holds no receipts")
		return "", ExitNotFound
	case 1:
		return chains[0], ExitOK
	default:
		fmt.Fprintf(stderr, "obsigna receipt disclose: store holds %d chains; pass --chain-id to select one. Available chains:\n", len(chains))
		for _, c := range chains {
			fmt.Fprintf(stderr, "  %s\n", c)
		}
		return "", ExitUsageError
	}
}

// parseForensicPrivateKey accepts the forensic private key in any of the forms
// a solo operator is likely to hand it over: raw 32-byte file, hex (64 chars),
// standard or URL-safe base64 (padded or unpadded), or PKCS#8 PEM-wrapped X25519.
// Returns the raw 32-byte key on success.
func parseForensicPrivateKey(raw []byte) ([]byte, error) {
	if len(raw) == 32 {
		return append([]byte(nil), raw...), nil
	}
	// Raw key file with a trailing newline appended by a text editor or shell.
	stripped := raw
	for len(stripped) > 32 && (stripped[len(stripped)-1] == '\n' || stripped[len(stripped)-1] == '\r') {
		stripped = stripped[:len(stripped)-1]
	}
	if len(stripped) == 32 {
		return append([]byte(nil), stripped...), nil
	}

	trimmed := bytes.TrimSpace(raw)

	if block, _ := pem.Decode(trimmed); block != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 PEM: %w", err)
		}
		xkey, ok := key.(*ecdh.PrivateKey)
		if !ok || xkey.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("PEM key is not an X25519 private key")
		}
		return xkey.Bytes(), nil
	}

	s := string(trimmed)
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("unrecognised key encoding or wrong length")
}

func zeroSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j] < ss[j-1]; j-- {
			ss[j], ss[j-1] = ss[j-1], ss[j]
		}
	}
}
