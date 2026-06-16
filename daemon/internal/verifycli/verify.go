// Package verifycli implements the `obsigna receipt verify` subcommand:
// validate a stored chain's signatures and hash links using a daemon-written
// SQLite store and the daemon-published public key. For a chain that has
// survived an offline key rotation the published key is the post-rotation key,
// so verification resolves the genesis key — the key that signed the first
// receipt — from the archives `obsigna-daemon --rotate` leaves beside it, then
// traverses each key_rotated receipt forward (spec §7.3.7). It opens the
// database read-only (sdk/go/store.OpenReadOnly) so it is safe to run while the
// daemon is the active writer, and it does not require the daemon socket to be
// reachable — independent verifiability is not gated on daemon availability
// (issue #236, Section 4).
//
// Logic lives here, away from cmd/agent-receipts/main.go, so tests can drive
// the subcommand directly with arbitrary args / captured I/O without shelling
// out to a built binary.
package verifycli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// Exit codes are part of the CLI contract — scripts and CI checks pivot on
// them. Keep these stable.
const (
	ExitOK         = 0 // chain verified
	ExitChainBad   = 1 // chain failed verification
	ExitUsageError = 2 // bad flags / unreadable DB or key file
)

// Run executes the verify subcommand with the given args (sans the program
// name and "verify" subcommand token), writing human-readable output to
// stdout and diagnostics to stderr. Returns one of the Exit* constants;
// cmd/agent-receipts/main.go forwards it to os.Exit.
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

	// Resolve the public-key default in two steps so the flag declaration
	// stays readable: --public-key inherits AGENTRECEIPTS_PUBLIC_KEY when set,
	// otherwise it falls back to <KeyPath>.pub computed from the same KeyPath
	// the daemon would use, so a verify run with no flags works after the
	// daemon has run at least once with the same per-user paths.
	keyPath := envOr("AGENTRECEIPTS_KEY", daemon.DefaultKeyPath())
	defaultPubKey := envOr("AGENTRECEIPTS_PUBLIC_KEY", daemon.DefaultPublicKeyPath(keyPath))

	fs := flag.NewFlagSet("receipt verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", envOr("AGENTRECEIPTS_DB", daemon.DefaultDBPath()), "SQLite receipt-store path (env: AGENTRECEIPTS_DB)")
	pubKeyPath := fs.String("public-key", defaultPubKey, "PEM-encoded SPKI public key path (env: AGENTRECEIPTS_PUBLIC_KEY)")
	chainID := fs.String("chain-id", envOr("AGENTRECEIPTS_CHAIN_ID", time.Now().UTC().Format("2006-01-02")), "Chain id to verify (env: AGENTRECEIPTS_CHAIN_ID)")
	if err := fs.Parse(args); err != nil {
		// `-h` / `--help` is intentional, not an error — flag.ContinueOnError
		// surfaces it as flag.ErrHelp after writing the usage message. Exit 0
		// so scripts that probe `obsigna receipt verify -h` don't see a failure.
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsageError
	}
	// `verify` takes no positional arguments — chain selection is via
	// --chain-id. Surface stray args as a usage error so a typo like
	// `obsigna receipt verify --db /path/to.db extra` doesn't silently succeed
	// and hide a scripting mistake.
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "obsigna receipt verify: unexpected positional argument(s): %v (use --chain-id for chain selection)\n", fs.Args())
		return ExitUsageError
	}
	if *dbPath == "" {
		fmt.Fprintln(stderr, "obsigna receipt verify: --db is required (no AGENTRECEIPTS_DB and no home directory)")
		return ExitUsageError
	}
	if *pubKeyPath == "" {
		fmt.Fprintln(stderr, "obsigna receipt verify: --public-key is required (set AGENTRECEIPTS_PUBLIC_KEY directly, or AGENTRECEIPTS_KEY so its <KeyPath>.pub default can be derived; both are unset and no home directory is available)")
		return ExitUsageError
	}

	pubPEM, err := os.ReadFile(*pubKeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "obsigna receipt verify: read public key: %v\n", err)
		return ExitUsageError
	}
	// Validate the public key's PEM/SPKI shape upfront so a malformed key
	// surfaces as a usage error instead of being routed through
	// VerifyStoredChain → ExitChainBad, which would falsely suggest the chain
	// itself was tampered with.
	if err := validatePublicKeyPEM(pubPEM); err != nil {
		fmt.Fprintf(stderr, "obsigna receipt verify: invalid public key at %s: %v\n", *pubKeyPath, err)
		return ExitUsageError
	}

	s, err := store.OpenReadOnly(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "obsigna receipt verify: open store: %v\n", err)
		return ExitUsageError
	}
	defer s.Close()

	receipts, err := s.GetChain(*chainID)
	if err != nil {
		fmt.Fprintf(stderr, "obsigna receipt verify: load chain: %v\n", err)
		return ExitUsageError
	}

	// Resolve the genesis key before verifying. After an offline key rotation
	// the *published* .pub holds the post-rotation key, but a chain is anchored
	// to the key that signed its first receipt: VerifyChain must start there and
	// traverse each key_rotated receipt forward (spec §7.3.7).
	// `obsigna-daemon --rotate` archives every superseded public key beside
	// the live one as
	// `<public-key>.rotated-<fingerprint>`, so a verify run pointed only at the
	// current .pub would otherwise report a rotated chain as BROKEN at receipt 0.
	// With no rotation the published key already is the genesis key and this is a
	// no-op.
	genesisPEM, genesisPath := resolveGenesisKey(receipts, candidate{path: *pubKeyPath, pem: string(pubPEM)}, stderr)
	resolvedFromArchive := genesisPath != *pubKeyPath
	if resolvedFromArchive {
		fmt.Fprintf(stderr, "Note: chain is rotated; verifying from archived genesis key %s\n", genesisPath)
	}

	result := receipt.VerifyChain(receipts, genesisPEM)

	// Pin a rotation-resolved chain back to the operator's published key.
	// resolveGenesisKey anchors on whatever archived key signed receipt[0], so a
	// chain forged end-to-end under an attacker key — with a matching
	// <public-key>.rotated-* archive planted beside the real key — would otherwise
	// verify against that archive and report VALID. Require the chain's most recent
	// rotation to hand signing duty to the published key: proof the published key
	// is the current key the lineage culminates in, not an unrelated key the
	// attacker never superseded. Only needed when an archive was used as genesis —
	// when the published key itself signed receipt[0], VerifyChain already proved
	// the binding. new_key_fingerprint is trustworthy here because result.Valid
	// means VerifyChain checked it against the inline new_public_key (spec §7.3.7).
	if result.Valid && resolvedFromArchive {
		publishedFp, err := publicKeyFingerprint(pubPEM)
		if err != nil {
			fmt.Fprintf(stderr, "obsigna receipt verify: fingerprint published key: %v\n", err)
			return ExitUsageError
		}
		currentFp, rotated := currentChainKeyFingerprint(receipts)
		switch {
		case !rotated:
			fmt.Fprintf(stdout, "Chain %s: BROKEN — verified against an archived key, but the chain has no key rotation that installs the published key %s\n", *chainID, *pubKeyPath)
			return ExitChainBad
		case currentFp != publishedFp:
			fmt.Fprintf(stdout, "Chain %s: BROKEN — rotation chain does not terminate at the published key\n", *chainID)
			fmt.Fprintf(stdout, "  cause: verified from archived genesis %s, but the chain's current key %s is not the published key %s (%s)\n",
				genesisPath, currentFp, *pubKeyPath, publishedFp)
			return ExitChainBad
		}
	}

	if result.ResponseHashNote != "" {
		fmt.Fprintf(stderr, "Note: %s\n", result.ResponseHashNote)
	}

	// Advisory: a final non-terminal receipt with outcome.status pending is a
	// tool call whose result receipt never arrived (ADR-0019 §O3, retained by
	// ADR-0020). It does NOT break the chain, so it never changes the exit
	// code — surface it as an advisory line regardless of Valid.
	if result.IncompleteToolRoundtrip {
		fmt.Fprintln(stdout, "Advisory: incomplete tool roundtrip: final tool call has no result receipt")
	}
	if result.IncompleteSession {
		fmt.Fprintln(stdout, "Advisory: incomplete session: PTY open/close imbalance")
	}

	if result.Valid {
		noun := "receipts"
		if result.Length == 1 {
			noun = "receipt"
		}
		fmt.Fprintf(stdout, "Chain %s: VALID (%d %s)\n", *chainID, result.Length, noun)
		return ExitOK
	}
	fmt.Fprintf(stdout, "Chain %s: BROKEN at receipt %d\n", *chainID, result.BrokenAt)
	if result.Error != "" {
		// Surface the structured failure cause from VerifyChain — for hash
		// recompute / response_hash / chain-length / terminal-receipt errors
		// it carries detail the per-receipt status lines can't express.
		fmt.Fprintf(stdout, "  cause: %s\n", result.Error)
	}
	for _, rv := range result.Receipts {
		status := "ok"
		switch {
		case !rv.SignatureValid:
			status = "BAD SIGNATURE"
		case !rv.HashLinkValid:
			status = "BAD HASH LINK"
		case !rv.SequenceValid:
			status = "BAD SEQUENCE"
		}
		fmt.Fprintf(stdout, "  [%d] %s — %s\n", rv.Index, rv.ReceiptID, status)
	}
	return ExitChainBad
}

// validatePublicKeyPEM rejects PEM bytes that don't decode to an Ed25519 SPKI
// public key. Catching key-format errors here lets the CLI surface them as
// ExitUsageError instead of routing them through VerifyStoredChain, where a
// malformed key would surface as a "BROKEN" chain — falsely implicating the
// receipts.
func validatePublicKeyPEM(pubPEM []byte) error {
	_, err := ed25519PublicFromPEM(pubPEM)
	return err
}

// ed25519PublicFromPEM decodes PEM/SPKI bytes into an Ed25519 public key,
// rejecting any other key type or malformed input. It is the single parse behind
// both validatePublicKeyPEM and publicKeyFingerprint so the two cannot diverge.
func ed25519PublicFromPEM(pubPEM []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, errors.New("PEM decode failed (no PUBLIC KEY block)")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("PEM block type is %q, want PUBLIC KEY", block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SPKI public key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want ed25519.PublicKey", parsed)
	}
	return pub, nil
}

// publicKeyFingerprint returns the ADR-0015 fingerprint of a PEM/SPKI Ed25519
// public key: SHA-256 of the raw 32-byte key, as sha256:<lowercase hex>. This
// matches the construction the rotation writer and the SDK use, so it compares
// directly against a key_rotated receipt's new_key_fingerprint.
func publicKeyFingerprint(pubPEM []byte) (string, error) {
	pub, err := ed25519PublicFromPEM(pubPEM)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// currentChainKeyFingerprint returns the new_key_fingerprint of the chain's most
// recent key_rotated receipt — the key the rotation lineage hands signing duty to
// — and whether the chain rotated at all. Reading the field directly is sound only
// for a chain VerifyChain has reported Valid: that traversal checks each
// new_key_fingerprint equals the SHA-256 of its inline new_public_key (spec §7.3.7).
func currentChainKeyFingerprint(receipts []receipt.AgentReceipt) (fingerprint string, rotated bool) {
	for i := range receipts {
		if kr := receipts[i].CredentialSubject.KeyRotation; kr != nil {
			fingerprint, rotated = kr.NewKeyFingerprint, true
		}
	}
	return fingerprint, rotated
}

// candidate pairs a public-key file path with its PEM bytes so genesis-key
// resolution can report which file it settled on.
type candidate struct {
	path string
	pem  string
}

// resolveGenesisKey selects the public key that signed the chain's first
// receipt — the key VerifyChain must start from to traverse key rotations
// (spec §7.3.7). The published key (provided) is tried first, then every
// archived pre-rotation key written beside it by `obsigna-daemon --rotate` as
// `<public-key>.rotated-*`. The first candidate whose key verifies receipt[0]'s
// signature is the genesis key.
//
// When the chain is empty, or no candidate verifies receipt[0] (a genuinely
// broken chain, or one rotated with archives the verifier can't see), the
// published key is returned unchanged so the failure is reported against the
// operator's expected key rather than an archive. A stray or malformed
// `.rotated-*` sibling is skipped with a note, not treated as fatal.
func resolveGenesisKey(receipts []receipt.AgentReceipt, provided candidate, stderr io.Writer) (pem, path string) {
	if len(receipts) == 0 {
		return provided.pem, provided.path
	}

	// Discover archived pre-rotation keys by listing the directory and matching a
	// literal filename prefix, not by globbing provided.path — a key path
	// containing glob metacharacters ([ ] ? \) would make filepath.Glob match the
	// wrong files or none, silently losing the genesis key.
	candidates := []candidate{provided}
	dir := filepath.Dir(provided.path)
	prefix := filepath.Base(provided.path) + daemon.RotatedPublicKeySuffix
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(stderr, "Note: cannot list %s for archived keys: %v\n", dir, err)
		entries = nil
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		archivePath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(archivePath)
		if err == nil {
			err = validatePublicKeyPEM(data)
		}
		if err != nil {
			fmt.Fprintf(stderr, "Note: skipping archived key %s: %v\n", archivePath, err)
			continue
		}
		candidates = append(candidates, candidate{path: archivePath, pem: string(data)})
	}

	for _, c := range candidates {
		if ok, err := receipt.Verify(receipts[0], c.pem); ok && err == nil {
			return c.pem, c.path
		}
	}
	return provided.pem, provided.path
}
