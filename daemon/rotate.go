package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/anchor"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// socketReachable best-effort probes whether a daemon is already listening on
// path. An empty path or any dial error reports not-reachable — the check
// guards against the obvious footgun (rotating under a live daemon) without
// blocking rotation when the socket location is unknown.
func socketReachable(path string) bool {
	if path == "" {
		return false
	}
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// actionTypeKeyRotate is the action.type stamped on a key_rotated receipt so
// downstream filters can locate rotation events without parsing keyRotation
// (ADR-0015 amendment). The presence of credentialSubject.keyRotation is
// authoritative; action.type is the index hint.
const actionTypeKeyRotate = "agent.key.rotate"

// RotatedPublicKeySuffix is the filename suffix archiveOldPublicKey appends to a
// superseded public key (followed by a short key fingerprint), e.g.
// signing.key.pub.rotated-<fp>. The verify CLI scans for it to rediscover a
// rotated chain's genesis key, so the writer here and that reader share this one
// definition rather than hardcoding the literal on each side.
const RotatedPublicKeySuffix = ".rotated-"

// RotateSummary reports the outcome of a key rotation for the CLI to print.
type RotateSummary struct {
	ChainID           string
	Sequence          int
	ReceiptID         string
	OldFingerprint    string
	NewFingerprint    string
	ArchivedPublicKey string
	AnchoredTo        string
}

// RotateKey rotates the daemon's signing key (ADR-0015 Phase A, offline).
//
// It loads the current ("outgoing") key, generates a new ("incoming") key,
// appends a key_rotated receipt — signed with the outgoing key — to the head of
// cfg.ChainID, archives the outgoing public key so historical receipts stay
// verifiable, and swaps the incoming key into place. After this returns the
// daemon must be (re)started to pick up the new key; the rotated chain verifies
// end-to-end only when the verifier starts from the *genesis* public key and
// traverses the rotation (spec §7.3.7), not from the freshly published key.
//
// The daemon MUST be stopped first: a running daemon holds the outgoing key in
// memory and would keep signing with it while the chain records a handover to
// the incoming key. RotateKey refuses to run when its socket is reachable.
//
// Ordering is chosen so a committed rotation receipt always matches the on-disk
// key: the rotation receipt is signed in memory with the outgoing key, the key
// files are swapped (with rollback on failure), and only then is the receipt
// inserted (rolling the key files back if the insert fails). The residual
// window — a crash between the key swap and the insert — is the gap the
// external anchor (--anchor-log, written before any local change) closes.
func RotateKey(cfg Config) (RotateSummary, error) {
	if cfg.KeyPath == "" {
		return RotateSummary{}, errors.New("KeyPath is required")
	}
	if cfg.PublicKeyPath == "" {
		cfg.PublicKeyPath = DefaultPublicKeyPath(cfg.KeyPath)
	}
	if cfg.DBPath == "" {
		return RotateSummary{}, errors.New("DBPath is required")
	}
	if cfg.ChainID == "" {
		return RotateSummary{}, errors.New("ChainID is required")
	}
	if cfg.IssuerID == "" {
		return RotateSummary{}, errors.New("IssuerID is required")
	}
	if cfg.VerificationMethodID == "" {
		return RotateSummary{}, errors.New("VerificationMethodID is required")
	}
	if socketReachable(cfg.SocketPath) {
		return RotateSummary{}, fmt.Errorf(
			"a daemon appears to be running on %s — stop it before rotating the signing key", cfg.SocketPath)
	}

	// 1. Load the outgoing key. Read the PEM for signing and derive its raw
	//    public bytes for the fingerprint.
	oldPrivPEM, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return RotateSummary{}, fmt.Errorf("read signing key %s: %w", cfg.KeyPath, err)
	}
	oldPubRaw, err := ed25519RawPublicFromPrivatePEM(oldPrivPEM)
	if err != nil {
		return RotateSummary{}, fmt.Errorf("parse signing key %s: %w", cfg.KeyPath, err)
	}
	oldFingerprint := rawKeyFingerprint(oldPubRaw)

	// 2. Generate the incoming key.
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return RotateSummary{}, fmt.Errorf("generate new key: %w", err)
	}
	newPrivPEM, newPubPEM, err := ed25519KeyPEM(newPriv, newPub)
	if err != nil {
		return RotateSummary{}, err
	}
	newFingerprint := rawKeyFingerprint(newPub)
	newPublicKeyMultibase := "u" + base64.RawURLEncoding.EncodeToString(newPub)

	// 3. Read the chain head to position the rotation receipt.
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return RotateSummary{}, fmt.Errorf("open store %s: %w", cfg.DBPath, err)
	}
	defer func() { _ = st.Close() }()

	tailSeq, tailHash, found, err := st.GetChainTail(cfg.ChainID)
	if err != nil {
		return RotateSummary{}, fmt.Errorf("read chain tail: %w", err)
	}
	seq := 1
	var prevHash *string
	if found {
		seq = int(tailSeq) + 1
		prevHash = &tailHash
	}

	// 4. Build and sign the rotation receipt with the OUTGOING key.
	unsigned := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: cfg.IssuerID},
		Principal: receipt.Principal{ID: cfg.IssuerID},
		Action:    receipt.Action{Type: actionTypeKeyRotate, RiskLevel: receipt.RiskHigh},
		Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
		Chain:     receipt.Chain{Sequence: seq, PreviousReceiptHash: prevHash, ChainID: cfg.ChainID},
	})
	unsigned.CredentialSubject.KeyRotation = &receipt.KeyRotation{
		EventType:         "key_rotated",
		NewPublicKey:      newPublicKeyMultibase,
		OldKeyFingerprint: oldFingerprint,
		NewKeyFingerprint: newFingerprint,
		OldAlgorithm:      "ed25519",
		NewAlgorithm:      "ed25519",
		SignedWith:        "old",
	}
	signed, err := receipt.Sign(unsigned, string(oldPrivPEM), cfg.VerificationMethodID)
	if err != nil {
		return RotateSummary{}, fmt.Errorf("sign rotation receipt with outgoing key: %w", err)
	}
	receiptHash, err := receipt.HashReceipt(signed)
	if err != nil {
		return RotateSummary{}, fmt.Errorf("hash rotation receipt: %w", err)
	}

	// 5. Anchor-first (ADR-0015): write the rotation event to the external
	//    witness BEFORE any local change. A sink-write failure aborts the
	//    rotation cleanly — nothing on disk or in the chain has moved yet, so
	//    there is no torn state where the local chain reflects an unanchored
	//    handover.
	if err := anchorRotationEvent(cfg.AnchorLogPath, signed); err != nil {
		return RotateSummary{}, err
	}

	// 6. Archive the outgoing public key so the genesis key stays resolvable.
	archivePath, err := archiveOldPublicKey(cfg.PublicKeyPath, oldFingerprint)
	if err != nil {
		return RotateSummary{}, fmt.Errorf("archive outgoing public key: %w", err)
	}

	// 7. Swap the incoming key into place, then commit the receipt. Roll the
	//    key files back if the insert fails so disk and chain never disagree.
	restore, err := swapKeyFiles(cfg.KeyPath, cfg.PublicKeyPath, newPrivPEM, newPubPEM)
	if err != nil {
		_ = os.Remove(archivePath)
		return RotateSummary{}, fmt.Errorf("swap key files: %w", err)
	}
	if err := st.Insert(signed, receiptHash); err != nil {
		if rerr := restore(); rerr != nil {
			return RotateSummary{}, fmt.Errorf(
				"insert rotation receipt failed (%w) AND key-file rollback failed (%v) — "+
					"on-disk keys may be the new pair while the chain has no rotation receipt; "+
					"restore %s and %s from %s before restarting the daemon",
				err, rerr, cfg.KeyPath, cfg.PublicKeyPath, archivePath)
		}
		_ = os.Remove(archivePath)
		return RotateSummary{}, fmt.Errorf("insert rotation receipt: %w", err)
	}

	return RotateSummary{
		ChainID:           cfg.ChainID,
		Sequence:          seq,
		ReceiptID:         signed.ID,
		OldFingerprint:    oldFingerprint,
		NewFingerprint:    newFingerprint,
		ArchivedPublicKey: archivePath,
		AnchoredTo:        cfg.AnchorLogPath,
	}, nil
}

// anchorRotationEvent writes the signed rotation receipt to the configured
// external witness in its RFC 8785 canonical form (ADR-0015). A no-op when no
// anchor is configured — the operator has opted out of the post-compromise
// integrity guarantee but keeps every other property.
func anchorRotationEvent(anchorLogPath string, signed receipt.AgentReceipt) error {
	if anchorLogPath == "" {
		return nil
	}
	canonical, err := receipt.Canonicalize(signed)
	if err != nil {
		return fmt.Errorf("canonicalize rotation event for anchor: %w", err)
	}
	sink, err := anchor.OpenFileLog(anchorLogPath)
	if err != nil {
		return fmt.Errorf("open anchor: %w", err)
	}
	if err := sink.Write(anchor.EventTypeRotation, []byte(canonical)); err != nil {
		_ = sink.Close()
		return fmt.Errorf("anchor rotation event (aborting, nothing committed): %w", err)
	}
	if err := sink.Close(); err != nil {
		return fmt.Errorf("close anchor: %w", err)
	}
	return nil
}

// rawKeyFingerprint is the ADR-0015 fingerprint: SHA-256 of the raw public key
// bytes, as sha256:<lowercase hex>.
func rawKeyFingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ed25519RawPublicFromPrivatePEM(privPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, errors.New("PEM decode failed")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want ed25519.PrivateKey", parsed)
	}
	return priv.Public().(ed25519.PublicKey), nil
}

func ed25519KeyPEM(priv ed25519.PrivateKey, pub ed25519.PublicKey) (privPEM, pubPEM []byte, err error) {
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privPEM, pubPEM, nil
}

// archiveOldPublicKey copies the outgoing public key to a fingerprint-suffixed
// sibling path so a verifier can still resolve it after the live .pub is
// replaced. Refuses to overwrite an existing archive (O_EXCL).
func archiveOldPublicKey(publicKeyPath, fingerprint string) (string, error) {
	data, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", publicKeyPath, err)
	}
	// fingerprint is "sha256:<hex>"; take a short, filesystem-safe suffix.
	short := fingerprint
	if len(fingerprint) > 16 {
		short = fingerprint[len(fingerprint)-16:]
	}
	archivePath := publicKeyPath + RotatedPublicKeySuffix + short
	if err := writeNewSecretFile(archivePath, data, 0o644); err != nil {
		return "", fmt.Errorf("write archive %s: %w", archivePath, err)
	}
	return archivePath, nil
}

// swapKeyFiles atomically replaces the private and public key files with the
// new pair, returning a restore closure that puts the originals back. The
// originals are kept in sibling backup files for the duration; restore() and a
// successful return both clean them up.
func swapKeyFiles(keyPath, publicKeyPath string, newPriv, newPub []byte) (restore func() error, err error) {
	privBackup := keyPath + ".bak"
	pubBackup := publicKeyPath + ".bak"

	origPriv, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", keyPath, err)
	}
	origPub, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", publicKeyPath, err)
	}
	if err := writeNewSecretFile(privBackup, origPriv, 0o600); err != nil {
		return nil, fmt.Errorf("back up private key: %w", err)
	}
	if err := writeNewSecretFile(pubBackup, origPub, 0o644); err != nil {
		_ = os.Remove(privBackup)
		return nil, fmt.Errorf("back up public key: %w", err)
	}

	restore = func() error {
		if err := replaceFile(keyPath, origPriv, 0o600); err != nil {
			return err
		}
		if err := replaceFile(publicKeyPath, origPub, 0o644); err != nil {
			return err
		}
		_ = os.Remove(privBackup)
		_ = os.Remove(pubBackup)
		return nil
	}

	if err := replaceFile(keyPath, newPriv, 0o600); err != nil {
		_ = os.Remove(privBackup)
		_ = os.Remove(pubBackup)
		return nil, fmt.Errorf("write new private key: %w", err)
	}
	if err := replaceFile(publicKeyPath, newPub, 0o644); err != nil {
		// Roll the private key back before surfacing the error.
		_ = replaceFile(keyPath, origPriv, 0o600)
		_ = os.Remove(privBackup)
		_ = os.Remove(pubBackup)
		return nil, fmt.Errorf("write new public key: %w", err)
	}

	// Success: drop the backups.
	_ = os.Remove(privBackup)
	_ = os.Remove(pubBackup)
	return restore, nil
}

// replaceFile atomically overwrites path with data at the given mode via a
// temp file and rename within the same directory.
func replaceFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".key-swap-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
