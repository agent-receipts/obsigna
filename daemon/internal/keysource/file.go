package keysource

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// MaxKeyFileBytes is the upper bound on the PEM file size File.Init will
// read. Generous: a PKCS#8-wrapped Ed25519 private key is ~120 bytes and the
// PEM envelope adds <100 bytes; 16 KiB tolerates wrapped or commented keys
// while still capping memory pressure on a misconfigured path.
const MaxKeyFileBytes int64 = 16 * 1024

// File is a KeySource backed by a PEM-encoded Ed25519 private key on disk.
// Phase 1 uses this exclusively. Future ADR-0015 adapters (PKCS#11, cloud KMS)
// implement KeySource alongside this type.
type File struct {
	// Path is the PEM private-key path (PKCS#8). Required.
	Path string

	// VerificationMethodID is the DID URL embedded in proof.verificationMethod.
	// Required: receipts with an empty verification method aren't independently
	// verifiable.
	VerificationMethodID string

	// RequireOwnerOnly, when true, refuses to load a key whose file mode allows
	// group or world access. Defaults to true; tests can disable for tmpfile
	// fixtures whose perms are platform-controlled.
	RequireOwnerOnly bool

	priv   ed25519.PrivateKey
	pubPEM string
}

// NewFile returns an unloaded File. Call Init to read the key from disk.
func NewFile(path, verificationMethodID string) *File {
	return &File{Path: path, VerificationMethodID: verificationMethodID, RequireOwnerOnly: true}
}

// Init reads the PEM private key from f.Path and caches it.
func (f *File) Init() error {
	if f.Path == "" {
		return errors.New("keysource/file: Path is required")
	}
	if f.VerificationMethodID == "" {
		return errors.New("keysource/file: VerificationMethodID is required")
	}

	// Open with O_NOFOLLOW so a symlink AT the key path is rejected outright
	// (returns ELOOP), then fstat THE OPEN FD so the validation and the read
	// operate on the same inode. Doing Lstat → ReadFile across two separate
	// path resolutions would leave a TOCTOU window where an attacker with
	// write access to the parent directory could swap the file between the
	// check and the read, tricking the daemon into loading attacker-supplied
	// key material despite the earlier checks.
	//
	// Operators with legitimate reasons to indirect via a symlink should
	// resolve it before pointing AGENTRECEIPTS_KEY at the result, or wait for
	// the ADR-0015 KMS adapters that don't read the key from disk at all.
	fh, err := os.OpenFile(f.Path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return fmt.Errorf("open key file: %w", err)
	}
	defer fh.Close()

	info, err := fh.Stat()
	if err != nil {
		return fmt.Errorf("fstat key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf(
			"keysource/file: refusing to load %s — not a regular file (mode %s); avoid FIFO/device/directory paths",
			f.Path, info.Mode(),
		)
	}
	if f.RequireOwnerOnly && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(
			"keysource/file: refusing to load %s with permissions %o (any group/world bits set); chmod 0600",
			f.Path, info.Mode().Perm(),
		)
	}
	// PEM-encoded Ed25519 private keys are well under 1 KiB. Cap the read at
	// MaxKeyFileBytes so a misconfigured AGENTRECEIPTS_KEY pointing at a huge
	// file doesn't waste memory at startup. Refuse outright rather than
	// silently truncating — a truncated key would parse as garbage anyway.
	if info.Size() > MaxKeyFileBytes {
		return fmt.Errorf(
			"keysource/file: refusing to load %s — size %d exceeds MaxKeyFileBytes %d (PEM-encoded Ed25519 keys are ~< 1 KiB)",
			f.Path, info.Size(), MaxKeyFileBytes,
		)
	}

	raw, err := io.ReadAll(io.LimitReader(fh, MaxKeyFileBytes))
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return errors.New("keysource/file: PEM decode failed")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("keysource/file: key is %T, want ed25519.PrivateKey", parsed)
	}

	pub := priv.Public().(ed25519.PublicKey)
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	f.priv = priv
	f.pubPEM = string(pubPEM)
	return nil
}

// Sign returns the raw 64-byte Ed25519 signature over message.
func (f *File) Sign(message []byte) ([]byte, error) {
	if f.priv == nil {
		return nil, errors.New("keysource/file: Init not called")
	}
	return ed25519.Sign(f.priv, message), nil
}

// PublicKey returns the PEM-encoded SPKI public key.
func (f *File) PublicKey() (string, error) {
	if f.pubPEM == "" {
		return "", errors.New("keysource/file: Init not called")
	}
	return f.pubPEM, nil
}

// VerificationMethod returns the configured verification-method ID.
func (f *File) VerificationMethod() string { return f.VerificationMethodID }

// Teardown wipes the in-memory key.
func (f *File) Teardown() error {
	if f.priv != nil {
		for i := range f.priv {
			f.priv[i] = 0
		}
		f.priv = nil
	}
	f.pubPEM = ""
	return nil
}
