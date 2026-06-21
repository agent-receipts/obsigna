package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"obsigna.dev/sdk/go/receipt"
)

// TestGenerateForensicKey_HappyPath proves the post-condition the
// --init-forensic-key flow relies on: after a clean run the operator has a
// 0o600 private key and a 0o644 public key, both raw 32-byte X25519 keys, the
// returned fingerprint matches the public key, and the pair round-trips through
// encrypt/decrypt.
func TestGenerateForensicKey_HappyPath(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "forensic.key")
	pubPath := filepath.Join(dir, "forensic.key.pub")

	fingerprint, err := GenerateForensicKey(keyPath, pubPath)
	if err != nil {
		t.Fatalf("GenerateForensicKey: %v", err)
	}

	priv, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("private key missing: %v", err)
	}
	if len(priv) != 32 {
		t.Errorf("private key = %d bytes, want 32 (raw X25519)", len(priv))
	}
	privInfo, _ := os.Stat(keyPath)
	if got := privInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("private key perm = %o, want 0600", got)
	}

	pub, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("public key missing: %v", err)
	}
	if len(pub) != 32 {
		t.Errorf("public key = %d bytes, want 32 (raw X25519)", len(pub))
	}
	pubInfo, _ := os.Stat(pubPath)
	if got := pubInfo.Mode().Perm(); got != 0o644 {
		t.Errorf("public key perm = %o, want 0644", got)
	}

	// The returned fingerprint must match the on-disk public key (ADR-0015).
	wantFP, err := receipt.ForensicKeyFingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != wantFP {
		t.Errorf("fingerprint = %q, want %q", fingerprint, wantFP)
	}

	// The pair must round-trip: encrypt to the public key, decrypt with private.
	env, err := receipt.EncryptDisclosure(map[string]any{"k": "v"}, pub, wantFP)
	if err != nil {
		t.Fatalf("EncryptDisclosure: %v", err)
	}
	dec, err := receipt.DecryptDisclosure(env, priv)
	if err != nil {
		t.Fatalf("DecryptDisclosure: %v", err)
	}
	if dec["k"] != "v" {
		t.Errorf("round-trip: got %v, want v", dec["k"])
	}
}

func TestGenerateForensicKey_DerivesPublicPathWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "forensic.key")

	if _, err := GenerateForensicKey(keyPath, ""); err != nil {
		t.Fatalf("GenerateForensicKey: %v", err)
	}
	if _, err := os.Stat(keyPath + ".pub"); err != nil {
		t.Errorf("expected derived public key at %s.pub: %v", keyPath, err)
	}
}

func TestGenerateForensicKey_RejectsEmptyKeyPath(t *testing.T) {
	if _, err := GenerateForensicKey("", "x.pub"); err == nil {
		t.Fatal("expected error for empty keyPath")
	}
}

func TestGenerateForensicKey_RefusesIdenticalPaths(t *testing.T) {
	p := filepath.Join(t.TempDir(), "forensic.key")
	if _, err := GenerateForensicKey(p, p); err == nil {
		t.Fatal("expected error when keyPath == publicKeyPath")
	}
}

func TestGenerateForensicKey_RefusesExistingPrivateKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "forensic.key")
	if err := os.WriteFile(keyPath, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateForensicKey(keyPath, keyPath+".pub"); err == nil {
		t.Fatal("expected error: must not overwrite an existing private key")
	}
}
