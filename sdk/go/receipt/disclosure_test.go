package receipt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// RFC 7748 §6.1 Alice public key (32 bytes, hex).
// Used as forensic-test-recipient-1 in spec/test-vectors/disclosure-envelope/vectors.json.
const alicePubHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"

// RFC 7748 §6.1 Alice private key (32 bytes, hex).
// These are published test vectors from an IETF RFC — not real secrets.
// The RFC's hex grouping can be misread; this scalar is verified by
// crypto/ecdh.X25519().NewPrivateKey(scalar).PublicKey().Bytes() == alicePubHex.
const alicePrivHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a" //nolint:gosec

// RFC 7748 §6.1 Bob public key (32 bytes, hex).
// Used as forensic-test-recipient-2 in spec/test-vectors/disclosure-envelope/vectors.json.
const bobPubHex = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"

// RFC 7748 §6.1 Bob private key (32 bytes, hex). Published IETF test vector, not a real secret.
const bobPrivHex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb" //nolint:gosec

// vector1IkmEHex is the ikmE for test vector 1 from RFC 9180 §A.1.1.
const vector1IkmEHex = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"

// vector2IkmEHex is the ikmE for test vector 2 (SHA-256 of a fixed repo-local string).
const vector2IkmEHex = "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b"

func mustDecodeHex(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("hex decode %q: %v", h, err)
	}
	return b
}

// TestGenerateForensicKeyPair verifies that key generation produces valid 32-byte keys
// and that a freshly generated pair can encrypt and decrypt a round-trip.
func TestGenerateForensicKeyPair(t *testing.T) {
	kp, err := GenerateForensicKeyPair()
	if err != nil {
		t.Fatalf("GenerateForensicKeyPair: %v", err)
	}
	if len(kp.PublicKey) != 32 {
		t.Errorf("public key: want 32 bytes, got %d", len(kp.PublicKey))
	}
	if len(kp.PrivateKey) != 32 {
		t.Errorf("private key: want 32 bytes, got %d", len(kp.PrivateKey))
	}
	if string(kp.PublicKey) == string(kp.PrivateKey) {
		t.Error("public and private keys must differ")
	}

	// Verify the pair works for encrypt/decrypt.
	params := map[string]any{"tool": "read_file", "path": "/tmp/test.txt"}
	env, err := EncryptDisclosure(params, kp.PublicKey, "sha256:test")
	if err != nil {
		t.Fatalf("EncryptDisclosure: %v", err)
	}
	got, err := DecryptDisclosure(env, kp.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptDisclosure: %v", err)
	}
	if got["tool"] != "read_file" {
		t.Errorf("decrypted tool = %v, want read_file", got["tool"])
	}
	if got["path"] != "/tmp/test.txt" {
		t.Errorf("decrypted path = %v, want /tmp/test.txt", got["path"])
	}
}

// TestEncryptDecryptRoundTrip exercises the full encrypt/decrypt path with
// well-known RFC 7748 keys (Alice as recipient).
func TestEncryptDecryptRoundTrip(t *testing.T) {
	alicePub := mustDecodeHex(t, alicePubHex)
	alicePriv := mustDecodeHex(t, alicePrivHex)

	params := map[string]any{
		"command": "echo \"build complete\"",
	}
	env, err := EncryptDisclosure(params, alicePub, "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQUQUaHL9XJ7Z5W#enc-1")
	if err != nil {
		t.Fatalf("EncryptDisclosure: %v", err)
	}

	// Envelope shape invariants (ADR-0012 amendment, shape_invariants.rules).
	if env.V != "1" {
		t.Errorf("v = %q, want \"1\"", env.V)
	}
	if env.Alg != v1Alg {
		t.Errorf("alg = %q, want %q", env.Alg, v1Alg)
	}
	if len(env.Recipients) != 1 {
		t.Errorf("recipients len = %d, want 1", len(env.Recipients))
	}
	if len(env.Recipients[0].Enc) != 43 {
		t.Errorf("enc len = %d, want 43 (unpadded base64url of 32 bytes)", len(env.Recipients[0].Enc))
	}
	if len(env.CT) < 24 {
		t.Errorf("ct len = %d, want >= 24 (min for {} + 16-byte GCM tag)", len(env.CT))
	}
	if strings.ContainsAny(env.Recipients[0].Enc, "+/=") {
		t.Error("enc must use unpadded base64url (no +, /, or =)")
	}
	if strings.ContainsAny(env.CT, "+/=") {
		t.Error("ct must use unpadded base64url (no +, /, or =)")
	}

	// No nonce field (v1 is single-shot; nonce is internal to HPKE).
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if strings.Contains(string(b), `"nonce"`) {
		t.Error("v1 envelope must not contain a nonce field")
	}

	// Round-trip decrypt.
	got, err := DecryptDisclosure(env, alicePriv)
	if err != nil {
		t.Fatalf("DecryptDisclosure: %v", err)
	}
	if got["command"] != `echo "build complete"` {
		t.Errorf("decrypted command = %v, want 'echo \"build complete\"'", got["command"])
	}
}

// TestDisclosurePlaintextIsJCS verifies that the plaintext encrypted by
// EncryptDisclosure is the RFC 8785 JCS of the params object, not raw JSON.
// This is load-bearing for cross-SDK interop: two SDKs that disagree about JCS
// produce different ciphertexts and different parameters_hash values.
func TestDisclosurePlaintextIsJCS(t *testing.T) {
	alicePub := mustDecodeHex(t, alicePubHex)
	alicePriv := mustDecodeHex(t, alicePrivHex)

	// Non-trivially-ordered keys so JCS sort is observable.
	params := map[string]any{
		"z_last":  "last",
		"a_first": "first",
		"m_mid":   "middle",
	}

	env, err := EncryptDisclosure(params, alicePub, "test-kid")
	if err != nil {
		t.Fatalf("EncryptDisclosure: %v", err)
	}

	got, err := DecryptDisclosure(env, alicePriv)
	if err != nil {
		t.Fatalf("DecryptDisclosure: %v", err)
	}

	// Re-canonicalize decrypted result and compare with direct canonicalization
	// of the input params.
	wantCanon, err := Canonicalize(params)
	if err != nil {
		t.Fatalf("Canonicalize params: %v", err)
	}
	gotCanon, err := Canonicalize(got)
	if err != nil {
		t.Fatalf("Canonicalize decrypted: %v", err)
	}
	if wantCanon != gotCanon {
		t.Errorf("canonical mismatch:\n  want: %s\n   got: %s", wantCanon, gotCanon)
	}
}

// TestEnvelopeJCSShape verifies that the DisclosureEnvelope marshals and
// JCS-canonicalizes with keys in the order [alg, ct, recipients, v] at the top
// level and [enc, kid] inside each recipients entry. This canonical order is
// pinned by spec/test-vectors/disclosure-envelope/vectors.json shape_invariants.
func TestEnvelopeJCSShape(t *testing.T) {
	env := &DisclosureEnvelope{
		V:   "1",
		Alg: v1Alg,
		Recipients: []DisclosureRecipient{{
			KID: "did:key:z6LStest#enc-1",
			Enc: strings.Repeat("A", 43),
		}},
		CT: strings.Repeat("B", 24),
	}

	canon, err := Canonicalize(env)
	if err != nil {
		t.Fatalf("Canonicalize envelope: %v", err)
	}

	// Top-level key order must be: alg, ct, recipients, v.
	algIdx := strings.Index(canon, `"alg"`)
	ctIdx := strings.Index(canon, `"ct"`)
	recIdx := strings.Index(canon, `"recipients"`)
	vIdx := strings.Index(canon, `"v"`)
	if !(algIdx < ctIdx && ctIdx < recIdx && recIdx < vIdx) {
		t.Errorf("top-level key order wrong in canonical JSON: %s", canon)
	}

	// Recipient keys must be: enc, kid.
	encIdx := strings.Index(canon, `"enc"`)
	kidIdx := strings.Index(canon, `"kid"`)
	if !(encIdx < kidIdx) {
		t.Errorf("recipient key order wrong in canonical JSON: %s", canon)
	}
}

// TestDecryptValidationErrors covers the reject paths in DecryptDisclosure.
func TestDecryptValidationErrors(t *testing.T) {
	validEnv := &DisclosureEnvelope{
		V:          "1",
		Alg:        v1Alg,
		Recipients: []DisclosureRecipient{{KID: "k", Enc: strings.Repeat("A", 43)}},
		CT:         strings.Repeat("B", 24),
	}

	// nil envelope.
	if _, err := DecryptDisclosure(nil, make([]byte, 32)); err == nil {
		t.Error("expected error for nil envelope, got nil")
	}

	// Encryption-side validation errors.
	alicePub := mustDecodeHex(t, alicePubHex)
	validParams := map[string]any{"k": "v"}

	if _, err := EncryptDisclosure(nil, alicePub, "kid"); err == nil {
		t.Error("expected error for nil params")
	}
	if _, err := EncryptDisclosure(validParams, alicePub, ""); err == nil {
		t.Error("expected error for empty kid")
	}
	if _, err := EncryptDisclosure(validParams, make([]byte, 16), "kid"); err == nil {
		t.Error("expected error for short recipient public key")
	}

	// DecryptDisclosure: wrong private key length.
	if _, err := DecryptDisclosure(&DisclosureEnvelope{V: "1", Alg: v1Alg, Recipients: []DisclosureRecipient{{KID: "k", Enc: strings.Repeat("A", 43)}}, CT: strings.Repeat("B", 24)}, make([]byte, 16)); err == nil {
		t.Error("expected error for short recipient private key")
	}

	tests := []struct {
		name    string
		mutate  func(*DisclosureEnvelope) *DisclosureEnvelope
		wantErr string
	}{
		{
			name: "wrong version",
			mutate: func(e *DisclosureEnvelope) *DisclosureEnvelope {
				c := *e
				c.V = "2"
				return &c
			},
			wantErr: `unsupported envelope version "2"`,
		},
		{
			name: "wrong alg",
			mutate: func(e *DisclosureEnvelope) *DisclosureEnvelope {
				c := *e
				c.Alg = "hpke-x25519-chacha20poly1305"
				return &c
			},
			wantErr: `unsupported algorithm`,
		},
		{
			name: "zero recipients",
			mutate: func(e *DisclosureEnvelope) *DisclosureEnvelope {
				c := *e
				c.Recipients = nil
				return &c
			},
			wantErr: "exactly 1 recipient",
		},
		{
			name: "two recipients",
			mutate: func(e *DisclosureEnvelope) *DisclosureEnvelope {
				c := *e
				c.Recipients = []DisclosureRecipient{{}, {}}
				return &c
			},
			wantErr: "exactly 1 recipient",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := tt.mutate(validEnv)
			_, err := DecryptDisclosure(env, make([]byte, 32))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("want error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

// TestDeterministicVector1 exercises the deterministic encrypt path with the
// RFC 9180 §A.1.1 ikmE and RFC 7748 §6.1 Alice key (forensic-test-recipient-1).
// The resulting enc must match RFC 9180's pkEm. This test pins the concrete
// bytes that are then recorded in spec/test-vectors/disclosure-envelope/vectors.json.
func TestDeterministicVector1(t *testing.T) {
	alicePub := mustDecodeHex(t, alicePubHex)
	alicePriv := mustDecodeHex(t, alicePrivHex)
	ikmE := mustDecodeHex(t, vector1IkmEHex)

	params := map[string]any{
		"command": `echo "build complete"`,
	}
	kid := "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQUQUaHL9XJ7Z5W#enc-1"

	env, err := encryptDisclosureWithSeed(params, alicePub, kid, ikmE)
	if err != nil {
		t.Fatalf("encryptDisclosureWithSeed: %v", err)
	}

	// The enc for this ikmE must match RFC 9180 §A.1.1 pkEm.
	// pkEm = 37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431
	wantEncHex := "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
	wantEncB64 := base64.RawURLEncoding.EncodeToString(mustDecodeHex(t, wantEncHex))

	if env.Recipients[0].Enc != wantEncB64 {
		t.Errorf("enc = %s, want %s (RFC 9180 §A.1.1 pkEm)", env.Recipients[0].Enc, wantEncB64)
	}

	// Plaintext canonical JCS must match the vectors.json expectation.
	wantPlainJCS := `{"command":"echo \"build complete\""}`
	gotJCS, err := Canonicalize(params)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if gotJCS != wantPlainJCS {
		t.Errorf("plaintext JCS = %s, want %s", gotJCS, wantPlainJCS)
	}

	// Round-trip decrypt must recover the same params.
	got, err := DecryptDisclosure(env, alicePriv)
	if err != nil {
		t.Fatalf("DecryptDisclosure: %v", err)
	}
	if got["command"] != `echo "build complete"` {
		t.Errorf("decrypted command = %v", got["command"])
	}

	// Assert pinned ciphertext values (from spec/test-vectors/disclosure-envelope/vectors.json).
	// These are locked in once computed; any change means the ciphersuite or plaintext
	// serialisation diverged from the spec.
	const wantCT1 = "YGn3i4NpiZxHjeZVggTP8lTxb0ZVdLl-2HjW31qsvo28PjQ_Lt_UQgAMidEXjzwhJPHM7OM"
	if env.CT != wantCT1 {
		t.Errorf("ct = %s\nwant %s", env.CT, wantCT1)
	}

	// Assert pinned envelope JCS shape.
	const wantJCS1 = `{"alg":"hpke-x25519-hkdf-sha256-aes-256-gcm","ct":"YGn3i4NpiZxHjeZVggTP8lTxb0ZVdLl-2HjW31qsvo28PjQ_Lt_UQgAMidEXjzwhJPHM7OM","recipients":[{"enc":"N_2jVnvb1ijohmjDyNfpfR0SU7bU6m1EwVD3QfG_RDE","kid":"did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQUQUaHL9XJ7Z5W#enc-1"}],"v":"1"}`
	envelopeJCS, err := Canonicalize(env)
	if err != nil {
		t.Fatalf("Canonicalize envelope: %v", err)
	}
	if envelopeJCS != wantJCS1 {
		t.Errorf("envelope JCS =\n%s\nwant\n%s", envelopeJCS, wantJCS1)
	}
}

// TestDeterministicVector2 exercises the deterministic encrypt path with the
// repo-local ikmE seed and RFC 7748 §6.1 Bob key (forensic-test-recipient-2).
func TestDeterministicVector2(t *testing.T) {
	bobPub := mustDecodeHex(t, bobPubHex)
	bobPriv := mustDecodeHex(t, bobPrivHex)
	ikmE := mustDecodeHex(t, vector2IkmEHex)

	params := map[string]any{
		"method": "POST",
		"headers": map[string]any{
			"content-type": "application/json",
			"x-request-id": "abc-123",
		},
		"body": map[string]any{
			"user":  "otto",
			"delta": float64(42),
		},
	}
	kid := "sha256:8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"

	env, err := encryptDisclosureWithSeed(params, bobPub, kid, ikmE)
	if err != nil {
		t.Fatalf("encryptDisclosureWithSeed: %v", err)
	}

	// Plaintext must be the JCS of the nested params object.
	wantPlainJCS := `{"body":{"delta":42,"user":"otto"},"headers":{"content-type":"application/json","x-request-id":"abc-123"},"method":"POST"}`
	gotJCS, err := Canonicalize(params)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if gotJCS != wantPlainJCS {
		t.Errorf("plaintext JCS = %s, want %s", gotJCS, wantPlainJCS)
	}

	// Round-trip.
	got, err := DecryptDisclosure(env, bobPriv)
	if err != nil {
		t.Fatalf("DecryptDisclosure: %v", err)
	}
	if got["method"] != "POST" {
		t.Errorf("decrypted method = %v, want POST", got["method"])
	}

	// Assert pinned ciphertext values (from spec/test-vectors/disclosure-envelope/vectors.json).
	const wantEnc2 = "GvoI097AR6ZDiFFj8RgEdvp921TGqAKeoz-VeWvyrEo"
	if env.Recipients[0].Enc != wantEnc2 {
		t.Errorf("enc = %s\nwant %s", env.Recipients[0].Enc, wantEnc2)
	}
	const wantCT2 = "vJG1bfcwNTnyL7gqfzkIg8oDl08Rd0z2kp-HVcRypJDrYdPBwvHWbIwdhCXuYB4mKANMmKejzrsDHvaOnFAAHxVzB-f57sljHW5aDsb4kp5mhtM2SIAQwUj6VlVonllEdQquRKOl3hjbXEOwjQeXQUxvI7avsiWuk5z41na_Xx6vVJd96lb-59YV"
	if env.CT != wantCT2 {
		t.Errorf("ct = %s\nwant %s", env.CT, wantCT2)
	}

	// Assert pinned envelope JCS shape.
	const wantJCS2 = `{"alg":"hpke-x25519-hkdf-sha256-aes-256-gcm","ct":"vJG1bfcwNTnyL7gqfzkIg8oDl08Rd0z2kp-HVcRypJDrYdPBwvHWbIwdhCXuYB4mKANMmKejzrsDHvaOnFAAHxVzB-f57sljHW5aDsb4kp5mhtM2SIAQwUj6VlVonllEdQquRKOl3hjbXEOwjQeXQUxvI7avsiWuk5z41na_Xx6vVJd96lb-59YV","recipients":[{"enc":"GvoI097AR6ZDiFFj8RgEdvp921TGqAKeoz-VeWvyrEo","kid":"sha256:8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"}],"v":"1"}`
	envelopeJCS, err := Canonicalize(env)
	if err != nil {
		t.Fatalf("Canonicalize envelope: %v", err)
	}
	if envelopeJCS != wantJCS2 {
		t.Errorf("envelope JCS =\n%s\nwant\n%s", envelopeJCS, wantJCS2)
	}
}

// TestEnvelopeJSONRoundTrip verifies that a DisclosureEnvelope marshals and
// unmarshals cleanly and that the decoded value is structurally identical.
func TestEnvelopeJSONRoundTrip(t *testing.T) {
	alicePub := mustDecodeHex(t, alicePubHex)
	alicePriv := mustDecodeHex(t, alicePrivHex)

	env, err := EncryptDisclosure(
		map[string]any{"key": "value"},
		alicePub,
		"did:key:test#enc-1",
	)
	if err != nil {
		t.Fatalf("EncryptDisclosure: %v", err)
	}

	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	var decoded DisclosureEnvelope
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}

	// Decode and re-decrypt after JSON round-trip.
	got, err := DecryptDisclosure(&decoded, alicePriv)
	if err != nil {
		t.Fatalf("DecryptDisclosure after JSON round-trip: %v", err)
	}
	if got["key"] != "value" {
		t.Errorf("decrypted key = %v, want value", got["key"])
	}
}

// TestForensicKeyFingerprint verifies the ADR-0015 canonical fingerprint form:
// sha256:<lowercase hex of SHA-256(raw 32-byte X25519 public key)>. The expected
// values are computed independently from the well-known RFC 7748 §6.1 test keys.
func TestForensicKeyFingerprint(t *testing.T) {
	cases := []struct {
		name   string
		pubHex string
		// want = sha256: + hex(sha256(raw pubkey bytes)), computed independently.
		want string
	}{
		{
			name:   "alice",
			pubHex: alicePubHex,
			want:   "sha256:" + hexSHA256(mustDecodeHex(t, alicePubHex)),
		},
		{
			name:   "bob",
			pubHex: bobPubHex,
			want:   "sha256:" + hexSHA256(mustDecodeHex(t, bobPubHex)),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ForensicKeyFingerprint(mustDecodeHex(t, tc.pubHex))
			if err != nil {
				t.Fatalf("ForensicKeyFingerprint: %v", err)
			}
			if got != tc.want {
				t.Errorf("fingerprint = %q, want %q", got, tc.want)
			}
			if !strings.HasPrefix(got, "sha256:") {
				t.Errorf("fingerprint %q must start with sha256:", got)
			}
		})
	}
}

// TestForensicKeyFingerprintRejectsBadLength ensures a non-32-byte key is rejected
// rather than silently producing a fingerprint over the wrong bytes.
func TestForensicKeyFingerprintRejectsBadLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := ForensicKeyFingerprint(make([]byte, n)); err == nil {
			t.Errorf("ForensicKeyFingerprint(%d bytes): want error, got nil", n)
		}
	}
}

// TestForensicPublicFromPrivate verifies that the public key derived from a
// private key matches the known public key for the RFC 7748 test pairs. This is
// the operation a dashboard performs: load the private key, derive the public
// key, compute the fingerprint, and match it against receipts' kid values.
func TestForensicPublicFromPrivate(t *testing.T) {
	cases := []struct {
		name    string
		privHex string
		wantPub string
	}{
		{"alice", alicePrivHex, alicePubHex},
		{"bob", bobPrivHex, bobPubHex},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, err := ForensicPublicFromPrivate(mustDecodeHex(t, tc.privHex))
			if err != nil {
				t.Fatalf("ForensicPublicFromPrivate: %v", err)
			}
			if got := hex.EncodeToString(pub); got != tc.wantPub {
				t.Errorf("derived public = %s, want %s", got, tc.wantPub)
			}
		})
	}
}

// TestFingerprintMatchesAcrossKeyPair is the end-to-end dashboard check: a
// fingerprint computed from a public key equals the fingerprint computed from
// the public key derived from the matching private key.
func TestFingerprintMatchesAcrossKeyPair(t *testing.T) {
	kp, err := GenerateForensicKeyPair()
	if err != nil {
		t.Fatalf("GenerateForensicKeyPair: %v", err)
	}
	fromPub, err := ForensicKeyFingerprint(kp.PublicKey)
	if err != nil {
		t.Fatalf("fingerprint from public: %v", err)
	}
	derivedPub, err := ForensicPublicFromPrivate(kp.PrivateKey)
	if err != nil {
		t.Fatalf("derive public from private: %v", err)
	}
	fromPriv, err := ForensicKeyFingerprint(derivedPub)
	if err != nil {
		t.Fatalf("fingerprint from derived public: %v", err)
	}
	if fromPub != fromPriv {
		t.Errorf("fingerprint mismatch: from public %q != from derived %q", fromPub, fromPriv)
	}
}

// hexSHA256 is a test helper computing the lowercase hex of SHA-256(data).
func hexSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// TestEncryptResponseDecryptResponseRoundTrip verifies the response disclosure
// API (ADR-0012, spec v0.6.0+) round-trips through the public Response functions.
func TestEncryptResponseDecryptResponseRoundTrip(t *testing.T) {
	alicePub := mustDecodeHex(t, alicePubHex)
	alicePriv := mustDecodeHex(t, alicePrivHex)

	response := map[string]any{
		"stdout":    "build complete\n",
		"exit_code": float64(0),
	}
	env, err := EncryptResponse(response, alicePub, "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQUQUaHL9XJ7Z5W#enc-1")
	if err != nil {
		t.Fatalf("EncryptResponse: %v", err)
	}

	// Envelope shape invariants — identical envelope to the parameter surface.
	if env.V != "1" {
		t.Errorf("v = %q, want \"1\"", env.V)
	}
	if env.Alg != v1Alg {
		t.Errorf("alg = %q, want %q", env.Alg, v1Alg)
	}
	if len(env.Recipients) != 1 || len(env.Recipients[0].Enc) != 43 {
		t.Errorf("recipients shape wrong: %+v", env.Recipients)
	}

	got, err := DecryptResponse(env, alicePriv)
	if err != nil {
		t.Fatalf("DecryptResponse: %v", err)
	}
	if got["stdout"] != "build complete\n" || got["exit_code"] != float64(0) {
		t.Errorf("decrypted response = %v", got)
	}
}

// TestResponseEnvelopeMatchesParameterEnvelope is the load-bearing parity check:
// for the same plaintext, key, kid, and seed, the response surface
// (encryptResponseWithSeed) MUST produce a byte-identical envelope to the
// parameter surface (encryptDisclosureWithSeed). This pins the cross-SDK
// byte-identity property for outcome.response_disclosure against the same
// vector-1 values the parameter path is pinned to (vectors.json).
func TestResponseEnvelopeMatchesParameterEnvelope(t *testing.T) {
	alicePub := mustDecodeHex(t, alicePubHex)
	alicePriv := mustDecodeHex(t, alicePrivHex)
	ikmE := mustDecodeHex(t, vector1IkmEHex)
	kid := "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQUQUaHL9XJ7Z5W#enc-1"

	payload := map[string]any{"command": `echo "build complete"`}

	paramEnv, err := encryptDisclosureWithSeed(payload, alicePub, kid, ikmE)
	if err != nil {
		t.Fatalf("encryptDisclosureWithSeed: %v", err)
	}
	respEnv, err := encryptResponseWithSeed(payload, alicePub, kid, ikmE)
	if err != nil {
		t.Fatalf("encryptResponseWithSeed: %v", err)
	}

	paramJCS, err := Canonicalize(paramEnv)
	if err != nil {
		t.Fatalf("Canonicalize paramEnv: %v", err)
	}
	respJCS, err := Canonicalize(respEnv)
	if err != nil {
		t.Fatalf("Canonicalize respEnv: %v", err)
	}
	if paramJCS != respJCS {
		t.Errorf("response envelope diverges from parameter envelope:\nparam: %s\nresp:  %s", paramJCS, respJCS)
	}

	// And it must match the pinned vector-1 ciphertext, so the response surface
	// is locked to the same cross-SDK bytes.
	const wantCT1 = "YGn3i4NpiZxHjeZVggTP8lTxb0ZVdLl-2HjW31qsvo28PjQ_Lt_UQgAMidEXjzwhJPHM7OM"
	if respEnv.CT != wantCT1 {
		t.Errorf("response ct = %s\nwant %s", respEnv.CT, wantCT1)
	}

	got, err := DecryptResponse(respEnv, alicePriv)
	if err != nil {
		t.Fatalf("DecryptResponse: %v", err)
	}
	if got["command"] != `echo "build complete"` {
		t.Errorf("decrypted = %v", got)
	}
}

// TestEncryptResponseValidation verifies EncryptResponse rejects bad inputs the
// same way EncryptDisclosure does, and the seeded variant enforces ikmE length.
func TestEncryptResponseValidation(t *testing.T) {
	alicePub := mustDecodeHex(t, alicePubHex)
	kid := "sha256:abc"

	// Error wording is response-specific, not the delegate's "params" text,
	// matching the TS/Python encryptResponse surface.
	if _, err := EncryptResponse(nil, alicePub, kid); err == nil {
		t.Error("EncryptResponse(nil response) should error")
	} else if !strings.Contains(err.Error(), "response must not be nil") {
		t.Errorf("nil-response error = %q, want response-specific wording", err)
	}
	if _, err := EncryptResponse(map[string]any{}, alicePub[:31], kid); err == nil {
		t.Error("EncryptResponse(short key) should error")
	}
	if _, err := EncryptResponse(map[string]any{}, alicePub, ""); err == nil {
		t.Error("EncryptResponse(empty kid) should error")
	}
	if _, err := encryptResponseWithSeed(map[string]any{}, alicePub, kid, []byte{1, 2, 3}); err == nil {
		t.Error("encryptResponseWithSeed(short ikmE) should error")
	}
}
