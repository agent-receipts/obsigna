package did

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func mustPubKey(t *testing.T, hexStr string) ed25519.PublicKey {
	t.Helper()
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return ed25519.PublicKey(b)
}

// pubKeyHex is RFC 8032 §7.1 TEST 1's public key — the same key vector-1 in
// spec/test-vectors/did-key/vectors.json uses.
const pubKeyHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
const expectedDID = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"

func TestFromPublicKey(t *testing.T) {
	got, err := FromPublicKey(mustPubKey(t, pubKeyHex))
	if err != nil {
		t.Fatalf("FromPublicKey: %v", err)
	}
	if got != expectedDID {
		t.Errorf("FromPublicKey\n  got:  %s\n  want: %s", got, expectedDID)
	}
}

func TestFromPublicKeyRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := FromPublicKey(make([]byte, n)); err == nil {
			t.Errorf("FromPublicKey(%d bytes): expected error, got nil", n)
		}
	}
}

func TestResolveRoundTrip(t *testing.T) {
	doc, err := Resolve(expectedDID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if doc.ID != expectedDID {
		t.Errorf("doc.ID = %q, want %q", doc.ID, expectedDID)
	}
	if len(doc.VerificationMethod) != 1 {
		t.Fatalf("len(VerificationMethod) = %d, want 1", len(doc.VerificationMethod))
	}
	vm := doc.VerificationMethod[0]
	wantFragment := expectedDID[len("did:key:"):]
	wantVMID := expectedDID + "#" + wantFragment
	if vm.ID != wantVMID {
		t.Errorf("vm.ID = %q, want %q", vm.ID, wantVMID)
	}
	if vm.Type != "Multikey" {
		t.Errorf("vm.Type = %q, want Multikey", vm.Type)
	}
	if vm.Controller != expectedDID {
		t.Errorf("vm.Controller = %q, want %q", vm.Controller, expectedDID)
	}
	if vm.PublicKeyMultibase != wantFragment {
		t.Errorf("vm.PublicKeyMultibase = %q, want %q", vm.PublicKeyMultibase, wantFragment)
	}
	if len(doc.Authentication) != 1 || doc.Authentication[0] != wantVMID {
		t.Errorf("Authentication = %v, want [%q]", doc.Authentication, wantVMID)
	}
	if len(doc.AssertionMethod) != 1 || doc.AssertionMethod[0] != wantVMID {
		t.Errorf("AssertionMethod = %v, want [%q]", doc.AssertionMethod, wantVMID)
	}
	if len(doc.Context) != 2 || doc.Context[0] != "https://www.w3.org/ns/did/v1" || doc.Context[1] != "https://w3id.org/security/multikey/v1" {
		t.Errorf("Context = %v", doc.Context)
	}

	// Round trip: the publicKeyMultibase fragment, when re-encoded, must
	// reproduce the original public key bytes.
	decoded, err := base58btcDecode(vm.PublicKeyMultibase[1:])
	if err != nil {
		t.Fatalf("base58btcDecode: %v", err)
	}
	if len(decoded) != payloadLen {
		t.Fatalf("decoded payload length = %d, want %d", len(decoded), payloadLen)
	}
	wantPub, _ := hex.DecodeString(pubKeyHex)
	if string(decoded[2:]) != string(wantPub) {
		t.Errorf("decoded pubkey does not match original")
	}
}

func TestResolveRejectsMissingPrefix(t *testing.T) {
	cases := []string{
		"",
		"did:key:",
		"did:web:example.com",
		"did:key:u" + expectedDID[len(prefix):], // wrong multibase prefix
		"key:z6Mktwup",
		expectedDID[1:], // missing leading "d"
	}
	for _, id := range cases {
		if _, err := Resolve(id); err == nil {
			t.Errorf("Resolve(%q): expected error, got nil", id)
		}
	}
}

func TestResolveRejectsInvalidBase58Characters(t *testing.T) {
	// 0, O, I, l are excluded from the base58btc alphabet.
	for _, ch := range []byte{'0', 'O', 'I', 'l'} {
		id := prefix + string(ch) + "6Mktwup"
		if _, err := Resolve(id); err == nil {
			t.Errorf("Resolve(%q): expected error for excluded char %q, got nil", id, ch)
		}
	}
}

func TestResolveRejectsWrongPayloadLength(t *testing.T) {
	// Too short: encode a 33-byte payload (1-byte multicodec + 32-byte key)
	// instead of the required 34.
	short := base58btcEncode(append([]byte{0xed}, make([]byte, 32)...))
	if _, err := Resolve(prefix + short); err == nil {
		t.Error("Resolve: expected error for 33-byte payload, got nil")
	}

	// Too long: 35 bytes.
	long := base58btcEncode(append([]byte{0xed, 0x01}, make([]byte, 33)...))
	if _, err := Resolve(prefix + long); err == nil {
		t.Error("Resolve: expected error for 35-byte payload, got nil")
	}
}

// TestResolveRejectsOversizedInput guards the DoS fix: Resolve must reject an
// encoded payload longer than maxEncodedLen before running the O(n^2)
// base58btc decode on it, not just after decoding completes.
func TestResolveRejectsOversizedInput(t *testing.T) {
	oversized := strings.Repeat("z", maxEncodedLen+1)
	if _, err := Resolve(prefix + oversized); err == nil {
		t.Error("Resolve: expected error for oversized encoded payload, got nil")
	}
}

func TestResolveRejectsWrongMulticodec(t *testing.T) {
	// 0xed02 is not a registered Ed25519 multicodec.
	payload := append([]byte{0xed, 0x02}, make([]byte, 32)...)
	id := prefix + base58btcEncode(payload)
	if _, err := Resolve(id); err == nil {
		t.Error("Resolve: expected error for wrong multicodec, got nil")
	}

	// A completely different multicodec (e.g. 0x1205, secp256k1-pub).
	payload2 := append([]byte{0x12, 0x05}, make([]byte, 32)...)
	id2 := prefix + base58btcEncode(payload2)
	if _, err := Resolve(id2); err == nil {
		t.Error("Resolve: expected error for secp256k1 multicodec, got nil")
	}
}

func TestBase58EncodeDecodeRoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},             // single leading zero byte
		{0x00, 0x00, 0x01}, // multiple leading zeros, non-zero tail
		{0xff},
		{0xed, 0x01},
		make([]byte, 34), // all leading zeros (worst case for the zeros count)
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
	}
	for _, data := range cases {
		encoded := base58btcEncode(data)
		if strings.ContainsAny(encoded, "0OIl") {
			t.Errorf("base58btcEncode(%x) = %q contains an excluded character", data, encoded)
		}
		decoded, err := base58btcDecode(encoded)
		if err != nil {
			t.Fatalf("base58btcDecode(%q): %v", encoded, err)
		}
		if string(decoded) != string(data) {
			t.Errorf("round trip %x -> %q -> %x", data, encoded, decoded)
		}
	}
}
