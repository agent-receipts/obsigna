//go:build integration

package did

// Test runner for spec/test-vectors/did-key/vectors.json (ADR-0007,
// "Implementation spec — did:key v0.7 wire format").
//
// For each vector: FromPublicKey(publicKeyHex) must equal did, and
// Resolve(did) must equal did_document byte-for-byte (compared structurally,
// since JSON object member order is not semantically meaningful).
//
// Gated behind the `integration` build tag so `go test ./...` for the
// standalone sdk/go module still succeeds without the monorepo's
// spec/test-vectors/ sibling directory. CI runs with
// `go test -tags=integration ./...` to exercise these vectors.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const vectorsPath = "../../../spec/test-vectors/did-key/vectors.json"

type didKeyVectorFile struct {
	Vectors []didKeyVector `json:"vectors"`
}

type didKeyVector struct {
	Name         string          `json:"name"`
	Source       string          `json:"source"`
	PublicKeyHex string          `json:"public_key_hex"`
	DID          string          `json:"did"`
	DIDDocument  json.RawMessage `json:"did_document"`
}

func loadDIDKeyVectors(t *testing.T) didKeyVectorFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(filepath.Dir("."), vectorsPath))
	if err != nil {
		t.Fatalf("read did-key vectors.json: %v", err)
	}
	var vf didKeyVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse did-key vectors.json: %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("did-key vectors.json: no vectors found")
	}
	return vf
}

func TestDIDKeyVectors(t *testing.T) {
	vf := loadDIDKeyVectors(t)

	for _, v := range vf.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			pubBytes, err := hex.DecodeString(v.PublicKeyHex)
			if err != nil {
				t.Fatalf("decode public_key_hex: %v", err)
			}

			gotDID, err := FromPublicKey(ed25519.PublicKey(pubBytes))
			if err != nil {
				t.Fatalf("FromPublicKey: %v", err)
			}
			if gotDID != v.DID {
				t.Errorf("FromPublicKey\n  got:  %s\n  want: %s", gotDID, v.DID)
			}

			gotDoc, err := Resolve(v.DID)
			if err != nil {
				t.Fatalf("Resolve(%s): %v", v.DID, err)
			}

			gotJSON, err := json.Marshal(gotDoc)
			if err != nil {
				t.Fatalf("marshal resolved document: %v", err)
			}
			var gotGeneric, wantGeneric any
			if err := json.Unmarshal(gotJSON, &gotGeneric); err != nil {
				t.Fatalf("unmarshal resolved document: %v", err)
			}
			if err := json.Unmarshal(v.DIDDocument, &wantGeneric); err != nil {
				t.Fatalf("unmarshal expected document: %v", err)
			}
			if !reflect.DeepEqual(gotGeneric, wantGeneric) {
				t.Errorf("Resolve(%s) document mismatch\n  got:  %s\n  want: %s", v.DID, gotJSON, v.DIDDocument)
			}
		})
	}
}
