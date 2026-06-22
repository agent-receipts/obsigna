package collector

import (
	"errors"
	"sync"
	"testing"

	"obsigna.dev/sdk/go/receipt"
)

// testReceipt constructs a minimal AgentReceipt for store tests. It is not a
// schema-valid receipt for the wire — the collector store does not validate
// structure, so this is sufficient.
func testReceipt(id string) receipt.AgentReceipt {
	return receipt.AgentReceipt{
		ID:           id,
		IssuanceDate: "2026-05-22T00:00:00Z",
		Issuer:       receipt.Issuer{ID: "did:example:test"},
		CredentialSubject: receipt.CredentialSubject{
			Principal: receipt.Principal{ID: "did:example:user"},
			Action: receipt.Action{
				Type:      "tool_call",
				RiskLevel: receipt.RiskLow,
				Timestamp: "2026-05-22T00:00:00Z",
			},
			Outcome: receipt.Outcome{Status: "success"},
			Chain:   receipt.Chain{ChainID: "chain-1", Sequence: 0},
		},
	}
}

func TestInMemoryStore_InsertAndExists(t *testing.T) {
	s := NewInMemoryStore()
	r := testReceipt("urn:receipt:1")

	if exists, err := s.Exists(r.ID); err != nil || exists {
		t.Fatalf("Exists before insert: exists=%v err=%v, want false/nil", exists, err)
	}

	if err := s.Insert(r, []byte(`{"raw":"bytes"}`), "sha256:deadbeef"); err != nil {
		t.Fatalf("Insert: unexpected error: %v", err)
	}

	if exists, err := s.Exists(r.ID); err != nil || !exists {
		t.Fatalf("Exists after insert: exists=%v err=%v, want true/nil", exists, err)
	}

	if s.Len() != 1 {
		t.Fatalf("Len after insert: %d, want 1", s.Len())
	}
}

func TestInMemoryStore_InsertDuplicate(t *testing.T) {
	s := NewInMemoryStore()
	r := testReceipt("urn:receipt:dup")

	if err := s.Insert(r, []byte(`{}`), "sha256:1"); err != nil {
		t.Fatalf("first Insert: %v", err)
	}

	err := s.Insert(r, []byte(`{}`), "sha256:2")
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second Insert: err=%v, want ErrDuplicate", err)
	}

	// The first insert's data must not be overwritten.
	_, _, hash, ok := s.Get(r.ID)
	if !ok || hash != "sha256:1" {
		t.Fatalf("Get after duplicate Insert: hash=%q ok=%v, want sha256:1/true", hash, ok)
	}
}

func TestInMemoryStore_InsertPreservesRawBytes(t *testing.T) {
	s := NewInMemoryStore()
	r := testReceipt("urn:receipt:raw")
	raw := []byte(`{"_future_field":"forward-compat","id":"urn:receipt:raw"}`)

	if err := s.Insert(r, raw, "sha256:r"); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	_, gotRaw, _, ok := s.Get(r.ID)
	if !ok {
		t.Fatal("Get: not found")
	}
	if string(gotRaw) != string(raw) {
		t.Fatalf("Get returned raw bytes %q, want %q", gotRaw, raw)
	}

	// Mutating the caller's buffer after Insert must not affect stored
	// bytes — InMemoryStore copies on insert.
	raw[0] = '!'
	_, gotRawAfterMutate, _, _ := s.Get(r.ID)
	if gotRawAfterMutate[0] == '!' {
		t.Fatal("InMemoryStore did not copy raw bytes; caller mutation leaked into the store")
	}
}

func TestInMemoryStore_ConcurrentInserts(t *testing.T) {
	// Two concurrent inserts of the same id: exactly one must succeed, the
	// other must observe ErrDuplicate. This is the contract HttpEmitter
	// retries rely on — safe re-delivery cannot create silent duplicates.
	s := NewInMemoryStore()
	r := testReceipt("urn:receipt:race")

	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = s.Insert(r, []byte(`{}`), "sha256:r")
		}(i)
	}
	wg.Wait()

	var ok, dup int
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrDuplicate):
			dup++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 || dup != 1 {
		t.Fatalf("concurrent inserts: ok=%d dup=%d, want 1/1", ok, dup)
	}
}

func TestInMemoryStore_RejectsInvalidPayloads(t *testing.T) {
	// Get re-parses stored bytes; Insert must reject anything that isn't a
	// JSON object so Get's Unmarshal contract is honest. Mirrors the SDK
	// InsertRaw rejection set.
	s := NewInMemoryStore()
	r := testReceipt("urn:receipt:invalid")

	cases := []struct {
		name string
		raw  []byte
	}{
		{"not json", []byte(`{not json`)},
		{"json array", []byte(`[1, 2, 3]`)},
		{"json scalar", []byte(`42`)},
		{"json null", []byte(`null`)},
		{"empty body", []byte{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Insert(r, tc.raw, "sha256:invalid")
			if err == nil {
				t.Fatal("Insert with invalid payload: err=nil, want rejection")
			}
		})
	}
	if s.Len() != 0 {
		t.Fatalf("store mutated by rejected payloads: %d entries", s.Len())
	}
}

func TestInMemoryStore_ExistsUnknown(t *testing.T) {
	s := NewInMemoryStore()
	if exists, err := s.Exists("urn:receipt:nope"); err != nil || exists {
		t.Fatalf("Exists for unknown id: exists=%v err=%v, want false/nil", exists, err)
	}
}

func TestInMemoryStore_GetReturnsIndependentCopies(t *testing.T) {
	// Returned struct must not alias the store's internal state. Before
	// the rawJSON-only refactor, slice fields on receipt.AgentReceipt
	// (Context, Type) were shared between Insert input, Get output, and
	// the store's map, so a caller mutating Get's result would silently
	// corrupt the store. Re-parse on Get eliminates that aliasing.
	s := NewInMemoryStore()
	r := testReceipt("urn:receipt:alias")
	r.Context = []string{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"}
	r.Type = []string{"VerifiableCredential", "AgentReceipt"}

	raw := []byte(`{
		"id": "urn:receipt:alias",
		"@context": ["https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"],
		"type": ["VerifiableCredential", "AgentReceipt"]
	}`)
	if err := s.Insert(r, raw, "sha256:alias"); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	got1, raw1, _, _ := s.Get(r.ID)
	if len(got1.Context) == 0 {
		t.Fatal("Get returned empty Context; raw bytes parse should populate it")
	}

	// Mutate the returned struct's slice and the returned raw bytes.
	got1.Context[0] = "evil-aliased-write"
	raw1[0] = '!'

	// Second Get must return pristine values regardless of the mutations.
	got2, raw2, _, _ := s.Get(r.ID)
	if got2.Context[0] == "evil-aliased-write" {
		t.Fatalf("mutation leaked into Context: got %q", got2.Context[0])
	}
	if raw2[0] != '{' {
		t.Fatalf("mutation leaked into raw bytes: first byte = %q", raw2[0])
	}
}
