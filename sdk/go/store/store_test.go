package store

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

func setupStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustKeyPair(t *testing.T) receipt.KeyPair {
	t.Helper()
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	return kp
}

func mustHashReceipt(t *testing.T, r receipt.AgentReceipt) string {
	t.Helper()
	h, err := receipt.HashReceipt(r)
	if err != nil {
		t.Fatalf("hash receipt: %v", err)
	}
	return h
}

func makeSignedReceipt(t *testing.T, kp receipt.KeyPair, seq int, chainID string, prevHash *string) receipt.AgentReceipt {
	t.Helper()
	unsigned := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: "did:agent:test"},
		Principal: receipt.Principal{ID: "did:user:test"},
		Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
		Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
		Chain:     receipt.Chain{Sequence: seq, PreviousReceiptHash: prevHash, ChainID: chainID},
	})
	signed, err := receipt.Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestInsertAndGetByID(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)
	r := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h := mustHashReceipt(t, r)

	if err := s.Insert(r, h); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetByID(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected receipt, got nil")
	}
	if got.ID != r.ID {
		t.Errorf("expected %s, got %s", r.ID, got.ID)
	}
}

func TestGetByIDNotFound(t *testing.T) {
	s := setupStore(t)
	got, err := s.GetByID("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected nil for missing receipt")
	}
}

func TestExists(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)
	r := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h := mustHashReceipt(t, r)
	if err := s.Insert(r, h); err != nil {
		t.Fatal(err)
	}

	ok, err := s.Exists(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected Exists to report present receipt as true")
	}

	ok, err = s.Exists("urn:never:inserted")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected Exists to report absent receipt as false")
	}
}

func TestExistsAfterClose(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := s.Exists("anything"); err == nil {
		t.Error("expected Exists to surface an error on a closed store")
	}
}

func TestGetChain(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	var prevHash *string
	for i := 1; i <= 3; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h := mustHashReceipt(t, r)
		if err := s.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	chain, err := s.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 3 {
		t.Errorf("expected 3 receipts, got %d", len(chain))
	}
	for i, r := range chain {
		if r.CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("expected sequence %d, got %d", i+1, r.CredentialSubject.Chain.Sequence)
		}
	}
}

func TestGetByChainSequence(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	var prevHash *string
	for i := 1; i <= 3; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h := mustHashReceipt(t, r)
		if err := s.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	got, err := s.GetByChainSequence("chain-1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected receipt at sequence 2, got nil")
	}
	if got.CredentialSubject.Chain.Sequence != 2 {
		t.Errorf("expected sequence 2, got %d", got.CredentialSubject.Chain.Sequence)
	}
}

func TestGetByChainSequence_NotFound(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)
	r := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h := mustHashReceipt(t, r)
	if err := s.Insert(r, h); err != nil {
		t.Fatal(err)
	}

	// Missing sequence in an existing chain.
	got, err := s.GetByChainSequence("chain-1", 99)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected nil for missing sequence")
	}

	// Unknown chain entirely.
	got, err = s.GetByChainSequence("no-such-chain", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected nil for unknown chain")
	}
}

func TestDistinctChainIDs(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	// Two chains, "chain-b" written before "chain-a" to confirm sorted output.
	for _, chainID := range []string{"chain-b", "chain-a"} {
		var prevHash *string
		for i := 1; i <= 2; i++ {
			r := makeSignedReceipt(t, kp, i, chainID, prevHash)
			h := mustHashReceipt(t, r)
			if err := s.Insert(r, h); err != nil {
				t.Fatal(err)
			}
			prevHash = &h
		}
	}

	chains, err := s.DistinctChainIDs()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"chain-a", "chain-b"}
	if len(chains) != len(want) {
		t.Fatalf("got %v, want %v", chains, want)
	}
	for i := range want {
		if chains[i] != want[i] {
			t.Errorf("chains[%d] = %q, want %q", i, chains[i], want[i])
		}
	}
}

func TestDistinctChainIDs_Empty(t *testing.T) {
	s := setupStore(t)
	chains, err := s.DistinctChainIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 0 {
		t.Errorf("expected no chains, got %v", chains)
	}
}

func TestLatestRootChainID_Empty(t *testing.T) {
	s := setupStore(t)
	chainID, found, err := s.LatestRootChainID()
	if err != nil {
		t.Fatal(err)
	}
	if found || chainID != "" {
		t.Errorf("got (%q, %v), want (\"\", false) for an empty store", chainID, found)
	}
}

func TestLatestRootChainID_MostRecentlyWritten(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	// Insert "2026-06-03" first (more receipts → higher max sequence), then
	// "2026-06-03-8". Recency is by write order (rowid), so the second chain
	// wins even though the first holds a higher-sequence receipt — guarding
	// against a timestamp/sequence tiebreak surfacing the older chain.
	insert := func(chainID string, count int) {
		var prevHash *string
		for i := 1; i <= count; i++ {
			r := makeSignedReceipt(t, kp, i, chainID, prevHash)
			h := mustHashReceipt(t, r)
			if err := s.Insert(r, h); err != nil {
				t.Fatal(err)
			}
			prevHash = &h
		}
	}
	insert("2026-06-03", 3)
	insert("2026-06-03-8", 2)

	chainID, found, err := s.LatestRootChainID()
	if err != nil {
		t.Fatal(err)
	}
	if !found || chainID != "2026-06-03-8" {
		t.Errorf("got (%q, %v), want (\"2026-06-03-8\", true)", chainID, found)
	}
}

func TestLatestRootChainID_ExcludesAgentSubchains(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	r := makeSignedReceipt(t, kp, 1, "2026-06-03-8", nil)
	h := mustHashReceipt(t, r)
	if err := s.Insert(r, h); err != nil {
		t.Fatal(err)
	}
	// Agent sub-chain receipt written last: newer by rowid, but must be excluded.
	ar := makeSignedReceipt(t, kp, 1, "2026-06-03-8/agent/abc123", nil)
	ah := mustHashReceipt(t, ar)
	if err := s.Insert(ar, ah); err != nil {
		t.Fatal(err)
	}

	chainID, found, err := s.LatestRootChainID()
	if err != nil {
		t.Fatal(err)
	}
	if !found || chainID != "2026-06-03-8" {
		t.Errorf("got (%q, %v), want the root chain excluding agent sub-chains", chainID, found)
	}
}

func TestGetChainTail_Empty(t *testing.T) {
	s := setupStore(t)
	seq, hash, found, err := s.GetChainTail("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("expected found=false for empty chain")
	}
	if seq != 0 || hash != "" {
		t.Errorf("expected zero values, got seq=%d hash=%q", seq, hash)
	}
}

func TestGetChainTail_SingleRow(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)
	r := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h := mustHashReceipt(t, r)
	if err := s.Insert(r, h); err != nil {
		t.Fatal(err)
	}

	seq, hash, found, err := s.GetChainTail("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected found=true")
	}
	if seq != 1 {
		t.Errorf("expected seq=1, got %d", seq)
	}
	if hash != h {
		t.Errorf("expected hash=%s, got %s", h, hash)
	}
}

func TestGetChainTail_HighestSequence(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	// Insert 1..5 in non-monotonic order to confirm the query orders by sequence,
	// not insertion order.
	insertOrder := []int{3, 1, 5, 2, 4}
	hashes := make(map[int]string, len(insertOrder))
	for _, seq := range insertOrder {
		r := makeSignedReceipt(t, kp, seq, "chain-1", nil)
		h := mustHashReceipt(t, r)
		if err := s.Insert(r, h); err != nil {
			t.Fatalf("insert seq=%d: %v", seq, err)
		}
		hashes[seq] = h
	}

	seq, hash, found, err := s.GetChainTail("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected found=true")
	}
	if seq != 5 {
		t.Errorf("expected seq=5 (highest), got %d", seq)
	}
	if hash != hashes[5] {
		t.Errorf("expected hash for seq=5, got hash for a different row")
	}
}

func TestGetChainTail_MultiChainIsolation(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	rA := makeSignedReceipt(t, kp, 7, "chain-A", nil)
	hA := mustHashReceipt(t, rA)
	if err := s.Insert(rA, hA); err != nil {
		t.Fatal(err)
	}
	rB := makeSignedReceipt(t, kp, 2, "chain-B", nil)
	hB := mustHashReceipt(t, rB)
	if err := s.Insert(rB, hB); err != nil {
		t.Fatal(err)
	}

	seqA, hashA, foundA, err := s.GetChainTail("chain-A")
	if err != nil || !foundA {
		t.Fatalf("chain-A: err=%v found=%v", err, foundA)
	}
	if seqA != 7 || hashA != hA {
		t.Errorf("chain-A leaked: seq=%d hash=%s", seqA, hashA)
	}

	seqB, hashB, foundB, err := s.GetChainTail("chain-B")
	if err != nil || !foundB {
		t.Fatalf("chain-B: err=%v found=%v", err, foundB)
	}
	if seqB != 2 || hashB != hB {
		t.Errorf("chain-B leaked: seq=%d hash=%s", seqB, hashB)
	}

	_, _, foundC, err := s.GetChainTail("chain-C")
	if err != nil {
		t.Fatal(err)
	}
	if foundC {
		t.Error("chain-C should be empty")
	}
}

func TestQueryReceipts(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	r := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h := mustHashReceipt(t, r)
	s.Insert(r, h)

	chainID := "chain-1"
	results, err := s.QueryReceipts(Query{ChainID: &chainID})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1, got %d", len(results))
	}

	chainID = "nonexistent"
	results, err = s.QueryReceipts(Query{ChainID: &chainID})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0, got %d", len(results))
	}
}

func TestStats(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	for i := 1; i <= 3; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", nil)
		h := mustHashReceipt(t, r)
		s.Insert(r, h)
	}

	st, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 3 {
		t.Errorf("expected total 3, got %d", st.Total)
	}
	if st.Chains != 1 {
		t.Errorf("expected 1 chain, got %d", st.Chains)
	}
}

func TestInsertDuplicateReceiptID(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)
	r := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h := mustHashReceipt(t, r)

	if err := s.Insert(r, h); err != nil {
		t.Fatal(err)
	}
	err := s.Insert(r, h)
	if err == nil {
		t.Fatal("expected error on duplicate receipt ID insert")
	}
}

func TestInsertDuplicateChainSequence(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	r1 := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h1 := mustHashReceipt(t, r1)
	if err := s.Insert(r1, h1); err != nil {
		t.Fatal(err)
	}

	// Different receipt (new ID) but same chain_id + sequence.
	r2 := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h2 := mustHashReceipt(t, r2)
	err := s.Insert(r2, h2)
	if err == nil {
		t.Fatal("expected error on duplicate chain_id + sequence")
	}
}

func TestQueryReceiptsOrdering(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	// Insert three receipts with timestamps a few seconds apart by
	// stamping them post-Create (Create sets the Action.Timestamp to now).
	timestamps := []string{
		"2024-01-01T00:00:01Z",
		"2024-01-01T00:00:02Z",
		"2024-01-01T00:00:03Z",
	}
	for i, ts := range timestamps {
		unsigned := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: "did:agent:test"},
			Principal: receipt.Principal{ID: "did:user:test"},
			Action: receipt.Action{
				Type:      "filesystem.file.read",
				RiskLevel: receipt.RiskLow,
				Timestamp: ts,
			},
			Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
			Chain:   receipt.Chain{Sequence: i + 1, ChainID: "chain-1"},
		})
		signed, err := receipt.Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
		if err != nil {
			t.Fatal(err)
		}
		h := mustHashReceipt(t, signed)
		if err := s.Insert(signed, h); err != nil {
			t.Fatal(err)
		}
	}

	// Ascending by default.
	asc, err := s.QueryReceipts(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(asc) != 3 {
		t.Fatalf("expected 3 receipts, got %d", len(asc))
	}
	if got := asc[0].CredentialSubject.Action.Timestamp; got != timestamps[0] {
		t.Errorf("default ordering: expected oldest %s first, got %s", timestamps[0], got)
	}

	// Newest-first when opted in.
	desc, err := s.QueryReceipts(Query{NewestFirst: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(desc) != 3 {
		t.Fatalf("expected 3 receipts, got %d", len(desc))
	}
	if got := desc[0].CredentialSubject.Action.Timestamp; got != timestamps[2] {
		t.Errorf("NewestFirst: expected newest %s first, got %s", timestamps[2], got)
	}
}

func TestQueryReceiptsNoDefaultLimit(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	// A small batch here proves the integration path; the real regression guard
	// for the removed 10k cap is TestBuildQueryReceiptsSQLNoLimit in
	// store_sql_test.go (white-box SQL assertion in the store package).
	const n = 5
	for i := 1; i <= n; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", nil)
		h := mustHashReceipt(t, r)
		if err := s.Insert(r, h); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	// nil Limit must return all rows.
	results, err := s.QueryReceipts(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != n {
		t.Errorf("expected %d results with no limit, got %d", n, len(results))
	}

	// Explicit Limit still works.
	lim := 3
	limited, err := s.QueryReceipts(Query{Limit: &lim})
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != lim {
		t.Errorf("expected %d results with explicit limit, got %d", lim, len(limited))
	}
}

func TestQueryReceiptsDescSequenceTiebreaker(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	// Two receipts share the same timestamp but differ in sequence.
	// With NewestFirst the one with the higher sequence must come first.
	sharedTS := "2024-06-01T12:00:00Z"
	for _, seq := range []int{1, 2} {
		unsigned := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: "did:agent:test"},
			Principal: receipt.Principal{ID: "did:user:test"},
			Action: receipt.Action{
				Type:      "filesystem.file.read",
				RiskLevel: receipt.RiskLow,
				Timestamp: sharedTS,
			},
			Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
			Chain:   receipt.Chain{Sequence: seq, ChainID: "chain-tie"},
		})
		signed, err := receipt.Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
		if err != nil {
			t.Fatal(err)
		}
		h := mustHashReceipt(t, signed)
		if err := s.Insert(signed, h); err != nil {
			t.Fatal(err)
		}
	}

	desc, err := s.QueryReceipts(Query{NewestFirst: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(desc) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(desc))
	}
	if got := desc[0].CredentialSubject.Chain.Sequence; got != 2 {
		t.Errorf("tiebreaker: expected sequence 2 first, got %d", got)
	}
	if got := desc[1].CredentialSubject.Chain.Sequence; got != 1 {
		t.Errorf("tiebreaker: expected sequence 1 second, got %d", got)
	}
}

func TestQueryReceiptsAscSequenceTiebreaker(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	sharedTS := "2024-06-01T12:00:00Z"
	for _, seq := range []int{2, 1} { // insert in reverse to confirm ordering is by SQL not insertion
		unsigned := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: "did:agent:test"},
			Principal: receipt.Principal{ID: "did:user:test"},
			Action: receipt.Action{
				Type:      "filesystem.file.read",
				RiskLevel: receipt.RiskLow,
				Timestamp: sharedTS,
			},
			Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
			Chain:   receipt.Chain{Sequence: seq, ChainID: "chain-asc-tie"},
		})
		signed, err := receipt.Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
		if err != nil {
			t.Fatal(err)
		}
		h := mustHashReceipt(t, signed)
		if err := s.Insert(signed, h); err != nil {
			t.Fatal(err)
		}
	}

	asc, err := s.QueryReceipts(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(asc) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(asc))
	}
	if got := asc[0].CredentialSubject.Chain.Sequence; got != 1 {
		t.Errorf("ASC tiebreaker: expected sequence 1 first, got %d", got)
	}
	if got := asc[1].CredentialSubject.Chain.Sequence; got != 2 {
		t.Errorf("ASC tiebreaker: expected sequence 2 second, got %d", got)
	}
}

func TestQueryReceiptsCombinedFilters(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	// Insert a receipt we can filter on.
	r := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h := mustHashReceipt(t, r)
	s.Insert(r, h)

	actionType := "filesystem.file.read"
	riskLevel := receipt.RiskLow
	after := "2000-01-01T00:00:00Z"
	before := "2099-01-01T00:00:00Z"

	results, err := s.QueryReceipts(Query{
		ActionType: &actionType,
		RiskLevel:  &riskLevel,
		After:      &after,
		Before:     &before,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result with combined filters, got %d", len(results))
	}
}

func TestMaxRowIDEmpty(t *testing.T) {
	s := setupStore(t)
	max, err := s.MaxRowID()
	if err != nil {
		t.Fatal(err)
	}
	if max != 0 {
		t.Errorf("expected 0 for empty store, got %d", max)
	}
}

func TestMaxRowIDAfterInsert(t *testing.T) {
	s := setupStore(t)
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var prevHash *string
	for i := 1; i <= 3; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h, err := receipt.HashReceipt(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	max, err := s.MaxRowID()
	if err != nil {
		t.Fatal(err)
	}
	if max != 3 {
		t.Errorf("expected rowid 3 after 3 inserts, got %d", max)
	}
}

func TestQueryAfterRowIDReturnsOnlyNewRows(t *testing.T) {
	s := setupStore(t)
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var prevHash *string
	for i := 1; i <= 2; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h, err := receipt.HashReceipt(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	watermark, err := s.MaxRowID()
	if err != nil {
		t.Fatal(err)
	}

	// Insert two more after the watermark.
	for i := 3; i <= 4; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h, err := receipt.HashReceipt(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	results, newMax, err := s.QueryAfterRowID(Query{}, watermark)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 new rows, got %d", len(results))
	}
	if newMax != 4 {
		t.Errorf("expected newMax rowid 4, got %d", newMax)
	}
	// Second call with the advanced watermark should return nothing and
	// leave the watermark unchanged.
	results, same, err := s.QueryAfterRowID(Query{}, newMax)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 rows after advancing watermark, got %d", len(results))
	}
	if same != newMax {
		t.Errorf("expected watermark to stay at %d, got %d", newMax, same)
	}
}

func TestQueryReceiptsWithWatermarkReturnsConsistentPair(t *testing.T) {
	s := setupStore(t)
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var prevHash *string
	for i := 1; i <= 3; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h, err := receipt.HashReceipt(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	receipts, watermark, err := s.QueryReceiptsWithWatermark(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 3 {
		t.Errorf("expected 3 receipts, got %d", len(receipts))
	}
	if watermark != 3 {
		t.Errorf("expected watermark 3, got %d", watermark)
	}

	// Insert another row and confirm the watermark from above makes
	// QueryAfterRowID return only the new row.
	r := makeSignedReceipt(t, kp, 4, "chain-1", prevHash)
	h, err := receipt.HashReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(r, h); err != nil {
		t.Fatal(err)
	}
	newRows, _, err := s.QueryAfterRowID(Query{}, watermark)
	if err != nil {
		t.Fatal(err)
	}
	if len(newRows) != 1 {
		t.Errorf("expected 1 new row after watermark, got %d", len(newRows))
	}
}

func TestQueryAfterRowIDAppliesFilters(t *testing.T) {
	s := setupStore(t)
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Insert into two different chains.
	for i, chain := range []string{"chain-a", "chain-b"} {
		r := makeSignedReceipt(t, kp, i+1, chain, nil)
		h, err := receipt.HashReceipt(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(r, h); err != nil {
			t.Fatal(err)
		}
	}

	chainA := "chain-a"
	results, _, err := s.QueryAfterRowID(Query{ChainID: &chainA}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for chain-a filter, got %d", len(results))
	}
	if results[0].CredentialSubject.Chain.ChainID != chainA {
		t.Errorf("wrong chain: %s", results[0].CredentialSubject.Chain.ChainID)
	}
}

func TestQueryAfterRowIDNilLimitReturnsAllRows(t *testing.T) {
	s := setupStore(t)
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	const n = 5
	var prevHash *string
	for i := 1; i <= n; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-nil-limit", prevHash)
		h, err := receipt.HashReceipt(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	// nil Limit must return all rows above rowid 0.
	results, _, err := s.QueryAfterRowID(Query{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != n {
		t.Errorf("QueryAfterRowID with nil Limit: got %d rows, want %d", len(results), n)
	}
}

func TestBuildQueryAfterRowIDSQLNilLimitOmitsLIMIT(t *testing.T) {
	sql, _ := buildQueryAfterRowIDSQL(Query{}, 0)
	if strings.Contains(sql, "LIMIT") {
		t.Errorf("buildQueryAfterRowIDSQL with nil Limit must not contain LIMIT, got: %s", sql)
	}
}

func TestCloseMultipleTimes(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("first close failed: %v", err)
	}
	// Second close should not panic.
	_ = s.Close()
}

func TestOpenReadOnlyVerifiesExistingChain(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")

	rw, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	kp := mustKeyPair(t)
	var prevHash *string
	for i := 1; i <= 3; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h := mustHashReceipt(t, r)
		if err := rw.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}

	ro, err := OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	t.Cleanup(func() { ro.Close() })

	result, err := ro.VerifyStoredChain("chain-1", kp.PublicKey)
	if err != nil {
		t.Fatalf("VerifyStoredChain on read-only handle: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected valid chain, broken at %d", result.BrokenAt)
	}
	if result.Length != 3 {
		t.Fatalf("expected 3 receipts verified, got %d", result.Length)
	}
}

func TestOpenReadOnlyRejectsWrites(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")

	rw, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}

	ro, err := OpenReadOnly(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ro.Close() })

	kp := mustKeyPair(t)
	r := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h := mustHashReceipt(t, r)
	// We deliberately don't pin a specific SQLite error string here — the
	// driver's wording around read-only rejection has shifted between
	// modernc.org/sqlite versions, and the behaviour we actually care about
	// is "the write was rejected", regardless of how it's phrased.
	if err := ro.Insert(r, h); err == nil {
		t.Fatal("expected Insert against read-only handle to fail, got nil")
	}
}

func TestOpenReadOnlyConcurrentWithWriter(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")

	rw, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rw.Close() })

	kp := mustKeyPair(t)
	var prevHash *string
	for i := 1; i <= 2; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h := mustHashReceipt(t, r)
		if err := rw.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	// Open read-only while the writer handle is still live — verifies the
	// daemon-up case where agent-receipts verify must not collide with the
	// daemon's exclusive ownership of the write side.
	ro, err := OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("OpenReadOnly while writer is open: %v", err)
	}
	t.Cleanup(func() { ro.Close() })

	got, err := ro.GetChain("chain-1")
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(got))
	}
}

func TestOpenReadOnlyRejectsMemoryAndEmpty(t *testing.T) {
	if _, err := OpenReadOnly(""); err == nil {
		t.Fatal("expected error for empty path")
	}
	if _, err := OpenReadOnly(":memory:"); err == nil {
		t.Fatal("expected error for :memory:")
	}
}

func TestVerifyStoredChain(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	var prevHash *string
	for i := 1; i <= 3; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h := mustHashReceipt(t, r)
		s.Insert(r, h)
		prevHash = &h
	}

	result, err := s.VerifyStoredChain("chain-1", kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Errorf("expected valid chain, broken at %d", result.BrokenAt)
	}
}

func TestInsertRaw_PreservesUnknownFields(t *testing.T) {
	// InsertRaw must store the on-wire bytes verbatim so that auditors can
	// later re-verify the agent's signature against exactly what the agent
	// signed. The Go struct does not know about every field a future SDK
	// version may emit; round-tripping via json.Marshal(struct) would drop
	// those fields and break cross-SDK verification. This test pins that
	// behaviour by injecting an unknown field into the raw bytes and
	// asserting it survives the store round-trip.
	s := setupStore(t)
	kp := mustKeyPair(t)
	r := makeSignedReceipt(t, kp, 1, "chain-raw", nil)

	rJSON, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Splice in an unknown top-level field. The struct decoder ignores it,
	// but the bytes we hand to InsertRaw still contain it.
	raw := strings.Replace(string(rJSON), `"id":`, `"_future_field":"hello",`+`"id":`, 1)
	if !strings.Contains(raw, `"_future_field":"hello"`) {
		t.Fatalf("splice failed: %s", raw)
	}
	// Hash the raw bytes (not the struct) so the stored receipt_hash column
	// stays internally consistent with the stored receipt_json — an auditor
	// recomputing HashRawReceipt(stored_bytes) gets the same value back.
	h, err := receipt.HashRawReceipt([]byte(raw))
	if err != nil {
		t.Fatalf("HashRawReceipt: %v", err)
	}

	if err := s.InsertRaw(r, []byte(raw), h); err != nil {
		t.Fatalf("InsertRaw: %v", err)
	}

	// Pull the stored receipt_json column back directly — using GetByID
	// would round-trip through the Go struct and lose the field, defeating
	// the test.
	var stored string
	if err := s.db.QueryRow("SELECT receipt_json FROM receipts WHERE id = ?", r.ID).Scan(&stored); err != nil {
		t.Fatalf("select stored bytes: %v", err)
	}
	if !strings.Contains(stored, `"_future_field":"hello"`) {
		t.Fatalf("stored bytes lost unknown field: %s", stored)
	}

	// Stored hash must round-trip with the auditor's view.
	var storedHash string
	if err := s.db.QueryRow("SELECT receipt_hash FROM receipts WHERE id = ?", r.ID).Scan(&storedHash); err != nil {
		t.Fatalf("select stored hash: %v", err)
	}
	want, err := receipt.HashRawReceipt([]byte(stored))
	if err != nil {
		t.Fatalf("hash raw receipt: %v", err)
	}
	if storedHash != want {
		t.Fatalf("stored receipt_hash = %s; HashRawReceipt(stored bytes) = %s; want equal", storedHash, want)
	}
}

func TestInsertRaw_RejectsMismatchedID(t *testing.T) {
	// The row key (indexed `id` column) is taken from the struct; the
	// receipt_json column is taken from the raw bytes. If those two
	// disagree on `id`, GetByID-by-struct-id returns a parsed receipt with
	// a different ID — silent corruption that is lethal at audit time.
	// InsertRaw must refuse the insert.
	s := setupStore(t)
	kp := mustKeyPair(t)
	r := makeSignedReceipt(t, kp, 1, "chain-mismatch", nil)
	h := mustHashReceipt(t, r)

	err := s.InsertRaw(r, []byte(`{"id":"different","raw":"bytes"}`), h)
	if err == nil {
		t.Fatal("InsertRaw with mismatched id: err=nil, want rejection")
	}
	if !strings.Contains(err.Error(), "disagrees") {
		t.Fatalf("error %q does not mention id disagreement", err.Error())
	}

	// No row should have been inserted.
	if got, _ := s.GetByID(r.ID); got != nil {
		t.Fatalf("row was inserted despite rejection: %+v", got)
	}
}

func TestInsertRaw_AcceptsRawWithoutID(t *testing.T) {
	// The SDK is not the structural validator — a higher-layer caller (e.g.
	// the collector) enforces that receipts carry an id. If rawJSON happens
	// to omit the id key, the SDK accepts it: the indexed column still
	// reflects r.ID and GetByID still works by struct id. This documents
	// the boundary of validateRawReceipt's checks.
	s := setupStore(t)
	kp := mustKeyPair(t)
	r := makeSignedReceipt(t, kp, 1, "chain-noid", nil)
	h := mustHashReceipt(t, r)

	raw := []byte(`{"raw":"without-id-field"}`)
	if err := s.InsertRaw(r, raw, h); err != nil {
		t.Fatalf("InsertRaw without rawJSON id: %v", err)
	}

	var stored string
	if err := s.db.QueryRow("SELECT receipt_json FROM receipts WHERE id = ?", r.ID).Scan(&stored); err != nil {
		t.Fatalf("select stored bytes: %v", err)
	}
	if stored != string(raw) {
		t.Fatalf("stored bytes = %q, want %q", stored, raw)
	}
}

func TestInsertRaw_RejectsMismatchedChainOrSequence(t *testing.T) {
	// The indexed (chain_id, sequence) columns are taken from the struct, so
	// receipt_json carrying different values for those fields would describe
	// a different chain position than the row key — silent inconsistency
	// the UNIQUE index on the indexed columns cannot catch. InsertRaw must
	// reject both mismatch modes.
	s := setupStore(t)
	kp := mustKeyPair(t)
	r := makeSignedReceipt(t, kp, 7, "chain-honest", nil)
	h := mustHashReceipt(t, r)

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "chain_id mismatch",
			raw:  `{"id":"` + r.ID + `","credentialSubject":{"chain":{"chain_id":"chain-lie","sequence":7}}}`,
			want: "chain.chain_id",
		},
		{
			name: "sequence mismatch",
			raw:  `{"id":"` + r.ID + `","credentialSubject":{"chain":{"chain_id":"chain-honest","sequence":99}}}`,
			want: "chain.sequence",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.InsertRaw(r, []byte(tc.raw), h)
			if err == nil {
				t.Fatal("InsertRaw with mismatch: err=nil, want rejection")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}

	// No rows should have been inserted by any of the rejected attempts.
	if got, _ := s.GetByID(r.ID); got != nil {
		t.Fatalf("row leaked despite rejections: %+v", got)
	}
}

func TestInsertRaw_RejectsInvalidPayloads(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)
	r := makeSignedReceipt(t, kp, 1, "chain-bad", nil)
	h := mustHashReceipt(t, r)

	cases := []struct {
		name string
		raw  []byte
	}{
		{"not json", []byte(`{not json`)},
		{"json array", []byte(`[1, 2, 3]`)},
		{"json scalar", []byte(`42`)},
		{"json null", []byte(`null`)},
		{"empty body", []byte{}},
		{"non-string id", []byte(`{"id": 42}`)},
		{"non-integer sequence", []byte(`{"credentialSubject":{"chain":{"sequence":"oops"}}}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.InsertRaw(r, tc.raw, h)
			if err == nil {
				t.Fatal("InsertRaw with invalid payload: err=nil, want rejection")
			}
		})
	}

	// Re-check that none of those rejected calls leaked a row.
	if got, _ := s.GetByID(r.ID); got != nil {
		t.Fatalf("row was inserted by one of the rejected payloads: %+v", got)
	}
}

func TestGetChainTailReceipt_Empty(t *testing.T) {
	s := setupStore(t)
	got, err := s.GetChainTailReceipt("chain-1")
	if err != nil {
		t.Fatalf("GetChainTailReceipt on empty store: %v", err)
	}
	if got != nil {
		t.Fatalf("GetChainTailReceipt on empty store: want nil, got %+v", got)
	}
}

func TestGetChainTailReceipt_ReturnsHighestSequence(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	r1 := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h1 := mustHashReceipt(t, r1)
	r2 := makeSignedReceipt(t, kp, 2, "chain-1", &h1)
	h2 := mustHashReceipt(t, r2)

	if err := s.Insert(r1, h1); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(r2, h2); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetChainTailReceipt("chain-1")
	if err != nil {
		t.Fatalf("GetChainTailReceipt: %v", err)
	}
	if got == nil {
		t.Fatal("GetChainTailReceipt: want receipt, got nil")
	}
	if got.CredentialSubject.Chain.Sequence != 2 {
		t.Errorf("GetChainTailReceipt: got sequence %d, want 2", got.CredentialSubject.Chain.Sequence)
	}
}

func TestGetChainTailReceipt_ChainIsolation(t *testing.T) {
	s := setupStore(t)
	kp := mustKeyPair(t)

	rA := makeSignedReceipt(t, kp, 1, "chain-A", nil)
	hA := mustHashReceipt(t, rA)
	rB := makeSignedReceipt(t, kp, 1, "chain-B", nil)
	hB := mustHashReceipt(t, rB)

	if err := s.Insert(rA, hA); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(rB, hB); err != nil {
		t.Fatal(err)
	}

	gotA, err := s.GetChainTailReceipt("chain-A")
	if err != nil {
		t.Fatalf("GetChainTailReceipt chain-A: %v", err)
	}
	if gotA == nil || gotA.CredentialSubject.Chain.ChainID != "chain-A" {
		t.Errorf("GetChainTailReceipt chain-A: got %+v", gotA)
	}

	gotC, err := s.GetChainTailReceipt("chain-C")
	if err != nil {
		t.Fatalf("GetChainTailReceipt chain-C: %v", err)
	}
	if gotC != nil {
		t.Errorf("GetChainTailReceipt unknown chain: want nil, got %+v", gotC)
	}
}

func TestGetChainTailReceipt_CorruptJSON(t *testing.T) {
	s := setupStore(t)

	// Bypass InsertRaw validation and write a row with invalid JSON directly
	// to simulate on-disk corruption reaching GetChainTailReceipt.
	_, err := s.db.Exec(
		`INSERT INTO receipts (id, chain_id, sequence, action_type, risk_level, status, timestamp, issuer_id, receipt_hash, receipt_json)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		"corrupt-id", "chain-corrupt", 1, "test.action", "low", "success", "2026-01-01T00:00:00Z", "did:test", "deadbeef", `{not valid json`,
	)
	if err != nil {
		t.Fatalf("direct insert: %v", err)
	}

	_, err = s.GetChainTailReceipt("chain-corrupt")
	if err == nil {
		t.Error("GetChainTailReceipt with corrupt JSON: want error, got nil")
	}
}
