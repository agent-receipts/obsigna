// Package collector implements the reference HTTP collector that receives
// signed Agent Receipts from SDK HttpEmitters and persists them to a store.
//
// The collector is intentionally a dumb append-only sink. It does not sign,
// chain, sequence, or verify receipts — those are the SDK's responsibility on
// the emitting side and the auditor's responsibility on the consuming side.
// See ADR-0020 for the trust model.
package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"obsigna.dev/sdk/go/receipt"
)

// ErrDuplicate is returned by Store.Insert when a receipt with the same id is
// already present. Callers map this to HTTP 409.
var ErrDuplicate = errors.New("collector: receipt id already exists")

// Store is the persistence contract for the collector. It is intentionally
// narrower than sdk/go/store.ReceiptStore — the collector does not query.
//
// Insert takes both the decoded receipt (for indexed columns) and the raw
// bytes the receipt was decoded from. Storing the wire bytes verbatim — not
// a json.Marshal of the struct — is what lets an auditor later re-canonicalise
// and verify the agent's signature against exactly what was signed, including
// any forward-compat fields the Go struct may not know about.
type Store interface {
	// Insert persists a signed receipt with its precomputed canonical hash
	// and the raw JSON bytes as they arrived on the wire. Returns
	// ErrDuplicate when the receipt id already exists. Implementations
	// MUST be safe for concurrent use.
	Insert(r receipt.AgentReceipt, rawJSON []byte, receiptHash string) error

	// Exists reports whether a receipt with the given id is present.
	Exists(id string) (bool, error)

	// Close releases any resources held by the store.
	Close() error
}

// InMemoryStore is an in-process Store implementation suitable for tests and
// short-lived development use. It loses all data on process exit.
//
// Storage is rawJSON + hash only. The decoded receipt struct is re-parsed
// on Get so that callers cannot alias the store's internal state via slice
// fields on receipt.AgentReceipt (Context / Type / etc.). Mutex protection
// only covers the map operations — without the re-parse, returned slices
// would share backing arrays with stored state and would race the writers.
type InMemoryStore struct {
	mu       sync.RWMutex
	receipts map[string]storedReceipt
}

type storedReceipt struct {
	RawJSON []byte
	Hash    string
}

// NewInMemoryStore returns an empty in-memory Store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{receipts: make(map[string]storedReceipt)}
}

func (s *InMemoryStore) Insert(r receipt.AgentReceipt, rawJSON []byte, receiptHash string) error {
	// Validate that rawJSON is a JSON object up front. Get re-parses the
	// stored bytes back into a receipt struct; rejecting unparseable bytes
	// here keeps that path's contract honest (any later Unmarshal failure
	// in Get implies corruption, not bad input).
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(rawJSON, &probe); err != nil {
		return fmt.Errorf("collector: rawJSON is not valid JSON: %w", err)
	}
	if probe == nil {
		return errors.New("collector: rawJSON is not a JSON object")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.receipts[r.ID]; exists {
		return ErrDuplicate
	}
	// Copy rawJSON so a caller mutating the underlying buffer post-Insert
	// cannot corrupt our stored value. The receipt struct is intentionally
	// NOT stored — its slice fields (Context, Type, etc.) would alias caller
	// memory through the mutex; we re-parse on Get instead.
	stored := make([]byte, len(rawJSON))
	copy(stored, rawJSON)
	s.receipts[r.ID] = storedReceipt{RawJSON: stored, Hash: receiptHash}
	return nil
}

func (s *InMemoryStore) Exists(id string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.receipts[id]
	return ok, nil
}

func (s *InMemoryStore) Close() error { return nil }

// Len returns the number of receipts currently held. Test-only helper; not
// part of the Store interface.
func (s *InMemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.receipts)
}

// Get returns a freshly-decoded receipt, a fresh copy of the raw bytes, and
// the canonical hash for the given id, or false if absent. Test-only helper;
// not part of the Store interface.
//
// Re-parse on Get is intentional: it guarantees that callers cannot mutate
// store state via slice fields on the returned struct (Context/Type) or the
// returned byte slice. The allocation cost is acceptable for a test-only
// API.
func (s *InMemoryStore) Get(id string) (receipt.AgentReceipt, []byte, string, bool) {
	s.mu.RLock()
	sr, ok := s.receipts[id]
	s.mu.RUnlock()
	if !ok {
		return receipt.AgentReceipt{}, nil, "", false
	}

	rawCopy := make([]byte, len(sr.RawJSON))
	copy(rawCopy, sr.RawJSON)

	var r receipt.AgentReceipt
	if err := json.Unmarshal(rawCopy, &r); err != nil {
		// Insert rejects rawJSON that isn't a JSON object, so a parse
		// failure here implies the stored bytes were mutated in place
		// after the Insert returned — which the in-memory store guards
		// against via copy-on-insert. Return what we have so callers can
		// at least see the bytes and hash, but this path is best treated
		// as an invariant violation in test logs.
		return receipt.AgentReceipt{}, rawCopy, sr.Hash, true
	}
	return r, rawCopy, sr.Hash, true
}
