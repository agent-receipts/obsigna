package collector

import (
	"errors"
	"fmt"

	"obsigna.dev/sdk/go/receipt"
	"obsigna.dev/sdk/go/store"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// SQLiteStore is the production Store implementation backed by the shared
// sdk/go/store SQLite schema. The collector wraps store.Store with a
// duplicate-detection layer that maps id collisions to ErrDuplicate while
// preserving chain-uniqueness violations (a chain-construction bug, not a
// safe retry) as plain insert errors.
type SQLiteStore struct {
	inner *store.Store
}

// OpenSQLiteStore opens or creates a SQLite-backed collector store at the
// given path. Use ":memory:" for an in-process database (useful in tests but
// not durable across process restarts).
//
// store.Open sets MaxOpenConns(1), which is what makes ":memory:" retain
// state across calls in the same process — each new connection to
// ":memory:" otherwise gets a fresh in-memory database.
func OpenSQLiteStore(path string) (*SQLiteStore, error) {
	s, err := store.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}
	return &SQLiteStore{inner: s}, nil
}

func (s *SQLiteStore) Insert(r receipt.AgentReceipt, rawJSON []byte, receiptHash string) error {
	// Cheap path: if the id already exists, return ErrDuplicate without
	// attempting an INSERT. Handles the common HttpEmitter-retry case.
	if exists, err := s.inner.Exists(r.ID); err != nil {
		return fmt.Errorf("lookup existing receipt: %w", err)
	} else if exists {
		return ErrDuplicate
	}

	if err := s.inner.InsertRaw(r, rawJSON, receiptHash); err != nil {
		// Two failure modes to distinguish:
		//   1. PRIMARY KEY collision on receipts.id — a concurrent insert
		//      of the same id won the race after our cheap-path lookup
		//      missed. This is a safe-retry duplicate.
		//   2. UNIQUE collision on (chain_id, sequence) with a *different*
		//      id — a chain-construction bug; not a safe retry.
		//
		// modernc.org/sqlite happens to report whichever constraint fired
		// first, which depends on receipt content. Rather than parse the
		// driver's message, ask the database: re-look up by id and if the
		// row now exists, this was case (1); otherwise it was (2) and we
		// propagate the original error verbatim.
		if isPrimaryKeyViolation(err) {
			return ErrDuplicate
		}
		if exists, lookupErr := s.inner.Exists(r.ID); lookupErr == nil && exists {
			return ErrDuplicate
		}
		return fmt.Errorf("insert receipt: %w", err)
	}
	return nil
}

// isPrimaryKeyViolation reports whether err is a SQLite PRIMARY KEY
// constraint failure on the receipts.id column. This is a fast path that
// avoids the re-lookup round-trip in Insert when the driver clearly
// identifies an id collision (the common race-loser case). The Insert path's
// re-lookup fallback handles the case where this returns false but the row
// nonetheless exists — that path is the source of truth.
func isPrimaryKeyViolation(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	return sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}

func (s *SQLiteStore) Exists(id string) (bool, error) {
	ok, err := s.inner.Exists(id)
	if err != nil {
		return false, fmt.Errorf("lookup receipt: %w", err)
	}
	return ok, nil
}

func (s *SQLiteStore) Close() error {
	return s.inner.Close()
}
