// Package anchor defines the external-witness sink the daemon writes
// rotation (and, in a later phase, checkpoint) events to (ADR-0015).
//
// The sink is the construct that makes rotation history survive daemon-key
// compromise: a rotation event is written to the sink *before* the local chain
// commits, so an attacker who later controls the daemon cannot rewrite the
// rotation history alone. To actually deliver that guarantee a sink MUST be
// append-only and order/timestamp records itself (object-lock storage, a
// transparency log, a sequence-stamping SIEM ingest). FileLog here is a
// dependency-free *reference* adapter: it appends, but a plain file's
// immutability is only as strong as the filesystem permissions around it, so it
// is suitable for development and for fronting a medium that enforces
// append-only retention — not as a standalone tamper-proof anchor.
package anchor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// EventTypeRotation is the event type for key_rotated anchor records.
const EventTypeRotation = "rotation"

// Sink is an append-only external witness for daemon events.
//
// Implementations MUST be safe for concurrent use and MUST return an error
// unless the record was durably accepted — the caller treats a Write error as a
// reason to abort the local commit (anchor-first ordering).
type Sink interface {
	// Write appends a record for eventType carrying payload. payload is the
	// canonical JSON serialization of the event (for rotation, the signed
	// receipt) so any adapter produces byte-identical anchor content for the
	// same logical event.
	Write(eventType string, payload []byte) error

	// Close flushes and releases resources.
	Close() error
}

// Record is the line format FileLog appends: a self-describing envelope around
// the event payload. anchored_at is set by the sink, not the daemon, so the
// daemon does not choose the recorded time.
type Record struct {
	AnchoredAt string          `json:"anchored_at"`
	EventType  string          `json:"event_type"`
	Payload    json.RawMessage `json:"payload"`
}

// FileLog is an append-only newline-delimited-JSON Sink.
type FileLog struct {
	mu  sync.Mutex
	f   *os.File
	now func() time.Time
}

// OpenFileLog opens (creating if absent) an append-only log file at path with
// mode 0600. The file is opened O_APPEND so concurrent writers interleave whole
// records rather than overwriting one another.
func OpenFileLog(path string) (*FileLog, error) {
	if path == "" {
		return nil, errors.New("anchor: log path is required")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("anchor: open log %s: %w", path, err)
	}
	return &FileLog{f: f, now: time.Now}, nil
}

// Write appends one JSON record terminated by a newline and fsyncs so the
// record is durable before the caller proceeds to the local commit.
func (l *FileLog) Write(eventType string, payload []byte) error {
	if !json.Valid(payload) {
		return errors.New("anchor: payload is not valid JSON")
	}
	rec := Record{
		AnchoredAt: l.now().UTC().Format(time.RFC3339Nano),
		EventType:  eventType,
		Payload:    json.RawMessage(payload),
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("anchor: marshal record: %w", err)
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.f.Write(line); err != nil {
		return fmt.Errorf("anchor: write record: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("anchor: sync log: %w", err)
	}
	return nil
}

// Close closes the underlying file.
func (l *FileLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
