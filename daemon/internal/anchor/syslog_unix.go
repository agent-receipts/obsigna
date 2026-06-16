//go:build unix

package anchor

import (
	"bytes"
	"fmt"
	"log/syslog"
	"sync"
	"time"
)

// SyslogLog is an append-only Sink that writes each record to the local
// syslog daemon. Syslog stands for "a different host/principal" in the
// checkpoint seam: on a host with remote syslog forwarding, the record leaves
// the agent's machine entirely, so truncating the local receipt store cannot
// reach it. This is the deliberately minimal second-domain backend named in
// the spike — it satisfies the same Sink contract as FileLog and GitLog;
// durability/retry tuning is out of scope (#487/#480/#533).
type SyslogLog struct {
	mu  sync.Mutex
	w   *syslog.Writer
	now func() time.Time
}

// OpenSyslog connects to the local syslog daemon under tag. An empty tag
// defaults to "obsigna-anchor". A dial failure (no syslog socket) is returned
// so a misconfigured sink fails loudly at open rather than silently dropping
// every checkpoint.
func OpenSyslog(tag string) (*SyslogLog, error) {
	if tag == "" {
		tag = "obsigna-anchor"
	}
	w, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_DAEMON, tag)
	if err != nil {
		return nil, fmt.Errorf("anchor: connect syslog: %w", err)
	}
	return &SyslogLog{w: w, now: time.Now}, nil
}

// Write emits one record as a single syslog message. recordLine produces a
// newline-terminated NDJSON line for file/git sinks; syslog frames each call as
// its own message, so the trailing newline is stripped — leaving it in can make
// some syslog backends split one record into multiple log entries. The record
// JSON is itself single-line (no interior newlines), so trimming the final byte
// is sufficient to keep one checkpoint == one syslog event.
func (s *SyslogLog) Write(eventType string, payload []byte) error {
	line, err := recordLine(s.now(), eventType, payload)
	if err != nil {
		return err
	}
	line = bytes.TrimRight(line, "\n")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(line); err != nil {
		return fmt.Errorf("anchor: write syslog: %w", err)
	}
	return nil
}

// Close closes the syslog connection.
func (s *SyslogLog) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil {
		return nil
	}
	err := s.w.Close()
	s.w = nil
	return err
}
