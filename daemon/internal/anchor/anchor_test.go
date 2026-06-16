package anchor

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFileLogAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anchor.log")
	l, err := OpenFileLog(path)
	if err != nil {
		t.Fatalf("OpenFileLog: %v", err)
	}
	if err := l.Write(EventTypeRotation, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if err := l.Write(EventTypeRotation, []byte(`{"b":2}`)); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var recs []Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("anchor line is not JSON: %v", err)
		}
		recs = append(recs, r)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs[0].EventType != EventTypeRotation {
		t.Errorf("event_type = %q, want %q", recs[0].EventType, EventTypeRotation)
	}
	if string(recs[0].Payload) != `{"a":1}` {
		t.Errorf("payload = %s, want {\"a\":1}", recs[0].Payload)
	}
	if recs[0].AnchoredAt == "" {
		t.Error("anchored_at is empty — the sink must stamp the time")
	}
}

func TestFileLogRejectsInvalidJSON(t *testing.T) {
	l, err := OpenFileLog(filepath.Join(t.TempDir(), "a.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if err := l.Write(EventTypeRotation, []byte("not json")); err == nil {
		t.Fatal("expected error for invalid JSON payload")
	}
}

func TestOpenFileLogRequiresPath(t *testing.T) {
	if _, err := OpenFileLog(""); err == nil {
		t.Fatal("expected error for empty path")
	}
}
