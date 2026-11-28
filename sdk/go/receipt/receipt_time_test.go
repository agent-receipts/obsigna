package receipt

import (
	"testing"
	"time"
)

func TestParseReceiptTimeMs_MatchesTimeParse(t *testing.T) {
	for _, s := range []string{
		"1970-01-01T00:00:00Z",
		"1969-12-31T23:59:59.999Z",
		"0001-01-01T00:00:00Z",
		"9999-12-31T23:59:59.999999999Z",
		"2000-02-29T12:00:00Z",
		"2026-03-01T12:30:00.5Z",
		"2026-03-01T12:30:00.123456Z",
		"2026-03-01T13:30:00+01:00",
		"2026-03-01T07:30:00-05:00",
		"2026-03-01T12:30:00+23:59",
		"2026-03-01T12:30:00-00:00",
	} {
		want, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatalf("time.Parse(%q): %v", s, err)
		}
		got, ok := parseReceiptTimeMs(s)
		if !ok || got != want.UnixMilli() {
			t.Errorf("parseReceiptTimeMs(%q) = %d, %v; want %d", s, got, ok, want.UnixMilli())
		}
	}
}

func TestParseReceiptTimeMs_FloorsLongFractions(t *testing.T) {
	got, ok := parseReceiptTimeMs("1970-01-01T00:00:00.9999999999Z")
	if !ok || got != 999 {
		t.Errorf("got %d, %v; want 999", got, ok)
	}
}

func TestParseReceiptTimeMs_AcceptsLowercase(t *testing.T) {
	got, ok := parseReceiptTimeMs("1970-01-01t00:00:01z")
	if !ok || got != 1000 {
		t.Errorf("got %d, %v; want 1000", got, ok)
	}
}

func TestParseReceiptTimeMs_Rejects(t *testing.T) {
	for _, s := range []string{
		"",
		"2026-03-01",
		"2026-03-01T12:30:00",
		"2026-03-01 12:30:00Z",
		"2026-03-01T12:30Z",
		"2026-03-01T12:30:00+0100",
		"2026-03-01T12:30:00+01",
		"2026-03-01T12:30:00,5Z",
		"20260301T123000Z",
		"2026-02-30T12:30:00Z",
		"2026-02-29T12:30:00Z",
		"1900-02-29T12:30:00Z",
		"2026-13-01T12:30:00Z",
		"2026-00-01T12:30:00Z",
		"2026-03-00T12:30:00Z",
		"2026-03-01T24:00:00Z",
		"2026-03-01T12:60:00Z",
		"2026-03-01T12:29:60Z",
		"2026-03-01T12:30:00+24:00",
		"2026-03-01T12:30:00+01:60",
		"2026-03-01T12:30:00.Z",
		" 2026-03-01T12:30:00Z",
		"Sun, 01 Mar 2026 12:30:00 GMT",
		"２０２６-03-01T12:30:00Z",
	} {
		if got, ok := parseReceiptTimeMs(s); ok {
			t.Errorf("parseReceiptTimeMs(%q) = %d, want rejection", s, got)
		}
	}
}
