package receipt

import (
	"regexp"
	"strconv"
)

// receiptTimePattern is the RFC 3339 date-time grammar the grounded tier reads
// receipt times with (spec v0.7.0 §7.9): T or t, Z/z or a numeric offset with
// minutes, and an optional fraction. The Go, TypeScript and Python SDKs share
// this exact grammar and the arithmetic below, rather than each language's own
// time parser, so that all three read every string the same way.
var receiptTimePattern = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:([Zz])|([+-])(\d{2}):(\d{2}))$`)

// parseReceiptTimeMs reads an RFC 3339 date-time as milliseconds since the
// Unix epoch, flooring any fraction. It reports false for a string outside the
// grammar, an impossible date, an hour above 23, a minute or second above 59
// (leap seconds included), or an offset above 23:59.
func parseReceiptTimeMs(s string) (int64, bool) {
	m := receiptTimePattern.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	num := func(v string) int64 {
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	year, month, day := num(m[1]), num(m[2]), num(m[3])
	hour, minute, second := num(m[4]), num(m[5]), num(m[6])
	if month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) ||
		hour > 23 || minute > 59 || second > 59 {
		return 0, false
	}

	frac := m[7] + "000"
	ms := num(frac[:3])

	var offsetMin int64
	if m[8] == "" {
		oh, om := num(m[10]), num(m[11])
		if oh > 23 || om > 59 {
			return 0, false
		}
		offsetMin = oh*60 + om
		if m[9] == "-" {
			offsetMin = -offsetMin
		}
	}

	days := daysFromCivil(year, month, day)
	return ((days*24+hour)*60+minute-offsetMin)*60_000 + second*1000 + ms, true
}

func daysInMonth(year, month int64) int64 {
	switch month {
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}

// daysFromCivil returns the number of days from 1970-01-01 to the given
// proleptic Gregorian date (Howard Hinnant's days_from_civil).
func daysFromCivil(year, month, day int64) int64 {
	if month <= 2 {
		year--
	}
	era := floorDiv(year, 400)
	yoe := year - era*400
	mp := (month + 9) % 12
	doy := (153*mp+2)/5 + day - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return era*146097 + doe - 719468
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}
