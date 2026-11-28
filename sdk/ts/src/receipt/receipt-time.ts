/**
 * The RFC 3339 date-time grammar the grounded tier reads receipt times with
 * (spec v0.7.0 §7.9): `T` or `t`, `Z`/`z` or a numeric offset with minutes,
 * and an optional fraction. The Go, TypeScript and Python SDKs share this
 * exact grammar and the arithmetic below, rather than each language's own
 * time parser, so that all three read every string the same way. (`Date`
 * alone would accept local times without an offset and roll impossible dates
 * over.)
 */
const RECEIPT_TIME =
	/^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:([Zz])|([+-])(\d{2}):(\d{2}))$/;

function daysInMonth(year: number, month: number): number {
	if (month === 2) {
		return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
	}
	return month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31;
}

/** Days from 1970-01-01 to a proleptic Gregorian date (Hinnant's days_from_civil). */
function daysFromCivil(year: number, month: number, day: number): number {
	const y = month <= 2 ? year - 1 : year;
	const era = Math.floor(y / 400);
	const yoe = y - era * 400;
	const mp = (month + 9) % 12;
	const doy = Math.floor((153 * mp + 2) / 5) + day - 1;
	const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
	return era * 146097 + doe - 719468;
}

/**
 * Read an RFC 3339 date-time as milliseconds since the Unix epoch, flooring
 * any fraction. Returns `null` for a string outside the grammar, an impossible
 * date, an hour above 23, a minute or second above 59 (leap seconds included),
 * or an offset above 23:59.
 */
export function parseReceiptTimeMs(s: string | undefined): number | null {
	if (s === undefined) return null;
	const m = RECEIPT_TIME.exec(s);
	if (m === null) return null;
	const n = (i: number): number => Number(m[i]);
	const [year, month, day] = [n(1), n(2), n(3)];
	const [hour, minute, second] = [n(4), n(5), n(6)];
	if (
		month < 1 ||
		month > 12 ||
		day < 1 ||
		day > daysInMonth(year, month) ||
		hour > 23 ||
		minute > 59 ||
		second > 59
	) {
		return null;
	}
	const ms = Number(`${m[7] ?? ""}000`.slice(0, 3));

	let offsetMin = 0;
	if (m[8] === undefined) {
		const oh = n(10);
		const om = n(11);
		if (oh > 23 || om > 59) return null;
		offsetMin = (m[9] === "-" ? -1 : 1) * (oh * 60 + om);
	}

	const days = daysFromCivil(year, month, day);
	return (
		((days * 24 + hour) * 60 + minute - offsetMin) * 60_000 + second * 1000 + ms
	);
}
