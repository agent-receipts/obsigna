"""Reading receipt times for the grounded tier (spec v0.7.0 §7.9).

The Go, TypeScript and Python SDKs share this exact RFC 3339 grammar and the
arithmetic below, rather than each language's own time parser, so that all
three read every string the same way. (``datetime.fromisoformat`` alone would
accept ISO 8601 forms outside RFC 3339, such as ``T24:00`` or basic format.)
"""

from __future__ import annotations

import re

_RECEIPT_TIME = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?"
    r"(?:([Zz])|([+-])(\d{2}):(\d{2}))",
    re.ASCII,
)


def _days_in_month(year: int, month: int) -> int:
    if month == 2:  # noqa: PLR2004
        return 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28
    return 30 if month in (4, 6, 9, 11) else 31


def _days_from_civil(year: int, month: int, day: int) -> int:
    """Days from 1970-01-01 to a proleptic Gregorian date (Hinnant)."""
    y = year - 1 if month <= 2 else year  # noqa: PLR2004
    era = y // 400
    yoe = y - era * 400
    mp = (month + 9) % 12
    doy = (153 * mp + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def parse_receipt_time_ms(value: str | None) -> int | None:
    """Read an RFC 3339 date-time as milliseconds since the Unix epoch.

    Any fraction is floored. Returns ``None`` for a string outside the grammar
    (``T``/``t``, ``Z``/``z`` or a numeric offset with minutes, optional
    fraction), an impossible date, an hour above 23, a minute or second above
    59 (leap seconds included), or an offset above 23:59.
    """
    if not isinstance(value, str):
        return None
    m = _RECEIPT_TIME.fullmatch(value)
    if m is None:
        return None
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    if (
        not 1 <= month <= 12  # noqa: PLR2004
        or not 1 <= day <= _days_in_month(year, month)
        or hour > 23  # noqa: PLR2004
        or minute > 59  # noqa: PLR2004
        or second > 59  # noqa: PLR2004
    ):
        return None
    ms = int(((m.group(7) or "") + "000")[:3])

    offset_min = 0
    if m.group(8) is None:
        oh, om = int(m.group(10)), int(m.group(11))
        if oh > 23 or om > 59:  # noqa: PLR2004
            return None
        offset_min = (-1 if m.group(9) == "-" else 1) * (oh * 60 + om)

    days = _days_from_civil(year, month, day)
    return ((days * 24 + hour) * 60 + minute - offset_min) * 60_000 + second * 1000 + ms
