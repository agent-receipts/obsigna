"""Tests for the grounded tier's RFC 3339 reader (spec v0.7.0 §7.9)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from obsigna.receipt._receipt_time import parse_receipt_time_ms

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "value",
    [
        "1970-01-01T00:00:00Z",
        "1969-12-31T23:59:59.999Z",
        "0001-01-01T00:00:00Z",
        "9999-12-31T23:59:59.999Z",
        "2000-02-29T12:00:00Z",
        "2026-03-01T12:30:00.5Z",
        "2026-03-01T12:30:00.123456Z",
        "2026-03-01T13:30:00+01:00",
        "2026-03-01T07:30:00-05:00",
        "2026-03-01T12:30:00+23:59",
        "2026-03-01T12:30:00-00:00",
    ],
)
def test_matches_datetime(value: str) -> None:
    want = (datetime.fromisoformat(value) - _EPOCH) // timedelta(milliseconds=1)
    assert parse_receipt_time_ms(value) == want


def test_floors_long_fractions() -> None:
    assert parse_receipt_time_ms("1970-01-01T00:00:00.9999999999Z") == 999


def test_accepts_lowercase() -> None:
    assert parse_receipt_time_ms("1970-01-01t00:00:01z") == 1000


@pytest.mark.parametrize(
    "value",
    [
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
    ],
)
def test_rejects(value: str) -> None:
    assert parse_receipt_time_ms(value) is None
