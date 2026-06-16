"""Tests for the declared daemon-protocol range surface (ADR-0024 Gate #8)."""

from __future__ import annotations

from obsigna import DAEMON_PROTOCOL_RANGE, DaemonProtocolRange
from obsigna.daemon_emitter import SUPPORTED_FRAME_VERSION


def test_range_is_well_formed() -> None:
    assert DAEMON_PROTOCOL_RANGE.min <= DAEMON_PROTOCOL_RANGE.max


def test_range_is_immutable() -> None:
    # A frozen dataclass: callers cannot mutate the declared range at runtime.
    assert isinstance(DAEMON_PROTOCOL_RANGE, DaemonProtocolRange)


def test_range_covers_emitted_version() -> None:
    # While the SDK emits a single version, min == max == that version. A
    # mismatch would advertise a range that does not match the frames the SDK
    # puts on the wire, defeating Gate #8.
    emitted = int(SUPPORTED_FRAME_VERSION)
    assert DAEMON_PROTOCOL_RANGE.min == emitted
    assert DAEMON_PROTOCOL_RANGE.max == emitted
