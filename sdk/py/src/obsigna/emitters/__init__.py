"""Emitter abstraction for delivering signed receipts (ADR-0020)."""

from __future__ import annotations

from obsigna.emitters.buffering import BufferingEmitter
from obsigna.emitters.composite import CompositeEmitter
from obsigna.emitters.http import HttpEmitter
from obsigna.emitters.in_memory import InMemoryEmitter
from obsigna.emitters.types import (
    ApiKeyAuth,
    BearerAuth,
    BufferingFlushError,
    CompositeEmitError,
    EmitError,
    Emitter,
    HttpEmitterAuth,
    HttpEmitterConfig,
    MtlsAuth,
    NoAuth,
    RetryConfig,
)
from obsigna.emitters.wal import (
    FileWal,
    MemoryWal,
    Wal,
    WalDrainResult,
    WalEmitter,
)

__all__ = [
    "ApiKeyAuth",
    "BearerAuth",
    "BufferingEmitter",
    "BufferingFlushError",
    "CompositeEmitError",
    "CompositeEmitter",
    "EmitError",
    "Emitter",
    "FileWal",
    "HttpEmitter",
    "HttpEmitterAuth",
    "HttpEmitterConfig",
    "InMemoryEmitter",
    "MemoryWal",
    "MtlsAuth",
    "NoAuth",
    "RetryConfig",
    "Wal",
    "WalDrainResult",
    "WalEmitter",
]
