"""WalEmitter — at-least-once delivery via a write-ahead log (ADR-0020
§"At-least-once delivery and the WAL", supersedes ADR-0019 §O3).

Wraps an inner :class:`Emitter` (typically :class:`HttpEmitter` in ``sync``
mode) and records every receipt in a :class:`Wal` *before* attempting
delivery. The entry is cleared only once the inner emitter acknowledges
(``HttpEmitter`` returns on collector 201 or 409). If delivery raises the
entry survives, so the receipt can be re-delivered on the next
:meth:`WalEmitter.replay` (process restart) or :meth:`WalEmitter.flush`
(graceful shutdown).

Two backends ship:

- :class:`FileWal` — durable, for long-lived compute (EC2/VM/bare metal).
  Entries survive process restart; call :meth:`WalEmitter.replay` once at
  startup, before accepting new emissions, to drain anything left behind by a
  previous crash.
- :class:`MemoryWal` — in-memory only, for ephemeral compute (Lambda, Cloud
  Run, Fargate) where no persistent disk is available. Pending entries are
  lost on a hard timeout; on SIGTERM call :meth:`WalEmitter.flush` with a
  short deadline and, if it reports receipts still pending, emit a terminal
  ``agent_end { status: "interrupted" }`` receipt per ADR-0019 §P1.

Recommended ephemeral shutdown wiring (the SDK does NOT install signal
handlers — that is the caller's responsibility, matching the rest of the
emitter layer)::

    import signal

    def _on_sigterm(*_):
        remaining = wal_emitter.flush(2_000)
        if remaining > 0:
            # best-effort: sign + emit agent_end { status: "interrupted" }
            ...

    signal.signal(signal.SIGTERM, _on_sigterm)

The WAL is a local delivery aid, not part of the receipt protocol — its
on-disk format is private and is not required to match across SDKs (ADR-0019
§P1/§O3).
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from obsigna.receipt.types import AgentReceipt

if TYPE_CHECKING:
    from obsigna.emitters.types import Emitter

logger = logging.getLogger(__name__)


@runtime_checkable
class Wal(Protocol):
    """Backend that durably records receipts awaiting acknowledgement.

    Implementations must preserve append order in :meth:`list` and treat a
    repeated :meth:`append` of the same receipt ``id`` as an idempotent
    overwrite (it must not create a second entry or change the entry's
    position in the order).
    """

    def append(self, receipt: AgentReceipt) -> None:
        """Durably record a receipt as pending. Idempotent on ``receipt.id``."""
        raise NotImplementedError

    def remove(self, receipt_id: str) -> None:
        """Drop a receipt once acknowledged. No-op when the id is unknown."""
        raise NotImplementedError

    def list(self) -> list[AgentReceipt]:
        """Return pending receipts in append order."""
        raise NotImplementedError


@dataclass(frozen=True)
class WalDrainResult:
    """Outcome of a :meth:`WalEmitter.replay` or :meth:`WalEmitter.flush`."""

    delivered: int
    """Receipts acknowledged and cleared from the WAL during the drain."""
    remaining: int
    """Receipts still pending afterwards (delivery failed or deadline hit)."""


class MemoryWal:
    """In-memory write-ahead log.

    Entries live only for the lifetime of the process — suitable for ephemeral
    compute where persistent disk is not available. Receipt loss is possible
    on a hard crash or timeout (see :meth:`WalEmitter.flush`).
    """

    def __init__(self) -> None:
        # dict iteration order is insertion order, and re-assigning an existing
        # key keeps its original position — exactly the idempotent-overwrite
        # semantics the Wal contract requires.
        self._entries: dict[str, AgentReceipt] = {}
        self._lock = threading.Lock()

    def append(self, receipt: AgentReceipt) -> None:
        with self._lock:
            self._entries[receipt.id] = receipt

    def remove(self, receipt_id: str) -> None:
        with self._lock:
            self._entries.pop(receipt_id, None)

    def list(self) -> list[AgentReceipt]:
        with self._lock:
            return list(self._entries.values())


# Zero-padded width for the monotonic entry index encoded in each filename.
# 16 digits comfortably exceeds any realistic pending-entry count and keeps
# lexical sort order equal to numeric order.
_INDEX_WIDTH = 16
_ENTRY_RE = re.compile(r"^(\d{16})\.json$")


@dataclass
class _FileEntry:
    index: int
    receipt: AgentReceipt


class FileWal:
    """File-backed write-ahead log.

    Each pending receipt is one JSON file in ``dir``, named by a zero-padded
    monotonic index so that directory order equals append order. Writes are
    atomic (temp file + fsync + rename), so a crash mid-write never leaves a
    half-written entry that replay would choke on. Survives process restart:
    the directory is scanned lazily on first use and any leftover entries
    become the replay backlog.
    """

    def __init__(self, dir: str | os.PathLike[str]) -> None:
        self._dir = Path(dir)
        # id -> entry. Loaded lazily so construction stays cheap, matching the
        # `FileWal(dir)` ergonomics of the rest of the emitter layer.
        self._by_id: dict[str, _FileEntry] = {}
        self._max_index = 0
        self._loaded = False
        self._lock = threading.Lock()

    def append(self, receipt: AgentReceipt) -> None:
        with self._lock:
            self._ensure_loaded_locked()
            # Reuse the existing slot on idempotent re-append so the entry
            # keeps its position in the order; otherwise take the next index.
            existing = self._by_id.get(receipt.id)
            if existing is not None:
                index = existing.index
            else:
                self._max_index += 1
                index = self._max_index
            self._write_entry(index, receipt)
            self._by_id[receipt.id] = _FileEntry(index=index, receipt=receipt)

    def remove(self, receipt_id: str) -> None:
        with self._lock:
            self._ensure_loaded_locked()
            entry = self._by_id.pop(receipt_id, None)
            if entry is None:
                return
            self._unlink_quiet(entry.index)

    def list(self) -> list[AgentReceipt]:
        with self._lock:
            self._ensure_loaded_locked()
            ordered = sorted(self._by_id.values(), key=lambda e: e.index)
            return [e.receipt for e in ordered]

    # ------------------------------------------------------------------

    def _ensure_loaded_locked(self) -> None:
        # Caller must hold self._lock. Runs the directory scan exactly once.
        if self._loaded:
            return
        self._load()
        self._loaded = True

    def _load(self) -> None:
        # mode=0o700: keep the WAL directory owner-only so other local users
        # can't list pending receipts in a multi-user environment. Entry files
        # are written 0o600 in _write_entry.
        self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Sort by index so a duplicate id (possible if a crash interleaved an
        # idempotent rewrite) resolves to the highest-index file; the stale
        # lower-index file is unlinked.
        matched: list[tuple[int, str]] = []
        for entry in self._dir.iterdir():
            m = _ENTRY_RE.match(entry.name)
            if m is not None:
                matched.append((int(m.group(1)), entry.name))
        matched.sort(key=lambda x: x[0])

        for index, name in matched:
            if index > self._max_index:
                self._max_index = index
            try:
                raw = (self._dir / name).read_text(encoding="utf-8")
                receipt = AgentReceipt.model_validate_json(raw)
            except (OSError, ValueError):
                # A torn or unreadable entry (truncated JSON from a hard crash,
                # or a leftover that matched loosely) is dropped rather than
                # failing the whole load — the receipt was never acked, so at
                # worst the chain shows a gap, which the verifier surfaces.
                continue
            prior = self._by_id.get(receipt.id)
            if prior is not None:
                self._unlink_quiet(prior.index)
            self._by_id[receipt.id] = _FileEntry(index=index, receipt=receipt)

    def _write_entry(self, index: int, receipt: AgentReceipt) -> None:
        final_path = self._path(index)
        tmp_path = final_path.with_name(f"{final_path.name}.tmp")
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(receipt.model_dump_json(by_alias=True).encode("utf-8"))
                f.flush()
                # fsync the data before the rename so a crash can't expose a
                # rename-completed-but-data-lost entry.
                os.fsync(f.fileno())
        except BaseException:
            # Clean up the temp file on a failed write so it can't masquerade
            # as a torn entry on the next load.
            self._unlink_path_quiet(tmp_path)
            raise
        os.replace(tmp_path, final_path)

    def _unlink_quiet(self, index: int) -> None:
        self._unlink_path_quiet(self._path(index))

    def _unlink_path_quiet(self, path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            # A missing file is fine — the entry is gone either way.
            pass

    def _path(self, index: int) -> Path:
        return self._dir / f"{index:0{_INDEX_WIDTH}d}.json"


class WalEmitter:
    """At-least-once delivery on top of an inner emitter via a write-ahead log.

    See the module docstring for the durable vs in-memory backend choice and
    the recommended SIGTERM wiring.

    Parameters
    ----------
    inner:
        The emitter that performs the actual delivery (e.g. an HttpEmitter).
    wal:
        The write-ahead log backend (:class:`FileWal` or :class:`MemoryWal`).
    """

    def __init__(self, *, inner: Emitter, wal: Wal) -> None:
        self._inner = inner
        self._wal = wal

    def emit(self, receipt: AgentReceipt) -> None:
        """Write to the WAL, deliver via the inner emitter, clear on ack.

        If delivery raises, the entry is left in the WAL for later
        :meth:`replay`/:meth:`flush` and the error is re-raised to the caller.
        """
        self._wal.append(receipt)
        self._inner.emit(receipt)
        self._wal.remove(receipt.id)

    def replay(self) -> WalDrainResult:
        """Re-deliver every receipt left unacknowledged in the WAL.

        Call once at startup, before accepting new emissions, to drain a
        backlog left by a previous crash (durable backend) or to retry within
        a warm invocation. Each entry the inner emitter acknowledges is
        cleared; failures stay in the WAL and do not block the remaining
        entries. No deadline.
        """
        return self._drain(deadline_ms=None)

    def flush(self, deadline_ms: int = 2_000) -> int:
        """Best-effort delivery of all pending receipts, bounded by a deadline.

        Intended for graceful shutdown on SIGTERM in ephemeral compute.
        Returns the number of receipts still pending when the deadline elapses
        (0 means the WAL drained cleanly). A non-zero result is the caller's
        cue to emit ``agent_end { status: "interrupted" }`` per ADR-0019 §P1.

        Unlike the TypeScript reference — which races each delivery against a
        timer — a synchronous ``inner.emit`` cannot be cleanly cancelled
        mid-call (``HttpEmitter`` owns its own per-request timeout/retry
        budget). So the deadline is checked *between* deliveries: once
        ``time.monotonic()`` passes the deadline no further delivery is
        started. A single slow ``inner.emit`` already in flight may therefore
        overrun the deadline by up to one delivery.

        Parameters
        ----------
        deadline_ms:
            Wall-clock budget in milliseconds. Defaults to 2000.
        """
        return self._drain(deadline_ms=deadline_ms).remaining

    def pending(self) -> int:
        """Count of receipts currently awaiting acknowledgement."""
        return len(self._wal.list())

    # ------------------------------------------------------------------

    def _drain(self, *, deadline_ms: int | None) -> WalDrainResult:
        pending = self._wal.list()
        deadline = (
            None if deadline_ms is None else time.monotonic() + deadline_ms / 1000.0
        )
        delivered = 0

        for receipt in pending:
            # Check the deadline before starting each delivery. The in-flight
            # call can't be aborted (see flush docstring), so a late success
            # is harmless: it still clears its own WAL entry and a duplicate
            # POST is idempotent at the collector (409).
            if deadline is not None and time.monotonic() >= deadline:
                break
            try:
                self._inner.emit(receipt)
            except Exception as exc:  # noqa: BLE001 — one stuck receipt must not strand the rest
                logger.debug(
                    "WalEmitter: delivery failed during drain; leaving entry",
                    extra={"receipt_id": receipt.id, "err": str(exc)},
                )
                continue
            self._wal.remove(receipt.id)
            delivered += 1

        remaining = len(self._wal.list())
        return WalDrainResult(delivered=delivered, remaining=remaining)
