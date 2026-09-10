"""Durable audit storage: JSONL-backed, append-only, chain-verified on load.

Wraps — never replaces — the in-memory ``AuditLog``: every appended record is
written through to a JSONL file as a side effect of the decision itself
(PAT-0003: evidence is a by-product of running, not a separate step). On
reload, the chain is recomputed; any edit, deletion, or reordering of the
file fails closed with ``AuditIntegrityError``.

ATB-05 makes the file the **active segment** of a segment family: it may be
anchored to a sealed predecessor by an opening ``chain_checkpoint``, and its
archived siblings are guarded (stat only, never read on the hot path). Every
append is flushed and fsynced, so an acknowledged decision survives power
loss; a torn *unacknowledged* tail is recoverable through the gated
``trim_torn_tail`` path, while any malformed interior record stays a hard
failure.
"""

from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from atb.audit import AuditLog, AuditRecord
from atb.lifecycle import (
    LifecycleError,
    active_head,
    check_presence,
    discover_segments,
    is_sealed,
)


class AuditIntegrityError(Exception):
    """Persisted audit chain is broken; treat as an active security event."""


def _record_line(record: AuditRecord) -> str:
    """Canonical persisted form; ``at`` is written only when present."""
    body: dict[str, Any] = {
        "decision_id": record.decision_id,
        "payload": record.payload,
        "prev_hash": record.prev_hash,
        "record_hash": record.record_hash,
    }
    if record.at is not None:
        body["at"] = record.at
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


@dataclass
class JsonlAuditStore:
    """Append-through JSONL persistence for one active segment."""

    path: Path
    log: AuditLog
    sealed: bool = False
    _lock_fd: Any = None

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        now: Any = None,
        for_append: bool = True,
    ) -> JsonlAuditStore:
        """Load (or create) a store, verifying the persisted chain fail-closed.

        Bootstrap guard: a missing active file is created only in a clean
        directory. Beside segment artifacts or a rotation temp it is an
        integrity failure, not a first boot.
        """
        if not path.exists():
            siblings = discover_segments(path)
            temp = path.with_name(path.name + ".tmp-rotate")
            if siblings or temp.exists():
                raise AuditIntegrityError(
                    f"{path}: active segment missing beside segment artifacts — refusing to create"
                )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
            store = cls(path=path, log=AuditLog(now=now), sealed=False)
            if for_append:
                store._acquire_lock()
            return store

        persisted_records = cls._read_records(path)
        head = None
        if persisted_records:
            first_payload = persisted_records[0][1]["payload"]
            if isinstance(first_payload, dict) and first_payload.get("type") == "chain_checkpoint":
                head = first_payload
        log = cls._replay(path, persisted_records, head, now)
        records = log.records
        try:
            check_presence(path, active_head(records), records)
        except LifecycleError as exc:
            raise AuditIntegrityError(str(exc)) from exc
        if not log.verify_chain():
            raise AuditIntegrityError(f"{path}: chain verification failed after load")
        sealed = is_sealed(records)
        if sealed and for_append:
            raise AuditIntegrityError(
                f"{path}: rotation incomplete (segment is sealed) — run `atb rotate --execute`"
            )
        store = cls(path=path, log=log, sealed=sealed)
        if for_append:
            store._acquire_lock()
        return store

    # ------------------------------------------------------------ loading
    @staticmethod
    def _read_records(path: Path) -> list[tuple[int, dict[str, Any]]]:
        """Parse every line fail-closed; returns (line_number, body) pairs."""
        parsed: list[tuple[int, dict[str, Any]]] = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                body: dict[str, Any] = json.loads(line)
                body["payload"]
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                # A truncated tail (process death mid-append) or a
                # schema-damaged line is tampering/corruption evidence, not a
                # parse detail — same fail-closed error as a broken hash so
                # every caller already handles it. A torn *final* line is
                # recoverable through the gated trim_torn_tail path.
                raise AuditIntegrityError(
                    f"{path}:{line_number}: malformed or truncated record"
                ) from exc
            parsed.append((line_number, body))
        return parsed

    @staticmethod
    def _replay(
        path: Path,
        persisted: list[tuple[int, dict[str, Any]]],
        head: dict[str, Any] | None,
        now: Any,
    ) -> AuditLog:
        """Rebuild the log, demanding byte-identical ids, hashes, and stamps."""
        if head is not None:
            first = persisted[0][1]
            prev_seq = int(head["prev_segment_last_decision"].rsplit("-", 1)[1])
            expected_id = f"ATB-DEC-{prev_seq + 1:06d}"
            if first["decision_id"] != expected_id:
                raise AuditIntegrityError(
                    f"{path}:1: checkpoint id {first['decision_id']} does not continue "
                    f"{head['prev_segment_last_decision']}"
                )
            log = AuditLog(
                now=now,
                start_sequence=int(head["prev_segment_last_decision"].rsplit("-", 1)[1]),
                anchor_hash=str(first["prev_hash"]),
            )
        else:
            log = AuditLog(now=now)
        for line_number, body in persisted:
            record = AuditRecord(
                decision_id=str(body["decision_id"]),
                payload=body["payload"],
                prev_hash=str(body["prev_hash"]),
                record_hash=str(body["record_hash"]),
                at=body.get("at"),
            )
            try:
                log.adopt(record)
            except ValueError as exc:
                raise AuditIntegrityError(
                    f"{path}:{line_number}: persisted record does not match recomputed chain"
                ) from exc
        return log

    # ------------------------------------------------------------ sink API
    @property
    def records(self) -> tuple[AuditRecord, ...]:
        """Immutable view of the loaded chain (AuditSink protocol)."""
        return self.log.records

    def verify_chain(self) -> bool:
        """Verify the in-memory chain (AuditSink protocol)."""
        return self.log.verify_chain()

    def append(self, payload: dict[str, Any]) -> AuditRecord:
        """Append to the in-memory chain and write through durably.

        The write is flushed and fsynced before returning, so an
        acknowledged decision survives power loss.
        """
        if self.sealed:
            raise AuditIntegrityError(
                f"{self.path}: segment is sealed — run `atb rotate --execute`"
            )
        record = self.log.append(payload)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(_record_line(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record

    def _acquire_lock(self) -> None:
        lock_path = self.path.with_name(self.path.name + ".lock")
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise AuditIntegrityError(f"{self.path}: another writer holds the audit lock") from None
        self._lock_fd = fd

    def close(self) -> None:
        fd = self._lock_fd
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
                self._lock_fd = None


def trim_torn_tail(path: Path) -> str | None:
    """Gated recovery for a torn *unacknowledged* final line.

    Acts only when the sole defect is a trailing line that fails to parse
    while every preceding record replays green. Returns the discarded text,
    or None when there is nothing to trim. A malformed **interior** record is
    refused — history means acknowledged records, never a write fragment.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return None
    for index, line in enumerate(lines[:-1], 1):
        if not line.strip():
            continue
        try:
            json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditIntegrityError(
                f"{path}:{index}: malformed interior record — not a torn tail"
            ) from exc
    tail = lines[-1]
    try:
        json.loads(tail)
    except json.JSONDecodeError:
        path.write_text("".join(line + "\n" for line in lines[:-1]), encoding="utf-8")
        return tail
    return None
