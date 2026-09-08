"""Append-only, hash-chained decision log (ATB-01, extended by ATB-05).

Every broker decision appends exactly one record before the result returns to
the caller. Records chain by hash, so deletion or edit of any record breaks
the chain and is detectable. Records hold references and reasons — never
secrets, tokens, or raw sensitive payloads.

ATB-05 adds two things without disturbing any of that:

- **Chained time.** A record may carry a record-level ``at`` (ISO-8601 UTC,
  millisecond precision) minted by an injected clock. When present it is part
  of the hashed canonical form, so editing a timestamp breaks verification;
  when absent the canonical form is exactly the historical three-key shape, so
  every pre-ATB-05 record replays byte-identically forever. Records are never
  retro-edited. The stamp is floored at the previous record's ``at`` so a
  stepped-back host clock cannot mint backdated records; chain position, not
  time, remains the ordering authority.
- **Segment seeds.** A log may be anchored mid-history: ``start_sequence``
  continues ATB-DEC numbering across a rotation and ``anchor_hash`` chains the
  first appended record to the sealed tip of the previous segment. Defaults
  reproduce the original genesis-anchored behavior exactly.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

GENESIS = "sha256:" + "0" * 64
_GENESIS = GENESIS  # historical alias


def utc_now() -> str:
    """Current UTC instant as ISO-8601 with millisecond precision and a Z."""
    moment = datetime.now(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


@runtime_checkable
class AuditSink(Protocol):
    """Anything the policy engine may write decisions to (memory or durable)."""

    def append(self, payload: dict[str, Any]) -> AuditRecord:
        """Append one record to the chain and return it."""
        ...  # pragma: no cover - protocol definition

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        """Immutable view of the chain."""
        ...  # pragma: no cover - protocol definition

    def verify_chain(self) -> bool:
        """Recompute the chain; False means tampering or truncation."""
        ...  # pragma: no cover - protocol definition


@dataclass(frozen=True)
class AuditRecord:
    """One immutable, chained decision record.

    ``at`` is None for records minted without a clock (every pre-ATB-05
    record, and the in-memory default): those hash in the historical
    three-key form and must keep doing so forever.
    """

    decision_id: str
    payload: dict[str, Any]
    prev_hash: str
    record_hash: str
    at: str | None = None


def digest(prev_hash: str, decision_id: str, payload: dict[str, Any], at: str | None = None) -> str:
    """Canonical record digest; ``at`` participates only when present."""
    canonical: dict[str, Any] = {
        "decision_id": decision_id,
        "payload": payload,
        "prev": prev_hash,
    }
    if at is not None:
        canonical["at"] = at
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    )


_digest = digest  # historical alias


@dataclass
class AuditLog:
    """In-memory append-only log. Persistence adapters wrap, never replace, this.

    ``now`` is None by default: no timestamps, byte-identical to pre-ATB-05
    behavior. ``start_sequence``/``anchor_hash`` seed a rotated segment so
    ATB-DEC numbering continues and the first record chains to the sealed tip.
    """

    _records: list[AuditRecord] = field(default_factory=list)
    _sequence: int = 0
    now: Callable[[], str] | None = None
    start_sequence: int = 0
    anchor_hash: str = GENESIS
    _last_at: str | None = None

    def __post_init__(self) -> None:
        if self.start_sequence < 0:
            raise ValueError("start_sequence must not be negative")
        self._sequence = max(self._sequence, self.start_sequence)

    def _stamp(self) -> str | None:
        """Mint the next timestamp, floored at the previous record's.

        A stepped-back wall clock cannot mint a backdated record: the floor
        makes stored time non-decreasing within a segment. Time remains
        telemetry — the chain's order is its position, not its stamps.
        """
        if self.now is None:
            return None
        current = self.now()
        if self._last_at is not None and current < self._last_at:
            current = self._last_at
        self._last_at = current
        return current

    def append(self, payload: dict[str, Any]) -> AuditRecord:
        """Append one record and return it with its chain hashes."""
        self._sequence += 1
        decision_id = f"ATB-DEC-{self._sequence:06d}"
        prev_hash = self._records[-1].record_hash if self._records else self.anchor_hash
        at = self._stamp()
        record = AuditRecord(
            decision_id=decision_id,
            payload=payload,
            prev_hash=prev_hash,
            record_hash=digest(prev_hash, decision_id, payload, at),
            at=at,
        )
        self._records.append(record)
        return record

    def adopt(self, record: AuditRecord) -> AuditRecord:
        """Replay a persisted record verbatim, verifying it re-derives.

        Used by the persistence layer on load: the stored ``at`` (or its
        absence) is preserved exactly rather than re-minted, so replay is
        byte-identical and historical hashes stay frozen.
        """
        self._sequence += 1
        expected_id = f"ATB-DEC-{self._sequence:06d}"
        prev_hash = self._records[-1].record_hash if self._records else self.anchor_hash
        recomputed = digest(prev_hash, record.decision_id, record.payload, record.at)
        if record.decision_id != expected_id or record.prev_hash != prev_hash:
            raise ValueError("record does not continue the chain")
        if record.record_hash != recomputed:
            raise ValueError("record hash does not match its contents")
        self._records.append(record)
        if record.at is not None:
            self._last_at = record.at
        return record

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        """Immutable view of the chain."""
        return tuple(self._records)

    @property
    def sequence(self) -> int:
        """Number of the last minted decision id (continues across segments)."""
        return self._sequence

    def verify_chain(self) -> bool:
        """Recompute the chain; False means tampering or truncation."""
        prev = self.anchor_hash
        for record in self._records:
            if record.prev_hash != prev:
                return False
            if digest(record.prev_hash, record.decision_id, record.payload, record.at) != (
                record.record_hash
            ):
                return False
            prev = record.record_hash
        return True
