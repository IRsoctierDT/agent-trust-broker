"""Append-only, hash-chained decision log (ATB-01).

Every broker decision appends exactly one record before the result returns to
the caller. Records chain by hash, so deletion or edit of any record breaks
the chain and is detectable. Records hold references and reasons — never
secrets, tokens, or raw sensitive payloads.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

_GENESIS = "sha256:" + "0" * 64


@dataclass(frozen=True)
class AuditRecord:
    """One immutable, chained decision record."""

    decision_id: str
    payload: dict[str, Any]
    prev_hash: str
    record_hash: str


def _digest(prev_hash: str, decision_id: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"decision_id": decision_id, "payload": payload, "prev": prev_hash},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class AuditLog:
    """In-memory append-only log. Persistence adapters wrap, never replace, this."""

    _records: list[AuditRecord] = field(default_factory=list)
    _sequence: int = 0

    def append(self, payload: dict[str, Any]) -> AuditRecord:
        """Append one record and return it with its chain hashes."""
        self._sequence += 1
        decision_id = f"ATB-DEC-{self._sequence:06d}"
        prev_hash = self._records[-1].record_hash if self._records else _GENESIS
        record = AuditRecord(
            decision_id=decision_id,
            payload=payload,
            prev_hash=prev_hash,
            record_hash=_digest(prev_hash, decision_id, payload),
        )
        self._records.append(record)
        return record

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        """Immutable view of the chain."""
        return tuple(self._records)

    def verify_chain(self) -> bool:
        """Recompute the chain; False means tampering or truncation."""
        prev = _GENESIS
        for record in self._records:
            if record.prev_hash != prev:
                return False
            if _digest(record.prev_hash, record.decision_id, record.payload) != record.record_hash:
                return False
            prev = record.record_hash
        return True
