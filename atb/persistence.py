"""Durable audit storage: JSONL-backed, append-only, chain-verified on load.

Wraps — never replaces — the in-memory ``AuditLog``: every appended record is
written through to a JSONL file as a side effect of the decision itself
(PAT-0003: evidence is a by-product of running, not a separate step). On
reload, the chain is recomputed; any edit, deletion, or reordering of the
file fails closed with ``AuditIntegrityError``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from atb.audit import AuditLog, AuditRecord


class AuditIntegrityError(Exception):
    """Persisted audit chain is broken; treat as an active security event."""


@dataclass
class JsonlAuditStore:
    """Append-through JSONL persistence for an ``AuditLog``."""

    path: Path
    log: AuditLog

    @classmethod
    def open(cls, path: Path) -> JsonlAuditStore:
        """Load (or create) a store, verifying the persisted chain fail-closed."""
        log = AuditLog()
        if path.exists():
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if not line.strip():
                    continue
                persisted: dict[str, Any] = json.loads(line)
                replayed = log.append(persisted["payload"])
                if (
                    replayed.decision_id != persisted["decision_id"]
                    or replayed.prev_hash != persisted["prev_hash"]
                    or replayed.record_hash != persisted["record_hash"]
                ):
                    raise AuditIntegrityError(
                        f"{path}:{line_number}: persisted record does not match recomputed chain"
                    )
            if not log.verify_chain():
                raise AuditIntegrityError(f"{path}: chain verification failed after load")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        return cls(path=path, log=log)

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        """Immutable view of the loaded chain (AuditSink protocol)."""
        return self.log.records

    def verify_chain(self) -> bool:
        """Verify the in-memory chain (AuditSink protocol)."""
        return self.log.verify_chain()

    def append(self, payload: dict[str, Any]) -> AuditRecord:
        """Append to the in-memory chain and write through to disk."""
        record = self.log.append(payload)
        line = json.dumps(
            {
                "decision_id": record.decision_id,
                "payload": record.payload,
                "prev_hash": record.prev_hash,
                "record_hash": record.record_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        return record
