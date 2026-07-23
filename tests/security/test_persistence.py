"""Security tests for durable audit storage: tampering must fail closed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from atb.persistence import AuditIntegrityError, JsonlAuditStore


def _seed(path: Path) -> None:
    store = JsonlAuditStore.open(path)
    store.append({"subject": "agent:soc-analyst", "effect": "allow", "reason": "test"})
    store.append({"subject": "agent:soc-analyst", "effect": "deny", "reason": "test"})
    store.append({"subject": "agent:orchestrator", "effect": "escalate", "reason": "test"})


def test_clean_reload_verifies(tmp_path: Path) -> None:
    """A faithfully persisted chain reloads and verifies."""
    path = tmp_path / "audit.jsonl"
    _seed(path)
    store = JsonlAuditStore.open(path)
    assert len(store.log.records) == 3
    assert store.log.verify_chain() is True


def test_edited_record_fails_closed(tmp_path: Path) -> None:
    """Editing any persisted payload breaks the chain on reload."""
    path = tmp_path / "audit.jsonl"
    _seed(path)
    lines = path.read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["payload"]["effect"] = "allow"  # rewrite a deny into an allow
    lines[1] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditIntegrityError):
        JsonlAuditStore.open(path)


def test_deleted_record_fails_closed(tmp_path: Path) -> None:
    """Deleting a persisted record breaks the chain on reload."""
    path = tmp_path / "audit.jsonl"
    _seed(path)
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditIntegrityError):
        JsonlAuditStore.open(path)


def test_reordered_records_fail_closed(tmp_path: Path) -> None:
    """Reordering persisted records breaks the chain on reload."""
    path = tmp_path / "audit.jsonl"
    _seed(path)
    lines = path.read_text().splitlines()
    lines[0], lines[2] = lines[2], lines[0]
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditIntegrityError):
        JsonlAuditStore.open(path)
