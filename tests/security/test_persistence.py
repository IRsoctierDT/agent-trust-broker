"""Security tests for durable audit storage: tampering must fail closed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from atb.persistence import AuditIntegrityError, JsonlAuditStore


def _seed(path: Path) -> None:
    store = JsonlAuditStore.open(path)
    try:
        store.append({"subject": "agent:soc-analyst", "effect": "allow", "reason": "test"})
        store.append({"subject": "agent:soc-analyst", "effect": "deny", "reason": "test"})
        store.append({"subject": "agent:orchestrator", "effect": "escalate", "reason": "test"})
    finally:
        store.close()


def test_clean_reload_verifies(tmp_path: Path) -> None:
    """A faithfully persisted chain reloads and verifies."""
    path = tmp_path / "audit.jsonl"
    _seed(path)
    store = JsonlAuditStore.open(path, for_append=False)
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


def test_truncated_final_line_fails_closed(tmp_path: Path) -> None:
    """A half-written tail (process death mid-append) is integrity failure."""
    path = tmp_path / "audit.jsonl"
    _seed(path)
    text = path.read_text()
    path.write_text(text[: len(text) // 2])  # simulate death mid-append
    with pytest.raises(AuditIntegrityError, match="malformed or truncated"):
        JsonlAuditStore.open(path)


def test_garbage_line_fails_closed(tmp_path: Path) -> None:
    """A non-JSON or schema-damaged line is integrity failure, not a traceback."""
    path = tmp_path / "audit.jsonl"
    _seed(path)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("not json at all\n")
    with pytest.raises(AuditIntegrityError, match="malformed or truncated"):
        JsonlAuditStore.open(path)
    path.write_text('{"decision_id": "ATB-DEC-000001"}\n')  # valid JSON, missing fields
    with pytest.raises(AuditIntegrityError, match="malformed or truncated"):
        JsonlAuditStore.open(path)


def test_concurrent_writer_lock_fails_closed(tmp_path: Path) -> None:
    """A second for_append writer is refused while the first holds the lock."""
    path = tmp_path / "audit.jsonl"
    writer = JsonlAuditStore.open(path)
    try:
        writer.append({"subject": "agent:soc-analyst", "effect": "allow", "reason": "held"})
        with pytest.raises(AuditIntegrityError, match="another writer holds the audit lock"):
            JsonlAuditStore.open(path)
        # Readers must not take the exclusive lock.
        reader = JsonlAuditStore.open(path, for_append=False)
        assert len(reader.records) == 1
    finally:
        writer.close()
    # After release, a new writer may open.
    again = JsonlAuditStore.open(path)
    try:
        again.append({"subject": "agent:soc-analyst", "effect": "deny", "reason": "after"})
        assert len(again.records) == 2
    finally:
        again.close()
