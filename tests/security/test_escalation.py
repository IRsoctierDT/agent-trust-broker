"""Security tests for the escalation queue (Milestone 2).

The queue's every transition must fail closed, approvals must be one-shot
and triple-bound, and the entire lifecycle must live in the hash chain —
including surviving a persisted reload.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from atb.audit import AuditLog
from atb.escalation import EscalationError, EscalationQueue
from atb.identity import IdentityAuthority
from atb.persistence import JsonlAuditStore
from atb.policy import Effect, PolicyEngine


class Clock:
    def __init__(self) -> None:
        self.current = datetime(2026, 7, 23, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


@pytest.fixture()
def authority() -> IdentityAuthority:
    return IdentityAuthority(signing_key=b"test-only-key", now=Clock())


def _make(authority: IdentityAuthority) -> tuple[PolicyEngine, EscalationQueue, str]:
    log = AuditLog()
    queue = EscalationQueue(log=log)
    engine = PolicyEngine(authority=authority, log=log, approvals=queue)
    _, token = authority.mint("agent:soc-analyst")
    return engine, queue, token


def test_only_escalate_decisions_submit(authority: IdentityAuthority) -> None:
    engine, queue, token = _make(authority)
    allow = engine.authorize(token, "tool:log.read", "logs/lab/a.jsonl")
    with pytest.raises(EscalationError, match="only escalate"):
        queue.submit(allow)


def test_duplicate_submit_fails(authority: IdentityAuthority) -> None:
    engine, queue, token = _make(authority)
    escalate = engine.authorize(token, "net:egress", "host:intel.example")
    queue.submit(escalate)
    with pytest.raises(EscalationError, match="already submitted"):
        queue.submit(escalate)


def test_resolve_fails_closed(authority: IdentityAuthority) -> None:
    engine, queue, token = _make(authority)
    escalate = engine.authorize(token, "net:egress", "host:intel.example")
    ref = queue.submit(escalate)

    with pytest.raises(EscalationError, match="unknown"):
        queue.resolve("ATB-DEC-999999", approver="ivan", approved=True, reason="x")
    with pytest.raises(EscalationError, match="approver"):
        queue.resolve(ref, approver="  ", approved=True, reason="x")
    with pytest.raises(EscalationError, match="reason"):
        queue.resolve(ref, approver="ivan", approved=True, reason="  ")

    queue.resolve(ref, approver="ivan", approved=True, reason="known safe feed")
    with pytest.raises(EscalationError, match="already resolved"):
        queue.resolve(ref, approver="ivan", approved=False, reason="changed my mind")


def test_denied_resolution_never_consumes(authority: IdentityAuthority) -> None:
    engine, queue, token = _make(authority)
    escalate = engine.authorize(token, "net:egress", "host:exfil.example")
    ref = queue.submit(escalate)
    queue.resolve(ref, approver="ivan", approved=False, reason="unknown destination")
    assert queue.is_approved(ref) is False
    decision = engine.authorize(
        token, "net:egress", "host:exfil.example", context={"approval_ref": ref}
    )
    assert decision.effect is Effect.ESCALATE


def test_approval_closes_the_loop_once(authority: IdentityAuthority) -> None:
    """Approved -> exactly one matching request allows; the second escalates."""
    engine, queue, token = _make(authority)
    escalate = engine.authorize(token, "net:egress", "host:intel.example")
    ref = queue.submit(escalate)
    queue.resolve(ref, approver="ivan", approved=True, reason="known safe intel feed")

    first = engine.authorize(
        token, "net:egress", "host:intel.example", context={"approval_ref": ref}
    )
    assert first.effect is Effect.ALLOW
    assert first.reason == f"human_approved:{ref}"

    second = engine.authorize(
        token, "net:egress", "host:intel.example", context={"approval_ref": ref}
    )
    assert second.effect is Effect.ESCALATE  # single-use: replay refused


def test_approval_is_triple_bound(authority: IdentityAuthority) -> None:
    """An approval for one destination cannot authorize another."""
    engine, queue, token = _make(authority)
    escalate = engine.authorize(token, "net:egress", "host:intel.example")
    ref = queue.submit(escalate)
    queue.resolve(ref, approver="ivan", approved=True, reason="intel feed only")
    decision = engine.authorize(
        token, "net:egress", "host:exfil.example", context={"approval_ref": ref}
    )
    assert decision.effect is Effect.ESCALATE


def test_engine_without_queue_unchanged(authority: IdentityAuthority) -> None:
    engine = PolicyEngine(authority=authority)
    _, token = authority.mint("agent:soc-analyst")
    decision = engine.authorize(
        token, "net:egress", "host:x.example", context={"approval_ref": "ATB-DEC-000001"}
    )
    assert decision.effect is Effect.ESCALATE


def test_lifecycle_is_chained_and_persistent(authority: IdentityAuthority, tmp_path: Path) -> None:
    """Submit/resolve/consume live in the chain and survive a reload."""
    store = JsonlAuditStore.open(tmp_path / "audit.jsonl")
    queue = EscalationQueue(log=store)
    engine = PolicyEngine(authority=authority, log=store, approvals=queue)
    _, token = authority.mint("agent:soc-analyst")

    ref = queue.submit(engine.authorize(token, "net:egress", "host:intel.example"))
    assert [p.ref for p in queue.pending()] == [ref]

    # Reload from disk: pending state is rebuilt purely from the chain.
    reloaded_store = JsonlAuditStore.open(tmp_path / "audit.jsonl")
    reloaded_queue = EscalationQueue(log=reloaded_store)
    assert [p.ref for p in reloaded_queue.pending()] == [ref]

    reloaded_queue.resolve(ref, approver="ivan", approved=True, reason="known safe feed")
    assert reloaded_queue.pending() == ()
    assert reloaded_queue.is_approved(ref) is True

    engine2 = PolicyEngine(authority=authority, log=reloaded_store, approvals=reloaded_queue)
    _, token2 = authority.mint("agent:soc-analyst")
    allowed = engine2.authorize(
        token2, "net:egress", "host:intel.example", context={"approval_ref": ref}
    )
    assert allowed.effect is Effect.ALLOW
    assert reloaded_store.verify_chain() is True

    # The full lifecycle is on disk: submitted, resolved, consumed.
    kinds = [r.payload.get("type") for r in reloaded_store.records if "type" in r.payload]
    assert kinds == ["escalation_submitted", "escalation_resolved", "approval_consumed"]
