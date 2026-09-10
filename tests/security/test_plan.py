"""Unit tests for outbound plan declaration / divergence (Day-01 D3 MVP)."""

from __future__ import annotations

import pytest

from atb.audit import AuditLog
from atb.enforcement import PolicyEnforcementPoint, ToolInvocation
from atb.escalation import EscalationQueue
from atb.identity import IdentityAuthority
from atb.plan import PlanBook, PlanError
from atb.policy import Effect, PolicyEngine


def test_declare_rejects_empty_and_unknown() -> None:
    book = PlanBook()
    with pytest.raises(PlanError, match="at least one"):
        book.declare("agent:soc-analyst", [])
    with pytest.raises(PlanError, match="unknown tools"):
        book.declare("agent:soc-analyst", ["log_read", "nope"], known_tools=frozenset({"log_read"}))


def test_check_optional_until_declared_or_required() -> None:
    book = PlanBook()
    assert book.check("agent:soc-analyst", "log_read") is None
    book.declare("agent:soc-analyst", ["log_read"])
    assert book.check("agent:soc-analyst", "log_read") is None
    assert book.check("agent:soc-analyst", "http_fetch") == "plan_divergence"
    required = PlanBook(require_plan=True)
    assert required.check("agent:soc-analyst", "log_read") == "plan_required"


def test_pep_declare_and_divergence_escalates() -> None:
    authority = IdentityAuthority(signing_key=b"test-only-key")
    log = AuditLog()
    queue = EscalationQueue(log=log)
    engine = PolicyEngine(authority=authority, log=log, approvals=queue)
    pep = PolicyEnforcementPoint(
        engine=engine,
        queue=queue,
        downstream=lambda tool, args: f"ok:{tool}",
    )
    _, token = authority.mint("agent:soc-analyst")
    declared = pep.declare_plan(token, ["log_read"])
    assert declared.tools == frozenset({"log_read"})
    assert declared.audit_ref.startswith("ATB-DEC-")

    ok = pep.mediate(ToolInvocation(token=token, tool="log_read", arguments={"name": "auth.jsonl"}))
    assert ok.effect is Effect.ALLOW and ok.forwarded is True

    diverge = pep.mediate(
        ToolInvocation(token=token, tool="report_write", arguments={"name": "out.md"})
    )
    assert diverge.effect is Effect.ESCALATE
    assert diverge.reason == "plan_divergence"
    assert diverge.pending_ref.startswith("ATB-DEC-")
    assert diverge.security_event is True


def test_require_plan_refuses_without_declaration() -> None:
    from atb.plan import PlanBook

    authority = IdentityAuthority(signing_key=b"test-only-key")
    log = AuditLog()
    queue = EscalationQueue(log=log)
    engine = PolicyEngine(authority=authority, log=log, approvals=queue)
    pep = PolicyEnforcementPoint(
        engine=engine,
        queue=queue,
        downstream=lambda tool, args: f"ok:{tool}",
        plans=PlanBook(require_plan=True),
    )
    _, token = authority.mint("agent:soc-analyst")
    refused = pep.mediate(
        ToolInvocation(token=token, tool="log_read", arguments={"name": "auth.jsonl"})
    )
    assert refused.effect is Effect.DENY
    assert refused.reason == "plan_required"
    assert refused.forwarded is False
