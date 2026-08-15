"""ATB-03 enforcement conformance matrix E1-E6, plus derivation/TOCTOU hardening.

Every test asserts an *enforcement* outcome — forwarded vs. refused — not
merely a decision. A run that skips any row is a failed run. Escalating
calls append the decision record plus the Milestone-2 ``escalation_submitted``
lifecycle record; E6 counts both explicitly so "one decision, one record"
stays a checked invariant rather than an assumption.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from atb.audit import AuditLog
from atb.enforcement import (
    PolicyEnforcementPoint,
    ToolInvocation,
    ToolRule,
    validate_tool_map,
)
from atb.escalation import EscalationQueue
from atb.identity import IdentityAuthority
from atb.persistence import JsonlAuditStore
from atb.policy import Effect, PolicyEngine


class Clock:
    """Deterministic, advanceable clock."""

    def __init__(self) -> None:
        self.current = datetime(2026, 8, 14, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


class RecordingDownstream:
    """Records forwarded calls; the PEP must invoke this only on ALLOW."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, tool: str, arguments: Mapping[str, Any]) -> str:
        self.calls.append((tool, dict(arguments)))
        return f"ok:{tool}"


@pytest.fixture()
def clock() -> Clock:
    return Clock()


@pytest.fixture()
def authority(clock: Clock) -> IdentityAuthority:
    return IdentityAuthority(signing_key=b"test-only-key", now=clock)


@pytest.fixture()
def log() -> AuditLog:
    return AuditLog()


@pytest.fixture()
def queue(log: AuditLog) -> EscalationQueue:
    return EscalationQueue(log=log)


@pytest.fixture()
def engine(authority: IdentityAuthority, log: AuditLog, queue: EscalationQueue) -> PolicyEngine:
    return PolicyEngine(authority=authority, log=log, approvals=queue)


@pytest.fixture()
def downstream() -> RecordingDownstream:
    return RecordingDownstream()


@pytest.fixture()
def pep(
    engine: PolicyEngine, queue: EscalationQueue, downstream: RecordingDownstream
) -> PolicyEnforcementPoint:
    return PolicyEnforcementPoint(engine=engine, queue=queue, downstream=downstream)


# ------------------------------------------------------------------ E1
def test_e1_unmapped_tool_refused_downstream_never_called(
    authority: IdentityAuthority,
    pep: PolicyEnforcementPoint,
    downstream: RecordingDownstream,
    log: AuditLog,
) -> None:
    """E1: a tool absent from the map is refused; the refusal is chained."""
    _, token = authority.mint("agent:soc-analyst")
    result = pep.mediate(ToolInvocation(token=token, tool="drop_tables"))
    assert result.forwarded is False
    assert result.effect is Effect.DENY
    assert result.reason == "unknown_tool"
    assert result.security_event is True
    assert downstream.calls == []
    assert len(log.records) == 1
    assert log.records[-1].payload["type"] == "enforcement_refusal"
    assert log.records[-1].payload["tool"] == "drop_tables"
    assert log.verify_chain() is True


# ------------------------------------------------------------------ E2
def test_e2_in_scope_call_forwarded_exactly_once(
    authority: IdentityAuthority,
    pep: PolicyEnforcementPoint,
    downstream: RecordingDownstream,
    log: AuditLog,
) -> None:
    """E2: a mapped, in-scope call is authorized allow and forwarded once."""
    _, token = authority.mint("agent:soc-analyst")
    result = pep.mediate(
        ToolInvocation(token=token, tool="log_read", arguments={"name": "auth.jsonl"})
    )
    assert result.forwarded is True
    assert result.effect is Effect.ALLOW
    assert result.result == "ok:log_read"
    assert downstream.calls == [("log_read", {"name": "auth.jsonl"})]
    assert len(log.records) == 1
    assert log.records[-1].payload["resource"] == "logs/lab/auth.jsonl"
    assert log.verify_chain() is True


# ------------------------------------------------------------------ E3
def test_e3_out_of_scope_call_refused_security_event(
    authority: IdentityAuthority,
    pep: PolicyEnforcementPoint,
    downstream: RecordingDownstream,
) -> None:
    """E3 (T6 enforced): an injection-steered out-of-scope call never forwards."""
    _, token = authority.mint("agent:soc-analyst")
    result = pep.mediate(
        ToolInvocation(token=token, tool="report_write", arguments={"name": "exfil.md"})
    )
    assert result.forwarded is False
    assert result.effect is Effect.DENY
    assert result.reason == "scope_not_granted"
    assert result.security_event is True
    assert downstream.calls == []


def test_e3_traversal_name_component_refused_at_derivation(
    authority: IdentityAuthority,
    pep: PolicyEnforcementPoint,
    downstream: RecordingDownstream,
    log: AuditLog,
) -> None:
    """E3 hardening: a traversal-shaped name never even reaches the engine."""
    _, token = authority.mint("agent:soc-analyst")
    result = pep.mediate(
        ToolInvocation(token=token, tool="log_read", arguments={"name": "../../.env"})
    )
    assert result.forwarded is False
    assert result.reason.startswith("derivation_failed")
    assert result.security_event is True
    assert downstream.calls == []
    assert log.records[-1].payload["type"] == "enforcement_refusal"


def test_e3_workspace_traversal_denied_by_t3_gate(
    authority: IdentityAuthority,
    pep: PolicyEnforcementPoint,
    downstream: RecordingDownstream,
    log: AuditLog,
) -> None:
    """E3 hardening: fs paths pass through unrewritten so T3 fires as designed."""
    _, token = authority.mint("agent:soc-analyst")
    result = pep.mediate(
        ToolInvocation(token=token, tool="workspace_read", arguments={"path": "workspace/../.env"})
    )
    assert result.forwarded is False
    assert result.effect is Effect.DENY
    assert result.reason == "path_traversal"
    assert result.security_event is True
    assert downstream.calls == []
    assert log.records[-1].payload["reason"] == "path_traversal"


def test_e3_non_string_context_refused_at_derivation(
    authority: IdentityAuthority,
    pep: PolicyEnforcementPoint,
    downstream: RecordingDownstream,
) -> None:
    """E3 hardening: untrusted wire context must be str->str; anything else refuses."""
    _, token = authority.mint("agent:soc-analyst")
    hostile = cast(Mapping[str, str], {"approval_ref": 42})  # simulates raw wire data
    result = pep.mediate(
        ToolInvocation(
            token=token, tool="log_read", arguments={"name": "auth.jsonl"}, context=hostile
        )
    )
    assert result.forwarded is False
    assert result.reason.startswith("derivation_failed")
    assert downstream.calls == []


# ------------------------------------------------------------------ E4
def test_e4_escalation_holds_downstream_not_called(
    authority: IdentityAuthority,
    pep: PolicyEnforcementPoint,
    downstream: RecordingDownstream,
    queue: EscalationQueue,
) -> None:
    """E4 (T5): an escalating call is refused-until-approved with a pending ref."""
    _, token = authority.mint("agent:knowledge-curator")
    result = pep.mediate(
        ToolInvocation(token=token, tool="corpus_ingest", arguments={"corpus": "security"})
    )
    assert result.forwarded is False
    assert result.effect is Effect.ESCALATE
    assert result.pending_ref
    assert downstream.calls == []
    pending = queue.pending()
    assert [item.ref for item in pending] == [result.pending_ref]
    assert pending[0].action == "rag:corpus.ingest"
    assert pending[0].resource == "rag:corpus:security"


def test_e4_egress_always_escalates_even_unbound(
    authority: IdentityAuthority,
    pep: PolicyEnforcementPoint,
    downstream: RecordingDownstream,
) -> None:
    """E4 (T5): net egress escalates for every role; no role binds it."""
    _, token = authority.mint("agent:soc-analyst")
    result = pep.mediate(
        ToolInvocation(token=token, tool="http_fetch", arguments={"url": "https://exfil.example/x"})
    )
    assert result.forwarded is False
    assert result.effect is Effect.ESCALATE
    assert result.security_event is True  # scope not granted: injection-shaped
    assert downstream.calls == []


# ------------------------------------------------------------------ E5
def test_e5_human_approval_forwards_exactly_once(
    authority: IdentityAuthority,
    pep: PolicyEnforcementPoint,
    downstream: RecordingDownstream,
    queue: EscalationQueue,
) -> None:
    """E5: a valid approval_ref forwards exactly once; the approval is consumed."""
    _, token = authority.mint("agent:knowledge-curator")
    invocation = ToolInvocation(token=token, tool="corpus_ingest", arguments={"corpus": "security"})
    held = pep.mediate(invocation)
    assert held.effect is Effect.ESCALATE

    queue.resolve(held.pending_ref, approver="ivan", approved=True, reason="known safe lab feed")

    approved = ToolInvocation(
        token=token,
        tool="corpus_ingest",
        arguments={"corpus": "security"},
        context={"approval_ref": held.pending_ref},
    )
    first = pep.mediate(approved)
    assert first.forwarded is True
    assert first.effect is Effect.ALLOW
    assert first.reason == f"human_approved:{held.pending_ref}"
    assert len(downstream.calls) == 1

    replay = pep.mediate(approved)  # approval already consumed: back to escalate
    assert replay.forwarded is False
    assert replay.effect is Effect.ESCALATE
    assert replay.pending_ref != held.pending_ref
    assert len(downstream.calls) == 1


# ------------------------------------------------------------------ E6
def test_e6_exactly_one_decision_record_per_mediated_call(
    authority: IdentityAuthority,
    pep: PolicyEnforcementPoint,
    queue: EscalationQueue,
    log: AuditLog,
) -> None:
    """E6 (T12): every mediated call appends its one decision record; the
    escalating call adds exactly the one M2 submission record on top."""
    _, token = authority.mint("agent:soc-analyst")

    pep.mediate(ToolInvocation(token=token, tool="not_a_tool"))  # refusal record
    assert len(log.records) == 1
    pep.mediate(
        ToolInvocation(token=token, tool="log_read", arguments={"name": "auth.jsonl"})
    )  # allow
    assert len(log.records) == 2
    pep.mediate(
        ToolInvocation(token=token, tool="report_write", arguments={"name": "x.md"})
    )  # deny
    assert len(log.records) == 3
    pep.mediate(
        ToolInvocation(token=token, tool="http_fetch", arguments={"url": "http://example.org/"})
    )  # escalate: decision + escalation_submitted
    assert len(log.records) == 5
    assert log.records[-1].payload["type"] == "escalation_submitted"
    assert log.verify_chain() is True
    # Enforcement refusals are inert to the M2 queue replay.
    assert len(queue.pending()) == 1


# ------------------------------------------------------- TOCTOU / reuse
def test_no_decision_reuse_across_calls(
    authority: IdentityAuthority,
    engine: PolicyEngine,
    queue: EscalationQueue,
    log: AuditLog,
) -> None:
    """A decision binds to its own call frame; state changes bite the next call."""
    identity, token = authority.mint("agent:soc-analyst")

    def revoking_downstream(tool: str, arguments: Mapping[str, Any]) -> str:
        authority.revoke(identity.identity_id)  # sabotage mid-forward
        return f"ok:{tool}"

    pep = PolicyEnforcementPoint(engine=engine, queue=queue, downstream=revoking_downstream)
    invocation = ToolInvocation(token=token, tool="log_read", arguments={"name": "auth.jsonl"})

    first = pep.mediate(invocation)
    assert first.forwarded is True  # authorized before the sabotage landed

    second = pep.mediate(invocation)  # fresh decision: revocation now bites
    assert second.forwarded is False
    assert second.effect is Effect.DENY
    assert second.reason.startswith("identity_invalid")
    assert len(log.records) == 2  # one fresh decision record per call


# ------------------------------------------------------- map validation
def test_tool_map_with_uncataloged_action_fails_closed(
    engine: PolicyEngine, queue: EscalationQueue, downstream: RecordingDownstream
) -> None:
    """Mirrors T11: secrets stay unrepresentable — the map cannot name them."""
    rogue = {"steal_secrets": ToolRule("secrets:vault.read", lambda _: "secrets:vault")}
    with pytest.raises(ValueError, match="uncataloged"):
        validate_tool_map(rogue)
    with pytest.raises(ValueError, match="uncataloged"):
        PolicyEnforcementPoint(engine=engine, queue=queue, downstream=downstream, tool_map=rogue)


# ------------------------------------------------------- persistence
def test_enforcement_records_persist_and_reverify(
    tmp_path: Path, clock: Clock, authority: IdentityAuthority
) -> None:
    """PEP refusals and decisions round-trip the JSONL store fail-closed."""
    chain = tmp_path / "audit-chain.jsonl"
    store = JsonlAuditStore.open(chain)
    queue = EscalationQueue(log=store)
    engine = PolicyEngine(authority=authority, log=store, approvals=queue)
    downstream = RecordingDownstream()
    pep = PolicyEnforcementPoint(engine=engine, queue=queue, downstream=downstream)

    _, token = authority.mint("agent:soc-analyst")
    pep.mediate(ToolInvocation(token=token, tool="not_a_tool"))
    pep.mediate(ToolInvocation(token=token, tool="log_read", arguments={"name": "auth.jsonl"}))
    pep.mediate(
        ToolInvocation(token=token, tool="http_fetch", arguments={"url": "http://example.org/"})
    )

    reloaded = JsonlAuditStore.open(chain)  # fail-closed re-verification on load
    assert reloaded.verify_chain() is True
    assert len(reloaded.records) == len(store.records)
    assert len(EscalationQueue(log=reloaded).pending()) == 1
