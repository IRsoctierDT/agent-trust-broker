"""ATB-02 conformance matrix T1-T12: one security test per trust boundary.

Every test asserts a denial, an escalation, or chain integrity — fail-closed
behavior is the property under test. A run that skips any row is a failed run.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from atb.audit import AuditLog
from atb.catalog import validate_bindings
from atb.identity import DelegationError, IdentityAuthority, VerificationError
from atb.policy import Effect, PolicyEngine


class Clock:
    """Deterministic, advanceable clock."""

    def __init__(self) -> None:
        self.current = datetime(2026, 7, 23, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


@pytest.fixture()
def clock() -> Clock:
    return Clock()


@pytest.fixture()
def authority(clock: Clock) -> IdentityAuthority:
    return IdentityAuthority(signing_key=b"test-only-key", now=clock)


@pytest.fixture()
def engine(authority: IdentityAuthority) -> PolicyEngine:
    return PolicyEngine(authority=authority, log=AuditLog())


def test_t1_unbound_tool_scope_denied(authority: IdentityAuthority, engine: PolicyEngine) -> None:
    """T1: soc-analyst requesting tool:report.write (not in its binding) is denied."""
    _, token = authority.mint("agent:soc-analyst")
    decision = engine.authorize(token, "tool:report.write", "reports/summary.md")
    assert decision.effect is Effect.DENY
    assert decision.reason == "scope_not_granted"
    assert decision.audit.payload["effect"] == "deny"


def test_t2_cross_corpus_retrieval_denied(
    authority: IdentityAuthority, engine: PolicyEngine
) -> None:
    """T2: qualifier is not prefix-inferred — legal corpus is a different scope."""
    _, token = authority.mint("agent:soc-analyst")
    decision = engine.authorize(token, "rag:corpus.security.read", "rag:corpus:legal")
    assert decision.effect is Effect.DENY
    assert decision.reason == "resource_out_of_scope"


def test_t3_path_traversal_denied_before_policy(
    authority: IdentityAuthority, engine: PolicyEngine
) -> None:
    """T3: traversal outside the canonicalized workspace denies pre-policy-match."""
    _, token = authority.mint("agent:soc-analyst")
    decision = engine.authorize(token, "fs:workspace.read", "workspace/../.env")
    assert decision.effect is Effect.DENY
    assert decision.reason == "path_traversal"
    assert decision.security_event is True


def test_t4_unverified_caller_denied(engine: PolicyEngine) -> None:
    """T4: invocation without a verifiable identity is denied."""
    decision = engine.authorize("ATB-ID-999999.forged", "agent:kb.invoke", "agent:kb")
    assert decision.effect is Effect.DENY
    assert decision.reason.startswith("identity_invalid")
    assert decision.security_event is True


@pytest.mark.parametrize(
    "role",
    [
        "agent:soc-analyst",
        "agent:mitre-mapper",
        "agent:threat-intel",
        "agent:incident-report",
        "agent:kb",
        "agent:knowledge-curator",
        "agent:orchestrator",
    ],
)
def test_t5_net_egress_always_escalates(
    authority: IdentityAuthority, engine: PolicyEngine, role: str
) -> None:
    """T5: net:egress yields escalate — never silent allow — for every role."""
    _, token = authority.mint(role)
    decision = engine.authorize(token, "net:egress", "host:exfil.example")
    assert decision.effect is Effect.ESCALATE
    assert "human_approval_required" in decision.reason


def test_t6_injected_out_of_scope_action_is_security_event(
    authority: IdentityAuthority, engine: PolicyEngine
) -> None:
    """T6: an injection-steered out-of-scope request is denied and flagged."""
    _, token = authority.mint("agent:soc-analyst")
    decision = engine.authorize(
        token,
        "rag:corpus.ingest",
        "rag:corpus:security",
        context={"origin": "llm_output"},
    )
    # Escalating scope not granted to this role: surfaces to a human, flagged.
    assert decision.effect is Effect.ESCALATE
    assert decision.security_event is True
    assert decision.audit.payload["context"]["origin"] == "llm_output"


def test_t7_delegation_must_attenuate(authority: IdentityAuthority) -> None:
    """T7: delegated scopes outside the target role's binding are rejected."""
    _, orch_token = authority.mint("agent:orchestrator")
    with pytest.raises(DelegationError, match="subset"):
        authority.mint_delegated(
            orch_token, "agent:mitre-mapper", frozenset({"tool:report.write"})
        )


def test_t8_delegated_identity_cannot_delegate(authority: IdentityAuthority) -> None:
    """T8: depth-1 — a delegated identity attempting to delegate is rejected."""
    _, orch_token = authority.mint("agent:orchestrator")
    _, delegated_token = authority.mint_delegated(
        orch_token, "agent:mitre-mapper", frozenset({"rag:corpus.security.read"})
    )
    with pytest.raises(DelegationError, match="depth-1"):
        authority.mint_delegated(
            delegated_token, "agent:kb", frozenset({"rag:corpus.security.read"})
        )


def test_t9_delegated_lifetime_nested(authority: IdentityAuthority) -> None:
    """T9: delegated not_after exceeding the delegator's is rejected."""
    _, orch_token = authority.mint("agent:orchestrator", ttl_seconds=60)
    with pytest.raises(DelegationError, match="lifetime"):
        authority.mint_delegated(
            orch_token,
            "agent:mitre-mapper",
            frozenset({"rag:corpus.security.read"}),
            ttl_seconds=3600,
        )


def test_t10_revocation_cascades(authority: IdentityAuthority) -> None:
    """T10: revoking the delegator invalidates the delegatee on next verify."""
    orch_identity, orch_token = authority.mint("agent:orchestrator")
    _, delegated_token = authority.mint_delegated(
        orch_token, "agent:mitre-mapper", frozenset({"rag:corpus.security.read"})
    )
    authority.revoke(orch_identity.identity_id)
    with pytest.raises(VerificationError, match="revoked"):
        authority.verify(delegated_token)


def test_t11_uncataloged_scope_fails_static_validation() -> None:
    """T11: a binding referencing a scope outside the catalog fails closed."""
    with pytest.raises(ValueError, match="uncataloged"):
        validate_bindings({"agent:rogue": frozenset({"secrets:vault.read"})})


def test_t12_every_decision_path_appends_one_chained_record(
    authority: IdentityAuthority, engine: PolicyEngine, clock: Clock
) -> None:
    """T12: allow, deny, and escalate each append exactly one chained record."""
    _, token = authority.mint("agent:soc-analyst")

    allow = engine.authorize(token, "tool:log.read", "logs/lab/auth.jsonl")
    deny = engine.authorize(token, "tool:report.write", "reports/x.md")
    escalate = engine.authorize(token, "net:egress", "host:example.org")
    clock.advance(3600)
    expired = engine.authorize(token, "tool:log.read", "logs/lab/auth.jsonl")

    assert allow.effect is Effect.ALLOW
    assert deny.effect is Effect.DENY
    assert escalate.effect is Effect.ESCALATE
    assert expired.effect is Effect.DENY

    assert len(engine.log.records) == 4
    assert engine.log.verify_chain() is True
    # Chain links: each record's prev_hash is the previous record's hash.
    hashes = [record.record_hash for record in engine.log.records]
    prevs = [record.prev_hash for record in engine.log.records]
    assert prevs[1:] == hashes[:-1]
