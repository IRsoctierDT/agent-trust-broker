"""Role-spec to scope bindings (ATB-02).

Bindings are the sole source the Identity Authority mints from: an agent
cannot request a scope outside its binding. No role binds ``net:egress`` —
external network access exists only as an escalation path.
"""

from __future__ import annotations

from dataclasses import dataclass

from atb.catalog import validate_bindings


@dataclass(frozen=True)
class RoleBinding:
    """Minimal scope set for one agent role."""

    role: str
    scopes: frozenset[str]
    delegatable: bool


_BINDINGS: tuple[RoleBinding, ...] = (
    RoleBinding(
        "agent:soc-analyst",
        frozenset({"tool:log.read", "rag:corpus.security.read", "agent:mitre-mapper.invoke"}),
        delegatable=False,
    ),
    RoleBinding("agent:mitre-mapper", frozenset({"rag:corpus.security.read"}), delegatable=False),
    RoleBinding(
        "agent:threat-intel",
        frozenset({"rag:corpus.security.read", "tool:log.read"}),
        delegatable=False,
    ),
    RoleBinding(
        "agent:incident-report",
        frozenset({"rag:corpus.security.read", "agent:kb.invoke", "tool:report.write"}),
        delegatable=False,
    ),
    RoleBinding("agent:kb", frozenset({"rag:corpus.security.read"}), delegatable=False),
    RoleBinding(
        "agent:knowledge-curator",
        frozenset({"rag:corpus.security.read", "rag:corpus.ingest"}),
        delegatable=False,
    ),
    RoleBinding(
        "agent:orchestrator",
        frozenset({"agent:*.invoke", "atb:identity.mint", "atb:policy.read"}),
        delegatable=True,
    ),
)

ROLE_BINDINGS: dict[str, RoleBinding] = {binding.role: binding for binding in _BINDINGS}

# Fail closed at import time: an uncataloged scope in a binding is a defect.
validate_bindings({role: binding.scopes for role, binding in ROLE_BINDINGS.items()})
