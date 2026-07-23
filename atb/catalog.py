"""Canonical scope catalog (ATB-02).

Closed-world: a scope not present here cannot be granted, requested, or
delegated. Escalating scopes always produce an ``escalate`` decision — the
human gate cannot be compiled away by a permissive policy or binding.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from fnmatch import fnmatchcase


class Risk(Enum):
    """Registered blast-radius tier for a scope."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ScopeSpec:
    """One grantable capability and the resource patterns it may touch."""

    name: str
    risk: Risk
    escalates: bool
    resource_patterns: tuple[str, ...]


_SPECS: tuple[ScopeSpec, ...] = (
    ScopeSpec("tool:log.read", Risk.LOW, False, ("logs/lab/*",)),
    ScopeSpec("tool:report.write", Risk.MEDIUM, False, ("reports/*",)),
    ScopeSpec("rag:corpus.security.read", Risk.LOW, False, ("rag:corpus:security",)),
    ScopeSpec("rag:corpus.ingest", Risk.HIGH, True, ("rag:corpus:*",)),
    ScopeSpec("agent:mitre-mapper.invoke", Risk.LOW, False, ("agent:mitre-mapper",)),
    ScopeSpec("agent:threat-intel.invoke", Risk.MEDIUM, False, ("agent:threat-intel",)),
    ScopeSpec("agent:kb.invoke", Risk.LOW, False, ("agent:kb",)),
    ScopeSpec("agent:*.invoke", Risk.HIGH, False, ("agent:*",)),
    ScopeSpec("fs:workspace.read", Risk.LOW, False, ("workspace/*",)),
    ScopeSpec("fs:workspace.write", Risk.MEDIUM, False, ("workspace/*",)),
    ScopeSpec("net:egress", Risk.CRITICAL, True, ("host:*",)),
    ScopeSpec("atb:policy.read", Risk.LOW, False, ("atb:policy",)),
    ScopeSpec("atb:audit.read", Risk.MEDIUM, False, ("atb:audit",)),
    ScopeSpec("atb:identity.mint", Risk.HIGH, False, ("atb:identity",)),
)

CATALOG: dict[str, ScopeSpec] = {spec.name: spec for spec in _SPECS}


def scope_grants(granted: frozenset[str], action: str) -> bool:
    """Return True when a granted scope covers the requested action.

    Exact match, or a wildcard scope (e.g. ``agent:*.invoke``) whose pattern
    matches the action. No prefix inference beyond explicit ``*``.
    """
    if action in granted:
        return True
    return any("*" in scope and fnmatchcase(action, scope) for scope in granted)


def resource_in_scope(action: str, resource: str) -> bool:
    """Return True when the resource matches the action's registered patterns."""
    spec = CATALOG.get(action)
    if spec is None:
        return False
    return any(fnmatchcase(resource, pattern) for pattern in spec.resource_patterns)


def validate_bindings(bindings: dict[str, frozenset[str]]) -> None:
    """Fail closed on any binding that references an uncataloged scope (T11)."""
    for role, scopes in bindings.items():
        unknown = sorted(scope for scope in scopes if scope not in CATALOG)
        if unknown:
            raise ValueError(f"binding for {role!r} references uncataloged scopes: {unknown}")
