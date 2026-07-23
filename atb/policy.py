"""Policy Engine (ATB-01): authorize(subject, action, resource) -> decision.

Pure, deterministic evaluation over the scope catalog and role bindings.
Order (fail-closed at every step): verify identity -> known scope -> path
canonicalization -> escalation flag -> scope granted -> resource in scope.
Every call appends exactly one hash-chained audit record before returning.
"""

from __future__ import annotations

import posixpath
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum

from atb.audit import AuditLog, AuditRecord, AuditSink
from atb.catalog import CATALOG, resource_in_scope, scope_grants
from atb.identity import IdentityAuthority, VerificationError


class Effect(Enum):
    """Decision outcomes. ``escalate`` is deny-until-a-human-approves."""

    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


@dataclass(frozen=True)
class Decision:
    """The engine's answer plus its audit trail entry."""

    effect: Effect
    reason: str
    security_event: bool
    audit: AuditRecord


@dataclass
class PolicyEngine:
    """Zero-Trust reference monitor for the IANUA agent fleet."""

    authority: IdentityAuthority
    log: AuditSink = field(default_factory=AuditLog)

    def authorize(
        self,
        token: str,
        action: str,
        resource: str,
        context: Mapping[str, str] | None = None,
    ) -> Decision:
        """Evaluate one privileged action request; always audited."""
        effect, reason, security_event, subject = self._evaluate(token, action, resource)
        record = self.log.append(
            {
                "subject": subject,
                "action": action,
                "resource": resource,
                "effect": effect.value,
                "reason": reason,
                "security_event": security_event,
                "context": dict(context or {}),
            }
        )
        return Decision(effect=effect, reason=reason, security_event=security_event, audit=record)

    def _evaluate(self, token: str, action: str, resource: str) -> tuple[Effect, str, bool, str]:
        try:
            identity = self.authority.verify(token)
        except VerificationError as exc:
            return Effect.DENY, f"identity_invalid: {exc}", True, "unverified"

        subject = identity.subject

        spec = CATALOG.get(action)
        if spec is None:
            return Effect.DENY, "unknown_scope", True, subject

        if action.startswith("fs:"):
            normalized = posixpath.normpath(resource)
            if normalized.startswith(("..", "/")) or normalized != resource.rstrip("/"):
                return Effect.DENY, "path_traversal", True, subject

        if spec.escalates:
            granted = scope_grants(identity.scopes, action)
            reason = "human_approval_required" + ("" if granted else "_scope_not_granted")
            return Effect.ESCALATE, reason, not granted, subject

        if not scope_grants(identity.scopes, action):
            return Effect.DENY, "scope_not_granted", True, subject

        if not resource_in_scope(action, resource):
            return Effect.DENY, "resource_out_of_scope", False, subject

        return Effect.ALLOW, "least_privilege_grant", False, subject
