"""Policy Enforcement Point (ATB-03): inline tool-call mediation.

The PEP converts one MCP tool invocation into the ``(action, resource,
context)`` triple the ATB-01 policy engine evaluates, then makes the
decision binding: ``allow`` forwards to the downstream callable, ``deny``
refuses, ``escalate`` parks the call in the Milestone-2 escalation queue
until a named human approves it. The PEP holds no policy logic of its own;
every judgment is delegated to the engine and the ATB-02 catalog.

Security considerations (fail-closed by construction):

- **Closed-world tool map.** A tool without a mapping entry is refused
  (``unknown_tool``) and the refusal is chained; the map itself is validated
  at import against the ATB-02 catalog (mirrors T11). Secrets remain
  unrepresentable: no rule may name an uncataloged action.
- **Derivation never widens scope.** Name components are restricted to a
  conservative charset (no separators, no traversal), URL hosts are
  extracted with ``urllib.parse``, and filesystem paths are passed through
  *unrewritten*: the engine's T3 gate requires an already-canonical path and
  denies the rest as ``path_traversal`` security events — rewriting here
  would mask the attempt from the audit trail.
- **One decision, one record.** Every mediated call appends exactly one
  decision record: the engine's for mapped calls, a single chained
  enforcement refusal for unmappable ones. Escalating calls additionally
  append the Milestone-2 ``escalation_submitted`` lifecycle record,
  unchanged from M2.
- **No decision reuse (no TOCTOU gap).** The forward happens in the same
  call frame as the decision; nothing is cached across invocations.
- **Tokens and raw tool arguments are never written to the audit chain.**
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from atb.catalog import CATALOG
from atb.escalation import EscalationQueue
from atb.policy import Effect, PolicyEngine

REFUSAL = "enforcement_refusal"

# A single path-safe name component: no separators, no leading dot, and the
# explicit ".." reject below keeps even in-charset dotted runs conservative.
_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")

Deriver = Callable[[Mapping[str, Any]], str]
Downstream = Callable[[str, Mapping[str, Any]], object]


class DerivationError(Exception):
    """Invocation arguments cannot be mapped to a catalog resource."""


@dataclass(frozen=True)
class ToolInvocation:
    """One tool call as presented at the enforcement boundary (untrusted)."""

    token: str
    tool: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    context: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolRule:
    """Closed-world mapping from one MCP tool to its catalog action."""

    action: str
    derive: Deriver


@dataclass(frozen=True)
class MediationResult:
    """The PEP's structured answer to one mediated invocation."""

    forwarded: bool
    effect: Effect
    reason: str
    audit_ref: str
    security_event: bool
    pending_ref: str = ""
    result: object | None = None


def _require_str(arguments: Mapping[str, Any], key: str) -> str:
    """Extract a required string argument; fail closed on anything else."""
    value = arguments.get(key)
    if not isinstance(value, str) or not value or "\x00" in value:
        raise DerivationError(f"argument {key!r} must be a non-empty string")
    return value


def _component(key: str, template: str) -> Deriver:
    """Derive from a single path-safe name component (rejects separators/traversal)."""

    def derive(arguments: Mapping[str, Any]) -> str:
        value = _require_str(arguments, key)
        if not _COMPONENT.fullmatch(value) or ".." in value:
            raise DerivationError(f"argument {key!r} is not a safe name component")
        return template.format(value)

    return derive


def _fixed(resource: str) -> Deriver:
    """Derive a fixed resource regardless of arguments."""

    def derive(_: Mapping[str, Any]) -> str:
        return resource

    return derive


def _workspace_path(key: str) -> Deriver:
    """Pass a filesystem path through unrewritten (shape-validated only).

    The engine's T3 gate requires the presented path to already be canonical
    and denies everything else as a ``path_traversal`` security event.
    Normalizing on the caller's behalf would mask traversal attempts.
    """

    def derive(arguments: Mapping[str, Any]) -> str:
        return _require_str(arguments, key)

    return derive


def _url_host(key: str) -> Deriver:
    """Derive a reviewable egress summary from an http(s) URL argument.

    The resource is ``host:<scheme>://<hostname>:<port><path>`` — exactly
    what the approving human sees in ``atb pending``, and exactly what the
    one-shot approval is triple-bound to, so an approval cannot be spent on
    a different path, port, or scheme at the same host. Query, fragment,
    and userinfo are excluded by construction: they may carry secrets and
    must never enter the audit chain. An unparseable URL (including the
    stdlib's ``ValueError`` on malformed IPv6 / ports) fails closed as a
    derivation error — refused and chained, never an unhandled exception.
    """

    def derive(arguments: Mapping[str, Any]) -> str:
        raw = _require_str(arguments, key)
        try:
            parts = urlsplit(raw)
            hostname = parts.hostname
            port = parts.port
        except ValueError as exc:
            raise DerivationError(f"argument {key!r} is not a parseable URL") from exc
        if parts.scheme not in ("http", "https") or not hostname:
            raise DerivationError(f"argument {key!r} must be an http(s) URL with a host")
        effective_port = port if port is not None else (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        return f"host:{parts.scheme}://{hostname}:{effective_port}{path}"

    return derive


# Draft tool map v0.1 (ATB-03): the action column references only cataloged
# scopes; escalation is *not* re-declared here — it comes from the catalog,
# so the human gate cannot be compiled away by editing this table.
TOOL_MAP: dict[str, ToolRule] = {
    "log_read": ToolRule("tool:log.read", _component("name", "logs/lab/{}")),
    "report_write": ToolRule("tool:report.write", _component("name", "reports/{}")),
    "corpus_search": ToolRule("rag:corpus.security.read", _fixed("rag:corpus:security")),
    "corpus_ingest": ToolRule("rag:corpus.ingest", _component("corpus", "rag:corpus:{}")),
    "invoke_mitre_mapper": ToolRule("agent:mitre-mapper.invoke", _fixed("agent:mitre-mapper")),
    "invoke_threat_intel": ToolRule("agent:threat-intel.invoke", _fixed("agent:threat-intel")),
    "invoke_kb": ToolRule("agent:kb.invoke", _fixed("agent:kb")),
    "workspace_read": ToolRule("fs:workspace.read", _workspace_path("path")),
    "workspace_write": ToolRule("fs:workspace.write", _workspace_path("path")),
    "http_fetch": ToolRule("net:egress", _url_host("url")),
    "policy_read": ToolRule("atb:policy.read", _fixed("atb:policy")),
    "audit_read": ToolRule("atb:audit.read", _fixed("atb:audit")),
    "mint_sub_identity": ToolRule("atb:identity.mint", _fixed("atb:identity")),
}


def validate_tool_map(tool_map: Mapping[str, ToolRule]) -> None:
    """Fail closed on any rule that references an uncataloged action (mirrors T11)."""
    unknown = sorted({rule.action for rule in tool_map.values() if rule.action not in CATALOG})
    if unknown:
        raise ValueError(f"tool map references uncataloged actions: {unknown}")


# Fail closed at import time: an uncataloged action in the map is a defect.
validate_tool_map(TOOL_MAP)


def _validated_context(context: Mapping[str, str]) -> dict[str, str]:
    """Copy the caller's context; fail closed on non-string keys or values.

    The static type says ``str -> str``, but the boundary input is untrusted
    wire data — the runtime check is the control, not the annotation.
    """
    validated: dict[str, str] = {}
    for key, value in context.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise DerivationError("context keys and values must be strings")
        validated[key] = value
    return validated


@dataclass
class PolicyEnforcementPoint:
    """Inline reference monitor: derive -> decide -> forward/refuse/escalate."""

    engine: PolicyEngine
    queue: EscalationQueue
    downstream: Downstream
    tool_map: Mapping[str, ToolRule] = field(default_factory=lambda: dict(TOOL_MAP))

    def __post_init__(self) -> None:
        # A custom map is a governed change; it meets the same T11 bar.
        validate_tool_map(self.tool_map)

    def mediate(self, invocation: ToolInvocation) -> MediationResult:
        """Mediate one tool call; every path is audited and fails closed."""
        rule = self.tool_map.get(invocation.tool)
        if rule is None:
            return self._refuse(invocation.tool, "unknown_tool")
        try:
            resource = rule.derive(invocation.arguments)
            context = _validated_context(invocation.context)
        except DerivationError as exc:
            return self._refuse(invocation.tool, f"derivation_failed: {exc}")

        decision = self.engine.authorize(invocation.token, rule.action, resource, context)
        if decision.effect is Effect.ALLOW:
            # The authorization is already recorded; a downstream error is
            # surfaced unchanged, never swallowed and never retried.
            outcome = self.downstream(invocation.tool, dict(invocation.arguments))
            return MediationResult(
                forwarded=True,
                effect=Effect.ALLOW,
                reason=decision.reason,
                audit_ref=decision.audit.decision_id,
                security_event=decision.security_event,
                result=outcome,
            )
        if decision.effect is Effect.ESCALATE:
            pending_ref = self.queue.submit(decision)
            return MediationResult(
                forwarded=False,
                effect=Effect.ESCALATE,
                reason=decision.reason,
                audit_ref=decision.audit.decision_id,
                security_event=decision.security_event,
                pending_ref=pending_ref,
            )
        return MediationResult(
            forwarded=False,
            effect=Effect.DENY,
            reason=decision.reason,
            audit_ref=decision.audit.decision_id,
            security_event=decision.security_event,
        )

    def _refuse(self, tool: str, reason: str) -> MediationResult:
        """Refuse pre-decision; append the call's single chained record.

        Records the tool name and reason only — never the token, never raw
        arguments (they may carry sensitive payloads and are not needed as
        evidence). An unmappable call is always a security event: it is
        either a probe or a broken integration, and both need eyes.
        """
        record = self.engine.log.append(
            {
                "type": REFUSAL,
                "tool": tool,
                "effect": Effect.DENY.value,
                "reason": reason,
                "security_event": True,
            }
        )
        return MediationResult(
            forwarded=False,
            effect=Effect.DENY,
            reason=reason,
            audit_ref=record.decision_id,
            security_event=True,
        )
