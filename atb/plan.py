"""Outbound plan declaration / divergence MVP (Day-01 D3).

An agent may declare the closed set of MCP tool names it intends to use.
Once a plan is declared for a subject, every subsequent tool call must be
in that set or the PEP routes through ``atb:plan.override`` (always
escalates to HITL). This is an allowlist MVP — not semantic intent.

Fail-closed: empty tool names rejected; unknown tools rejected at declare
time against the PEP tool map when provided; undeclared subjects are
unrestricted unless ``require_plan`` is True.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class PlanError(Exception):
    """Plan declaration or lookup failed fail-closed."""


@dataclass
class DeclaredPlan:
    """Closed allowlist of MCP tool names for one subject."""

    subject: str
    tools: frozenset[str]


@dataclass
class PlanBook:
    """In-memory plan register keyed by verified subject."""

    require_plan: bool = False
    _plans: dict[str, DeclaredPlan] = field(default_factory=dict)

    def declare(
        self, subject: str, tools: list[str], *, known_tools: frozenset[str] | None = None
    ) -> DeclaredPlan:
        """Replace the subject's plan with an explicit tool allowlist."""
        if not subject or not isinstance(subject, str):
            raise PlanError("subject required")
        cleaned: list[str] = []
        for tool in tools:
            if not isinstance(tool, str) or not tool or "\x00" in tool:
                raise PlanError("tool names must be non-empty strings")
            cleaned.append(tool)
        if not cleaned:
            raise PlanError("plan must name at least one tool")
        unique = frozenset(cleaned)
        if known_tools is not None:
            unknown = sorted(unique - known_tools)
            if unknown:
                raise PlanError(f"unknown tools in plan: {unknown}")
        plan = DeclaredPlan(subject=subject, tools=unique)
        self._plans[subject] = plan
        return plan

    def clear(self, subject: str) -> None:
        """Drop a declared plan (operator/reset path)."""
        self._plans.pop(subject, None)

    def check(self, subject: str, tool: str) -> str | None:
        """Return a closed reason token when the call diverges; else None."""
        plan = self._plans.get(subject)
        if plan is None:
            if self.require_plan:
                return "plan_required"
            return None
        if tool not in plan.tools:
            return "plan_divergence"
        return None
