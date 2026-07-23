"""Escalation queue (Milestone 2): human approve/deny in the audit chain.

Closes the loop on ``escalate`` decisions (AGENTS.md §5.1). The queue keeps
no state of its own: submissions, resolutions, and consumptions are records
in the same hash-chained audit sink the policy engine writes to, so the
queue is persistent wherever the chain is (``JsonlAuditStore``), replayable,
and tamper-evident by construction.

Lifecycle: an ``escalate`` decision is *submitted*; a named human *resolves*
it (approve or deny, with a reason); an approval may then be *consumed* —
exactly once, and only for the same (subject, action, resource) triple —
to convert one matching request into an ``allow``. Every step fails closed:
unknown references, duplicate submissions, double resolution, and mismatched
or reused approvals are rejected.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from atb.audit import AuditRecord, AuditSink
from atb.policy import Decision, Effect

SUBMITTED = "escalation_submitted"
RESOLVED = "escalation_resolved"
CONSUMED = "approval_consumed"


class EscalationError(Exception):
    """Escalation request violates the queue's fail-closed rules."""


@dataclass(frozen=True)
class PendingEscalation:
    """One escalation awaiting a human decision."""

    ref: str
    subject: str
    action: str
    resource: str
    reason: str


@dataclass
class EscalationQueue:
    """Derives pending/resolved/consumed state by replaying the audit chain."""

    log: AuditSink

    # ------------------------------------------------------------ replay
    def _replay(self) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], set[str]]:
        submitted: dict[str, dict[str, Any]] = {}
        resolved: dict[str, dict[str, Any]] = {}
        consumed: set[str] = set()
        for record in self.log.records:
            payload = record.payload
            kind = payload.get("type")
            ref = str(payload.get("ref", ""))
            if kind == SUBMITTED:
                submitted[ref] = payload
            elif kind == RESOLVED:
                resolved[ref] = payload
            elif kind == CONSUMED:
                consumed.add(ref)
        return submitted, resolved, consumed

    # ------------------------------------------------------------ submit
    def submit(self, decision: Decision) -> str:
        """Queue an ``escalate`` decision for human review; returns its ref.

        The ref is the originating decision's audit id, so the whole lifecycle
        chains back to the request that triggered it. Fail closed: only
        ``escalate`` decisions may be submitted, and only once each.
        """
        if decision.effect is not Effect.ESCALATE:
            raise EscalationError("only escalate decisions may be submitted")
        ref = decision.audit.decision_id
        submitted, _, _ = self._replay()
        if ref in submitted:
            raise EscalationError(f"escalation {ref!r} already submitted")
        payload = decision.audit.payload
        self.log.append(
            {
                "type": SUBMITTED,
                "ref": ref,
                "subject": str(payload.get("subject", "")),
                "action": str(payload.get("action", "")),
                "resource": str(payload.get("resource", "")),
                "reason": decision.reason,
            }
        )
        return ref

    # ------------------------------------------------------------ query
    def pending(self) -> tuple[PendingEscalation, ...]:
        """Escalations submitted but not yet resolved, in submission order."""
        submitted, resolved, _ = self._replay()
        return tuple(
            PendingEscalation(
                ref=ref,
                subject=str(entry.get("subject", "")),
                action=str(entry.get("action", "")),
                resource=str(entry.get("resource", "")),
                reason=str(entry.get("reason", "")),
            )
            for ref, entry in submitted.items()
            if ref not in resolved
        )

    def is_approved(self, ref: str) -> bool:
        """True only when a human resolved this escalation as approved."""
        _, resolved, _ = self._replay()
        entry = resolved.get(ref)
        return bool(entry is not None and entry.get("approved"))

    # ------------------------------------------------------------ resolve
    def resolve(self, ref: str, *, approver: str, approved: bool, reason: str) -> AuditRecord:
        """Record a named human's approve/deny for a pending escalation.

        Fail closed: the ref must be submitted and unresolved, and both the
        approver and the reason must be non-empty — an anonymous or
        unexplained approval is not a valid control action.
        """
        if not approver.strip():
            raise EscalationError("approver must be a non-empty name")
        if not reason.strip():
            raise EscalationError("resolution reason must be non-empty")
        submitted, resolved, _ = self._replay()
        if ref not in submitted:
            raise EscalationError(f"unknown escalation: {ref!r}")
        if ref in resolved:
            raise EscalationError(f"escalation {ref!r} already resolved")
        return self.log.append(
            {
                "type": RESOLVED,
                "ref": ref,
                "approver": approver.strip(),
                "approved": approved,
                "reason": reason.strip(),
            }
        )

    # ------------------------------------------------------------ consume
    def try_consume(self, ref: str, subject: str, action: str, resource: str) -> bool:
        """Spend an approval for one matching request; False on any mismatch.

        Single-use and triple-bound: the approval must exist, be approved,
        be unconsumed, and match the requesting (subject, action, resource)
        exactly. Consumption itself is appended to the chain, so a replay
        attempt is both refused and evidenced. Never raises — a False simply
        leaves the caller on the normal escalate path.
        """
        submitted, resolved, consumed = self._replay()
        entry = submitted.get(ref)
        resolution = resolved.get(ref)
        if entry is None or resolution is None:
            return False
        if not resolution.get("approved") or ref in consumed:
            return False
        if (entry.get("subject"), entry.get("action"), entry.get("resource")) != (
            subject,
            action,
            resource,
        ):
            return False
        self.log.append({"type": CONSUMED, "ref": ref})
        return True
