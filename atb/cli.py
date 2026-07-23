"""Operator CLI: list, approve, and deny escalations without writing Python.

    atb pending                      # escalations awaiting a human decision
    atb approve ATB-DEC-000123 --reason "known safe intel feed"
    atb deny    ATB-DEC-000123 --reason "unknown destination"
    atb verify                       # verify the audit chain end to end

The audit chain path comes from ``--chain`` or the ``ATB_AUDIT_CHAIN``
environment variable. All writes go through the same ``JsonlAuditStore`` /
``EscalationQueue`` code the broker uses, so the chain is verified
fail-closed on open and resolutions obey the queue's rules (named approver,
required reason, no double resolution).

Security considerations: the approver defaults to the operating-system user
and is recorded in the chain — pass ``--approver`` to attribute explicitly.
The chain has one writer at a time by design; run this CLI when the broker
process is not actively appending.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from atb.escalation import EscalationError, EscalationQueue
from atb.persistence import AuditIntegrityError, JsonlAuditStore


def _resolve_chain_path(chain: str | None) -> Path:
    """Resolve the audit chain path from the flag or environment; fail closed."""
    raw = chain or os.environ.get("ATB_AUDIT_CHAIN", "")
    if not raw.strip():
        raise SystemExit("error: no audit chain — pass --chain or set ATB_AUDIT_CHAIN")
    path = Path(raw)
    if not path.is_file():
        raise SystemExit(f"error: no audit chain at {path}")
    return path


def _open_queue(chain: str | None) -> EscalationQueue:
    path = _resolve_chain_path(chain)
    try:
        store = JsonlAuditStore.open(path)
    except AuditIntegrityError as exc:
        raise SystemExit(f"error: audit chain FAILED verification — {exc}") from exc
    return EscalationQueue(log=store)


def _cmd_pending(args: argparse.Namespace) -> int:
    queue = _open_queue(args.chain)
    pending = queue.pending()
    if not pending:
        print("No escalations awaiting approval (chain verified).")
        return 0
    print(f"{'REF':<16} {'AGENT':<24} {'ACTION':<24} RESOURCE")
    for item in pending:
        print(f"{item.ref:<16} {item.subject:<24} {item.action:<24} {item.resource}")
    return 0


def _resolve(args: argparse.Namespace, *, approved: bool) -> int:
    queue = _open_queue(args.chain)
    approver = (args.approver or getpass.getuser()).strip()
    try:
        record = queue.resolve(args.ref, approver=approver, approved=approved, reason=args.reason)
    except EscalationError as exc:
        raise SystemExit(f"error: {exc}") from exc
    verdict = "APPROVED" if approved else "DENIED"
    print(f"{verdict} {args.ref} by {approver} — recorded as {record.decision_id}")
    if approved:
        print("The approval is one-shot and bound to the escalated (agent, action, resource).")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    queue = _open_queue(args.chain)  # open already verifies fail-closed
    log = queue.log
    print(f"Chain OK: {len(log.records)} records, {len(queue.pending())} pending escalation(s).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the ``atb`` argument parser (separated for testability)."""
    parser = argparse.ArgumentParser(
        prog="atb",
        description="IANUA Agent Trust Broker — operator commands for the escalation queue.",
    )
    parser.add_argument(
        "--chain",
        help="path to the audit chain JSONL (default: $ATB_AUDIT_CHAIN)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("pending", help="list escalations awaiting a human decision").set_defaults(
        func=_cmd_pending
    )

    for name, approved, help_text in (
        ("approve", True, "approve a pending escalation (one-shot, triple-bound)"),
        ("deny", False, "deny a pending escalation"),
    ):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("ref", help="escalation ref (e.g. ATB-DEC-000123)")
        cmd.add_argument("--reason", required=True, help="why (recorded in the chain)")
        cmd.add_argument("--approver", help="who (default: current OS user)")
        cmd.set_defaults(func=lambda a, _approved=approved: _resolve(a, approved=_approved))

    sub.add_parser("verify", help="verify the audit chain end to end").set_defaults(
        func=_cmd_verify
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
