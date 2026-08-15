"""Operator CLI: list, resolve, and review escalations without writing Python.

    atb pending                      # escalations awaiting a human decision
    atb show ATB-DEC-000123          # metadata-first triage of one record
    atb approve ATB-DEC-000123 --reason "known safe intel feed"
    atb deny    ATB-DEC-000123 --reason "unknown destination"
    atb verify                       # verify the audit chain end to end
    atb screen-stats                 # per-rule screening telemetry (ATB-04)
    atb quarantine show ATB-DEC-000123   # escaped, verified payload view
    atb quarantine purge                 # delete purge-eligible blobs

The audit chain path comes from ``--chain`` or the ``ATB_AUDIT_CHAIN``
environment variable; the quarantine directory from ``--dir`` or
``ATB_QUARANTINE_DIR``. All writes go through the same ``JsonlAuditStore``
/ ``EscalationQueue`` code the broker uses, so the chain is verified
fail-closed on open and resolutions obey the queue's rules (named approver,
required reason, no double resolution).

Security considerations: the approver defaults to the operating-system user
and is recorded in the chain — pass ``--approver`` to attribute explicitly.
The chain has one writer at a time by design: **stop the broker/gateway
process before approving or denying, then restart it** — it replays the
chain (including the resolution) on open. Appending from two processes
forks the chain, after which every open fails closed. Quarantined payloads
are hypothesized attacker text: ``quarantine show`` re-verifies the digest
and renders control characters escaped so the terminal cannot be steered;
``quarantine purge`` deletes only blobs with no pending or
approved-but-unconsumed escalation, after an explicit prompt.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from atb.audit import AuditRecord
from atb.escalation import CONSUMED, RESOLVED, SUBMITTED, EscalationError, EscalationQueue
from atb.persistence import AuditIntegrityError, JsonlAuditStore
from atb.screening import RELEASE_ACTION, FileQuarantineStore, ResponseScreener


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


# ------------------------------------------------------------ ATB-04 review
def _find_record(queue: EscalationQueue, ref: str) -> AuditRecord:
    """Locate one chained record by decision id; fail closed when absent."""
    for record in queue.log.records:
        if record.decision_id == ref:
            return record
    raise SystemExit(f"error: no chained record {ref}")


def _resolve_quarantine_dir(directory: str | None) -> Path:
    """Resolve the quarantine directory from the flag or environment."""
    raw = directory or os.environ.get("ATB_QUARANTINE_DIR", "")
    if not raw.strip():
        raise SystemExit("error: no quarantine dir — pass --dir or set ATB_QUARANTINE_DIR")
    path = Path(raw)
    if not path.is_dir():
        raise SystemExit(f"error: no quarantine directory at {path}")
    return path


def _release_lifecycle(
    queue: EscalationQueue,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], set[str]]:
    """Replay release-scope escalation lifecycle state from the chain."""
    submitted: dict[str, dict[str, Any]] = {}
    resolved: dict[str, dict[str, Any]] = {}
    consumed: set[str] = set()
    for record in queue.log.records:
        payload = record.payload
        kind = payload.get("type")
        ref = str(payload.get("ref", ""))
        if kind == SUBMITTED and str(payload.get("action", "")) == RELEASE_ACTION:
            submitted[ref] = payload
        elif kind == RESOLVED:
            resolved[ref] = payload
        elif kind == CONSUMED:
            consumed.add(ref)
    return submitted, resolved, consumed


def _cmd_show(args: argparse.Namespace) -> int:
    """Metadata-first triage: print one record's evidence, never a payload."""
    queue = _open_queue(args.chain)
    payload = _find_record(queue, args.ref).payload
    context = payload.get("context") or {}
    # Keys are code-defined labels; values (resource, reason, context) are
    # attacker-influenced, so escape them before printing (no terminal steering).
    for key in sorted(k for k in payload if k != "context"):
        print(f"{key}: {_escape_untrusted(str(payload[key]))}")
    for key in sorted(context):
        print(f"context.{key}: {_escape_untrusted(str(context[key]))}")
    if str(payload.get("action", "")) == RELEASE_ACTION:
        installed = {rule.rule_id: rule for rule in ResponseScreener().rules}
        for rule_id in filter(None, str(context.get("screen_rules", "")).split(",")):
            rule = installed.get(rule_id)
            description = rule.description if rule else "(not in installed ruleset)"
            print(f"rule {rule_id}: {description}")
        submitted, resolved, consumed = _release_lifecycle(queue)
        resource = str(payload.get("resource", ""))
        refs = [ref for ref, entry in submitted.items() if entry.get("resource") == resource]
        released = sum(1 for ref in refs if resolved.get(ref, {}).get("approved"))
        denied = sum(1 for ref in refs if ref in resolved and not resolved[ref].get("approved"))
        print(
            f"prior adjudication for this digest: {released} released, "
            f"{denied} denied, {len(refs) - released - denied} open"
        )
    return 0


def _escape_untrusted(text: str) -> str:
    """Render attacker-controlled text with controls escaped (no terminal steering)."""
    return "".join(
        ch if ch == "\n" or (ch.isprintable() and not ch.isspace()) or ch == " " else repr(ch)[1:-1]
        for ch in text
    )


def _cmd_quarantine_show(args: argparse.Namespace) -> int:
    """Opt-in payload view: integrity-verified, escaped, skew-warned."""
    queue = _open_queue(args.chain)
    payload = _find_record(queue, args.ref).payload
    resource = str(payload.get("resource", ""))
    if not resource.startswith("quarantine:"):
        raise SystemExit(f"error: {args.ref} is not a release decision")
    digest = resource.removeprefix("quarantine:")
    store = FileQuarantineStore(root=_resolve_quarantine_dir(args.dir))
    blob = store.get(digest)
    if blob is None:
        raise SystemExit(f"error: quarantine blob missing or corrupt for {digest}")
    context = payload.get("context") or {}
    # Size the review screener to the blob so the re-scan always covers the
    # exact bytes the operator is about to read — the live scan cap is a
    # cost bound for mediation, not a limit on a one-off human review.
    review = ResponseScreener(max_scan_bytes=max(1, len(blob)), max_blob_bytes=max(1, len(blob)))
    if (
        str(context.get("screen_ruleset", "")) != review.version
        or str(context.get("screen_rules_digest", "")) != review.rules_digest
    ):
        print(
            "WARNING: installed ruleset differs from the chained evidence "
            f"(installed {review.version}, chained "
            f"{context.get('screen_ruleset', '?')}) — displayed matches may diverge."
        )
    print(f"UNTRUSTED CONTENT — withheld by screening; digest {digest}; {len(blob)} bytes")
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        print("(binary content — not rendered; release delivers the exact bytes)")
        return 0
    verdict = review.screen(text)
    matches = ",".join(verdict.rule_ids) or "(none)"
    print(
        f"installed-ruleset re-scan: cause={verdict.cause}; matches={matches}; "
        f"invisible characters: {verdict.invisible_count}"
    )
    print("-" * 72)
    print(_escape_untrusted(text))
    return 0


def _cmd_screen_stats(args: argparse.Namespace) -> int:
    """Chain-derived per-rule telemetry: hits, releases, denies, release rate."""
    queue = _open_queue(args.chain)
    evidence: dict[str, list[str]] = {}
    hits: Counter[str] = Counter()
    agent_initiated = 0
    for record in queue.log.records:
        payload = record.payload
        if payload.get("action") != RELEASE_ACTION or payload.get("effect") != "escalate":
            continue
        context = payload.get("context") or {}
        cause = context.get("screen_cause")
        if not cause:
            # A release escalation with no screening evidence is an
            # agent-initiated release retry (deny-until-approved), not a
            # screening hit — the reserved screen_* namespace guarantees the
            # distinction. Count it separately, never against a rule.
            agent_initiated += 1
            continue
        rule_ids = [r for r in str(context.get("screen_rules", "")).split(",") if r]
        if not rule_ids:
            rule_ids = [f"cause:{cause}"]  # oversize / undecodable: no rule id
        evidence[record.decision_id] = rule_ids
        hits.update(rule_ids)
    if not hits:
        print("No screening activity in the chain.")
        if agent_initiated:
            print(f"agent-initiated release attempts: {agent_initiated}")
        return 0
    submitted, resolved, _ = _release_lifecycle(queue)
    released: Counter[str] = Counter()
    denied: Counter[str] = Counter()
    unresolved: Counter[str] = Counter()
    for ref in submitted:
        resolution = resolved.get(ref)
        bucket = (
            unresolved if resolution is None else released if resolution.get("approved") else denied
        )
        bucket.update(evidence.get(ref, []))
    print(f"{'RULE':<24} {'HITS':>5} {'RELEASED':>9} {'DENIED':>7} {'OPEN':>5}  RELEASE-RATE")
    for rule_id in sorted(hits):
        adjudicated = released[rule_id] + denied[rule_id]
        rate = f"{released[rule_id] / adjudicated:.0%}" if adjudicated else "-"
        print(
            f"{rule_id:<24} {hits[rule_id]:>5} {released[rule_id]:>9} "
            f"{denied[rule_id]:>7} {unresolved[rule_id]:>5}  {rate}"
        )
    if agent_initiated:
        print(f"agent-initiated release attempts (not screening hits): {agent_initiated}")
    return 0


def _cmd_quarantine_purge(args: argparse.Namespace) -> int:
    """Delete purge-eligible blobs only, after an explicit prompt.

    A blob is purge-eligible only when no escalation referencing its digest
    is pending or approved-but-unconsumed; orphan blobs and temp files are
    eligible (the flag remains provable from the chain).
    """
    queue = _open_queue(args.chain)
    root = _resolve_quarantine_dir(args.dir)
    submitted, resolved, consumed = _release_lifecycle(queue)
    blocked: set[str] = set()
    for ref, entry in submitted.items():
        resolution = resolved.get(ref)
        if resolution is None or (resolution.get("approved") and ref not in consumed):
            blocked.add(str(entry.get("resource", "")).removeprefix("quarantine:"))
    candidates = [
        blob_file
        for blob_file in sorted(root.iterdir())
        if blob_file.is_file()
        and (
            blob_file.name.startswith(".tmp-")
            or (
                re.fullmatch(r"[0-9a-f]{64}", blob_file.name)
                and f"sha256:{blob_file.name}" not in blocked
            )
        )
    ]
    if not candidates:
        print("Nothing purge-eligible.")
        return 0
    print(f"Purge-eligible under {root}:")
    for blob_file in candidates:
        print(f"  {blob_file.name}")
    answer = input(f"Delete {len(candidates)} file(s)? [y/N] ").strip().lower()
    if answer != "y":
        print("Aborted; nothing deleted.")
        return 1
    for blob_file in candidates:
        blob_file.unlink()
    print(f"Deleted {len(candidates)} file(s).")
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

    show = sub.add_parser("show", help="metadata-first triage of one chained record")
    show.add_argument("ref", help="decision id (e.g. ATB-DEC-000123)")
    show.set_defaults(func=_cmd_show)

    sub.add_parser(
        "screen-stats", help="per-rule screening telemetry derived from the chain"
    ).set_defaults(func=_cmd_screen_stats)

    quarantine = sub.add_parser(
        "quarantine", help="inspect or purge quarantined response payloads (ATB-04)"
    )
    quarantine.add_argument("--dir", help="quarantine directory (default: $ATB_QUARANTINE_DIR)")
    qsub = quarantine.add_subparsers(dest="quarantine_command", required=True)
    qshow = qsub.add_parser("show", help="escaped, integrity-verified payload view")
    qshow.add_argument("ref", help="release decision id (e.g. ATB-DEC-000123)")
    qshow.set_defaults(func=_cmd_quarantine_show)
    qsub.add_parser(
        "purge", help="delete purge-eligible blobs (prompts before deleting)"
    ).set_defaults(func=_cmd_quarantine_purge)
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
