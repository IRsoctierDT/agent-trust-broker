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
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from atb.audit import AuditRecord, utc_now
from atb.escalation import (
    CHECKPOINT,
    CONSUMED,
    RESOLVED,
    SUBMITTED,
    EscalationError,
    EscalationQueue,
)
from atb.lifecycle import (
    DETACHED,
    LifecycleError,
    active_head,
    check_anchor,
    execute_rotation,
    file_digest,
    plan_rotation,
    seal_tag,
    segment_path,
    verify_family,
)
from atb.persistence import AuditIntegrityError, JsonlAuditStore, trim_torn_tail
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
        if kind == CHECKPOINT:
            # ATB-05: honor carried state here too. Purge eligibility, show's
            # prior-adjudication summary, and screen-stats all read this
            # replay — a carried, still-open release escalation must stay
            # visible, or purge would delete evidence under an open gate.
            for entry in payload.get("pending", []):
                if str(entry.get("action", "")) == RELEASE_ACTION:
                    submitted[str(entry["ref"])] = dict(entry)
            for entry in payload.get("approvals", []):
                key = str(entry["ref"])
                if str(entry.get("action", "")) != RELEASE_ACTION:
                    continue
                submitted[key] = dict(entry)
                resolved[key] = {"approved": True, "approver": entry.get("approver", "")}
        elif kind == SUBMITTED and str(payload.get("action", "")) == RELEASE_ACTION:
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

    verify = sub.add_parser("verify", help="verify the whole segment family (deep by default)")
    verify.add_argument(
        "--active-only",
        action="store_true",
        help="verify only the active segment (prints what it does NOT prove)",
    )
    verify.add_argument("--expect-tip", help="off-box anchor: this hash must be in the lineage")
    verify.add_argument("--expect-seq", type=int, help="sequence recorded with the anchor")
    verify.add_argument(
        "--with-segment",
        action="append",
        metavar="PATH",
        help="re-present a detached archive from cold storage",
    )
    verify.add_argument(
        "--allow-unkeyed",
        action="store_true",
        help="accept a keyed chain without its seal key (explicit downgrade)",
    )
    verify.set_defaults(func=_cmd_verify_family)

    rotate = sub.add_parser("rotate", help="seal the active segment and open its successor")
    rotate.add_argument("--execute", action="store_true", help="act (default is a dry run)")
    rotate.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    rotate.add_argument(
        "--force-carry",
        action="store_true",
        help="rotate despite a large carried open-state backlog",
    )
    rotate.set_defaults(func=_cmd_rotate)

    detach = sub.add_parser("detach", help="authorize an archived segment to leave the volume")
    detach.add_argument("segment", type=int, help="segment index (e.g. 1)")
    detach.add_argument("--reason", required=True, help="why (recorded in the chain)")
    detach.add_argument("--approver", help="who (default: current OS user)")
    detach.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    detach.add_argument("--allow-unkeyed", action="store_true")
    detach.set_defaults(func=_cmd_detach)

    repair = sub.add_parser("repair", help="gated recovery for a torn, unacknowledged tail")
    repair.add_argument("--trim-torn-tail", action="store_true", help="name the repair")
    repair.add_argument("--execute", action="store_true", help="act (default is a dry run)")
    repair.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    repair.set_defaults(func=_cmd_repair)

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


# --------------------------------------------------------- ATB-05 lifecycle
def _seal_key() -> bytes | None:
    """Optional HMAC seal key from the environment; fail closed on garbage."""
    raw = os.environ.get("ATB_CHAIN_SEAL_KEY", "").strip()
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise SystemExit("error: ATB_CHAIN_SEAL_KEY must be hex-encoded") from exc
    if len(key) < 32:
        raise SystemExit("error: ATB_CHAIN_SEAL_KEY must be at least 32 bytes")
    return key


def _cmd_rotate(args: argparse.Namespace) -> int:
    """Seal the active segment and open its successor (dry run by default)."""
    path = _resolve_chain_path(args.chain)
    try:
        store = JsonlAuditStore.open(path, now=utc_now, for_append=False)
        plan = plan_rotation(path, store.records, force_carry=args.force_carry)
    except (AuditIntegrityError, LifecycleError) as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(f"active segment : {path} (segment {plan.segment}, {plan.records} records)")
    print(f"would archive  : {plan.archive.name}")
    print(
        f"carried state  : {len(plan.carried.pending)} pending, "
        f"{len(plan.carried.approvals)} unconsumed approval(s), "
        f"{len(plan.carried.detached)} detached segment(s)"
    )
    for entry in plan.carried.pending:
        print(
            f"  pending {entry['ref']} {entry.get('action', '')} {entry.get('resource', '')}"
            f" (since {entry.get('at') or 'unknown'})"
        )
    if plan.resuming:
        print("state          : ROTATION INCOMPLETE — this run resumes it")
    if not args.execute:
        print("\nnothing rotated — re-run with --execute (gateway must be stopped)")
        return 0
    if not args.yes:
        if input("Seal this segment and open its successor? [y/N] ").strip().lower() != "y":
            print("Aborted; nothing rotated.")
            return 1
    try:
        store = JsonlAuditStore.open(path, now=utc_now, for_append=not plan.resuming)
        result = execute_rotation(
            store, seal_key=_seal_key(), force_carry=args.force_carry, now=utc_now
        )
    except (AuditIntegrityError, LifecycleError) as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(f"\nsealed archive : {result.archive.name}")
    print(f"  sha256       : {result.archive_digest}")
    print(f"    verify off-box with: sha256sum {result.archive.name}")
    print(f"new tip hash   : {result.tip_hash}")
    print(f"new tip seq    : {result.tip_sequence}")
    print("  RECORD THE TIP OFF-BOX — it is your external trust anchor")
    print("  check it later with: atb verify --expect-tip <hash>")
    print("restart the gateway when the archive copy is confirmed.")
    return 0


def _cmd_verify_family(args: argparse.Namespace) -> int:
    """Verify the whole segment family (deep by default)."""
    path = _resolve_chain_path(args.chain)
    presented: dict[int, Path] = {}
    for item in args.with_segment or []:
        candidate = Path(item)
        if not candidate.is_file():
            raise SystemExit(f"error: no presented segment at {candidate}")
        match = re.search(r"\.seg-(\d{6})", candidate.name)
        if not match:
            raise SystemExit(f"error: {candidate.name} is not a segment file name")
        presented[int(match.group(1))] = candidate
    try:
        result = verify_family(
            path,
            deep=not args.active_only,
            seal_key=_seal_key(),
            allow_unkeyed=args.allow_unkeyed,
            presented=presented,
        )
    except LifecycleError as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(f"{'SEG':<5} {'FILE':<34} {'RECORDS':>7}  STATUS")
    for row in result.segments:
        print(
            f"{row.index:<5} {row.file:<34} {row.records:>7}  {row.status.upper()}"
            f"{'  ' + row.detail if row.detail else ''}"
        )
    print(f"tip: {result.tip_hash} (seq {result.tip_sequence})")
    if args.active_only:
        head = active_head(JsonlAuditStore.open(path, for_append=False).records)
        since = head["prev_segment_last_decision"] if head else "genesis"
        print(
            f"PROVEN: no record in the active segment (since {since}) has been added, "
            "edited, removed, or reordered."
        )
        print(
            "NOT PROVEN: that archived segments match their committed digests — verify "
            "them where they are stored (sha256sum), then run atb verify."
        )
    for failure in result.failures:
        print(f"FAILED: {failure}")
    if args.expect_tip:
        records = JsonlAuditStore.open(path, for_append=False).records
        if check_anchor(result, records, args.expect_tip, args.expect_seq):
            print(f"anchor OK: {args.expect_tip} is in this lineage")
        else:
            print(f"FAILED: anchor {args.expect_tip} is NOT in this lineage (rollback?)")
            return 1
    return 0 if result.ok else 1


def _cmd_detach(args: argparse.Namespace) -> int:
    """Authorize an archived segment to leave the volume (chained, gated)."""
    path = _resolve_chain_path(args.chain)
    archive = segment_path(path, args.segment)
    if not archive.is_file():
        raise SystemExit(f"error: no archived segment {args.segment} at {archive}")
    result = verify_family(path, seal_key=_seal_key(), allow_unkeyed=args.allow_unkeyed)
    if not result.ok:
        raise SystemExit("error: deep verify is not green — refusing to detach")
    digest = file_digest(archive)
    print(f"segment {args.segment}: {archive.name}")
    print(f"  sha256: {digest}")
    print("  confirm you hold an off-box copy verified against this digest.")
    if not args.yes:
        if input(f"Authorize detaching segment {args.segment}? [y/N] ").strip().lower() != "y":
            print("Aborted; nothing detached.")
            return 1
    store = JsonlAuditStore.open(path, now=utc_now)
    payload: dict[str, Any] = {
        "type": DETACHED,
        "segment": args.segment,
        "file_digest": digest,
        "detached_by": (args.approver or getpass.getuser()).strip(),
        "reason": args.reason,
    }
    key = _seal_key()
    if key is not None:
        payload["auth"] = seal_tag(payload, key)
    record = store.append(payload)
    print(f"detached segment {args.segment} — recorded as {record.decision_id}")
    return 0


def _cmd_repair(args: argparse.Namespace) -> int:
    """Trim a torn, unacknowledged final line (gated recovery)."""
    path = _resolve_chain_path(args.chain)
    try:
        if not args.trim_torn_tail:
            raise SystemExit("error: pass --trim-torn-tail to name the repair")
        text = path.read_text(encoding="utf-8").splitlines()
        tail = text[-1] if text else ""
        try:
            json.loads(tail)
            print("Nothing to repair: the final line parses.")
            return 0
        except json.JSONDecodeError:
            pass
        print(f"torn final line ({len(tail)} bytes) would be discarded:")
        print(f"  {tail[:200]}")
        if not args.execute:
            print("\nnothing changed — re-run with --execute")
            return 0
        if not args.yes:
            if input("Discard this torn line? [y/N] ").strip().lower() != "y":
                print("Aborted; nothing changed.")
                return 1
        discarded = trim_torn_tail(path)
        print(f"trimmed {len(discarded or '')} bytes; re-verifying…")
        JsonlAuditStore.open(path, for_append=False)
        print("chain verifies green.")
    except AuditIntegrityError as exc:
        raise SystemExit(f"error: {exc}") from exc
    return 0
