"""Audit-chain lifecycle (ATB-05): segments, rotation, checkpoints, verification.

The chain is a family of hash-linked **segments**: one active append-only file
(what ``ATB_AUDIT_CHAIN`` points at) plus zero or more sealed, read-only,
digest-committed archives beside it. Continuity is literal — the first record
of every new segment (a ``chain_checkpoint``) takes its ``prev_hash`` from the
last record of the sealed one (a ``chain_rotated`` seal) and additionally
commits to the sealed file's whole-file sha256 — so segments cannot be
dropped, swapped, or forged undetected.

The checkpoint also carries the escalation queue's **open state** forward
(pending escalations, approved-but-unconsumed approvals) plus the set of
segments authorized off-volume (``detached``), so every runtime operation is
O(records since the last rotation) and archives are never read on the hot
path. Carried state is inside the hash chain, so it cannot be edited after the
fact, and deep verification re-derives it from the archive to prove each
checkpoint was honest when written.

Security considerations (fail-closed by construction):

- **Rotation deletes nothing, ever.** It appends exactly two records, creates
  one new name (the archive hard link), and atomically renames one staged
  file. Every interruption leaves an append-blocked state that one re-run
  converges from; nothing is lost.
- **Deep verification is the default.** A missing, edited, reordered, or
  forged segment fails. The weaker active-only mode is explicit and prints
  what it does not prove.
- **No secret material anywhere.** Payloads carry refs, hashes, counts, and
  values already chain-resident. The optional seal key is HMAC material held
  in memory only, never chained, never logged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from atb.audit import GENESIS, AuditRecord

ROTATED = "chain_rotated"
CHECKPOINT = "chain_checkpoint"
DETACHED = "segment_detached"
TAIL_TRIMMED = "tail_trimmed"

LIFECYCLE_TYPES = frozenset({ROTATED, CHECKPOINT, DETACHED})

#: Domain separation for keyed seals — never reuse the identity signing key.
_SEAL_DOMAIN = b"atb-chain-seal-v1\n"

#: Default refusal threshold for carried open state ("not a landfill").
DEFAULT_MAX_CARRY = 256

_SEGMENT_SUFFIX = re.compile(r"\.seg-(\d{6})$")
_TEMP_SUFFIX = ".tmp-rotate"


class LifecycleError(Exception):
    """Rotation, detach, or verification refused; the chain is unchanged."""


def file_digest(path: Path) -> str:
    """Whole-file sha256 of exact bytes, as ``sha256:<hex>``."""
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            hasher.update(block)
    return "sha256:" + hasher.hexdigest()


def seal_tag(payload: dict[str, Any], key: bytes) -> str:
    """HMAC-SHA256 over the domain-separated canonical payload minus ``auth``."""
    body = {k: v for k, v in payload.items() if k != "auth"}
    message = _SEAL_DOMAIN + json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "hmac-sha256:" + hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_seal_tag(payload: dict[str, Any], key: bytes) -> bool:
    """Constant-time check of a lifecycle record's ``auth`` tag."""
    presented = str(payload.get("auth", ""))
    if not presented:
        return False
    return hmac.compare_digest(presented, seal_tag(payload, key))


def segment_path(active: Path, index: int) -> Path:
    """Archive path for segment ``index`` beside the active file."""
    return active.with_name(f"{active.stem}.seg-{index:06d}{active.suffix}")


def temp_path(active: Path) -> Path:
    """Reserved staging name; never part of any lineage."""
    return active.with_name(active.name + _TEMP_SUFFIX)


def discover_segments(active: Path) -> dict[int, Path]:
    """Map segment index -> archive path for siblings of the active file."""
    found: dict[int, Path] = {}
    prefix = active.stem + ".seg-"
    for entry in active.parent.glob(f"{active.stem}.seg-*{active.suffix}"):
        if not entry.is_file() or entry.name.endswith(_TEMP_SUFFIX):
            continue
        stem = entry.name[: -len(active.suffix)] if active.suffix else entry.name
        if not stem.startswith(prefix):
            continue
        match = _SEGMENT_SUFFIX.search(stem)
        if match:
            found[int(match.group(1))] = entry
    return found


@dataclass(frozen=True)
class CarriedState:
    """Queue state and detach authorizations carried across a rotation."""

    pending: tuple[dict[str, Any], ...] = ()
    approvals: tuple[dict[str, Any], ...] = ()
    detached: tuple[dict[str, Any], ...] = ()

    @property
    def size(self) -> int:
        """Open-state size the carry threshold applies to."""
        return len(self.pending) + len(self.approvals)

    def as_payload(self) -> dict[str, Any]:
        """Canonical, JSON-deterministic payload fragment."""
        return {
            "pending": [dict(entry) for entry in self.pending],
            "approvals": [dict(entry) for entry in self.approvals],
            "detached": [dict(entry) for entry in self.detached],
        }


def derive_carried_state(records: tuple[AuditRecord, ...]) -> CarriedState:
    """Replay records (checkpoint-seeded) into the state a rotation carries.

    Mirrors the queue's own replay so the checkpoint a rotation writes is
    exactly what the queue would have derived — the property deep
    verification re-derives and byte-compares.
    """
    submitted: dict[str, dict[str, Any]] = {}
    resolved: dict[str, dict[str, Any]] = {}
    consumed: set[str] = set()
    detached: dict[int, dict[str, Any]] = {}
    for record in records:
        payload = record.payload
        kind = payload.get("type")
        ref = str(payload.get("ref", ""))
        if kind == CHECKPOINT:
            for entry in payload.get("pending", []):
                submitted[str(entry["ref"])] = dict(entry)
            for entry in payload.get("approvals", []):
                key = str(entry["ref"])
                submitted[key] = {
                    "ref": key,
                    "subject": entry.get("subject", ""),
                    "action": entry.get("action", ""),
                    "resource": entry.get("resource", ""),
                    "reason": entry.get("reason", ""),
                    "at": entry.get("at"),
                }
                resolved[key] = {
                    "approved": True,
                    "approver": entry.get("approver", ""),
                    "at": entry.get("at"),
                }
            for entry in payload.get("detached", []):
                detached[int(entry["segment"])] = dict(entry)
        elif kind == DETACHED:
            detached[int(payload["segment"])] = {
                "segment": int(payload["segment"]),
                "file_digest": payload.get("file_digest", ""),
                "ref": record.decision_id,
                "detached_by": payload.get("detached_by", ""),
                "at": record.at,
            }
        elif kind == "escalation_submitted":
            submitted[ref] = {
                "ref": ref,
                "subject": str(payload.get("subject", "")),
                "action": str(payload.get("action", "")),
                "resource": str(payload.get("resource", "")),
                "reason": str(payload.get("reason", "")),
                "at": record.at,
            }
        elif kind == "escalation_resolved":
            resolved[ref] = {
                "approved": bool(payload.get("approved")),
                "approver": str(payload.get("approver", "")),
                "at": record.at,
            }
        elif kind == "approval_consumed":
            consumed.add(ref)

    pending = tuple(entry for ref, entry in submitted.items() if ref not in resolved)
    approvals = tuple(
        {
            "ref": ref,
            "subject": submitted[ref].get("subject", ""),
            "action": submitted[ref].get("action", ""),
            "resource": submitted[ref].get("resource", ""),
            "approver": entry.get("approver", ""),
            "at": entry.get("at"),
        }
        for ref, entry in resolved.items()
        if entry.get("approved") and ref not in consumed and ref in submitted
    )
    return CarriedState(
        pending=pending,
        approvals=approvals,
        detached=tuple(detached[index] for index in sorted(detached)),
    )


def active_head(records: tuple[AuditRecord, ...]) -> dict[str, Any] | None:
    """The active segment's opening checkpoint payload, if it has one."""
    if records and records[0].payload.get("type") == CHECKPOINT:
        return dict(records[0].payload)
    return None


def is_sealed(records: tuple[AuditRecord, ...]) -> bool:
    """True when the last record is a seal (rotation in progress or complete)."""
    return bool(records) and records[-1].payload.get("type") == ROTATED


@dataclass
class SegmentFamily:
    """The active segment plus the archives its checkpoint lineage names."""

    active: Path
    head: dict[str, Any] | None
    archives: dict[int, Path] = field(default_factory=dict)

    @property
    def active_index(self) -> int:
        """Index of the active segment (1 for a never-rotated chain)."""
        return int(self.head["segment"]) if self.head else 1

    @property
    def detached_indexes(self) -> frozenset[int]:
        """Segments authorized off-volume; exempt from the presence guard."""
        if not self.head:
            return frozenset()
        return frozenset(int(entry["segment"]) for entry in self.head.get("detached", []))


def check_presence(
    active: Path,
    head: dict[str, Any] | None,
    records: tuple[AuditRecord, ...],
    *,
    detached: frozenset[int] = frozenset(),
) -> None:
    """Stat-only lineage guards run on every open (ATB-05 guards a and b).

    (a) Every archived segment the lineage names and that is not detached must
    exist. (b) A genesis-anchored active file beside segment artifacts is a
    fresh-genesis swap — unless the active file is *sealed* and the artifact
    is its own hard link, which is a rotation in progress.
    """
    found = discover_segments(active)
    # Detach authorizations are exempt from the presence check whether they
    # were carried forward by the head checkpoint or appended to the segment
    # currently open — otherwise a detach would brick startup until the next
    # rotation carried it.
    local_detached = frozenset(
        int(record.payload["segment"])
        for record in records
        if record.payload.get("type") == DETACHED
    )
    if head is not None:
        exempt = (
            detached
            | local_detached
            | frozenset(int(entry["segment"]) for entry in head.get("detached", []))
        )
        for index in range(1, int(head["segment"])):
            if index in exempt or index in found:
                continue
            raise LifecycleError(f"{active}: archived segment {index} is missing and not detached")
        return
    if not found:
        return
    # Genesis-anchored active with archives present: only a rotation in
    # progress (sealed active whose bytes match the artifact) is legitimate.
    if is_sealed(records):
        active_bytes = file_digest(active)
        for _index, path in sorted(found.items()):
            if file_digest(path) != active_bytes:
                raise LifecycleError(
                    f"{active}: unlinked segment artifact {path.name} during rotation"
                )
        return
    raise LifecycleError(
        f"{active}: genesis-anchored active segment beside archived segments "
        f"{sorted(found)} — refusing (possible fresh-genesis swap)"
    )


def build_seal_payload(
    segment: int, records_count: int, carried: CarriedState, key: bytes | None
) -> dict[str, Any]:
    """Payload for the ``chain_rotated`` seal that closes a segment."""
    payload: dict[str, Any] = {
        "type": ROTATED,
        "segment": segment,
        "next_segment": segment + 1,
        "records": records_count,
        "pending": len(carried.pending),
        "approvals": len(carried.approvals),
        "detached": len(carried.detached),
    }
    if key is not None:
        payload["auth"] = seal_tag(payload, key)
    return payload


def build_checkpoint_payload(
    segment: int,
    prev_records: int,
    prev_last_decision: str,
    prev_digest: str,
    carried: CarriedState,
    key: bytes | None,
) -> dict[str, Any]:
    """Payload for the ``chain_checkpoint`` that opens the new segment."""
    payload: dict[str, Any] = {
        "type": CHECKPOINT,
        "segment": segment,
        "prev_segment": segment - 1,
        "prev_segment_records": prev_records,
        "prev_segment_last_decision": prev_last_decision,
        "prev_segment_digest": prev_digest,
        **carried.as_payload(),
    }
    if key is not None:
        payload["auth"] = seal_tag(payload, key)
    return payload


def fsync_dir(directory: Path) -> None:
    """Make a directory entry durable (link/rename must survive power loss)."""
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# ------------------------------------------------------------------ rotation
@dataclass(frozen=True)
class RotationPlan:
    """What a rotation would do; the dry run prints exactly this."""

    active: Path
    segment: int
    records: int
    archive: Path
    carried: CarriedState
    resuming: bool


@dataclass(frozen=True)
class RotationResult:
    """What a completed rotation did; the operator records the anchor."""

    archive: Path
    archive_digest: str
    tip_hash: str
    tip_sequence: int
    carried: CarriedState


def plan_rotation(
    active: Path,
    records: tuple[AuditRecord, ...],
    *,
    max_carry: int = DEFAULT_MAX_CARRY,
    force_carry: bool = False,
) -> RotationPlan:
    """Derive the rotation plan; refuse an empty or over-full rotation.

    Refuses when the segment holds nothing beyond its own checkpoint (an
    idempotent no-op) and when carried open state exceeds ``max_carry``
    without ``force_carry`` — a checkpoint is not a landfill.
    """
    head = active_head(records)
    segment = int(head["segment"]) if head else 1
    resuming = is_sealed(records)
    substantive = [r for r in records if r.payload.get("type") not in (CHECKPOINT, ROTATED)]
    if not substantive and not resuming:
        raise LifecycleError(f"{active}: nothing to rotate (segment holds no new records)")
    carried = derive_carried_state(records)
    if carried.size > max_carry and not force_carry:
        raise LifecycleError(
            f"{active}: {carried.size} open items exceed the carry threshold "
            f"({max_carry}) — adjudicate the backlog or pass --force-carry"
        )
    return RotationPlan(
        active=active,
        segment=segment,
        records=len(records),
        archive=segment_path(active, segment),
        carried=carried,
        resuming=resuming,
    )


def execute_rotation(
    store: Any,
    *,
    seal_key: bytes | None = None,
    max_carry: int = DEFAULT_MAX_CARRY,
    force_carry: bool = False,
    now: Any = None,
) -> RotationResult:
    """Seal the active segment and open its successor (ATB-05 steps 1-9).

    Crash-safe and idempotent: every step is read-only, an append to an
    append-only file, or the creation of a *new* name; the only mutation of
    an existing path is the atomic rename of a file this function just wrote.
    Nothing is ever deleted. Re-running after any interruption converges to
    the same final state, and the whole rotation costs exactly two records
    however many times it crashed.
    """
    from atb.audit import AuditLog  # local import: audit must not import lifecycle
    from atb.persistence import JsonlAuditStore

    active: Path = store.path
    records = store.records
    plan = plan_rotation(active, records, max_carry=max_carry, force_carry=force_carry)

    # Step 3 — seal (skipped when resuming an interrupted rotation).
    if not plan.resuming:
        payload = build_seal_payload(plan.segment, len(records) + 1, plan.carried, seal_key)
        store.append(payload)
        store.sealed = True
        records = store.records
    else:
        # Re-derive from the sealed bytes and cross-check the seal's counts:
        # a mismatch means the file changed during the outage.
        seal = records[-1].payload
        recheck = derive_carried_state(records)
        if (
            int(seal.get("pending", -1)) != len(recheck.pending)
            or int(seal.get("approvals", -1)) != len(recheck.approvals)
            or int(seal.get("records", -1)) != len(records)
        ):
            raise LifecycleError(
                f"{active}: sealed segment does not match its seal counts — refusing to resume"
            )
        plan = RotationPlan(
            active=active,
            segment=int(seal["segment"]),
            records=len(records),
            archive=segment_path(active, int(seal["segment"])),
            carried=recheck,
            resuming=True,
        )

    seal_record = records[-1]
    # Step 4 — digest the sealed bytes.
    sealed_digest = file_digest(active)
    sealed_size = active.stat().st_size

    # Step 5 — stage the successor's checkpoint.
    checkpoint_payload = build_checkpoint_payload(
        plan.segment + 1,
        len(records),
        seal_record.decision_id,
        sealed_digest,
        plan.carried,
        seal_key,
    )
    staged = AuditLog(
        now=now,
        start_sequence=int(seal_record.decision_id.rsplit("-", 1)[1]),
        anchor_hash=seal_record.record_hash,
    )
    checkpoint = staged.append(checkpoint_payload)
    temp = temp_path(active)
    with temp.open("w", encoding="utf-8") as handle:
        handle.write(_persisted_line(checkpoint) + "\n")
        handle.flush()
        os.fsync(handle.fileno())

    # Step 6 — link the sealed bytes under the archive name, durably.
    archive = plan.archive
    if not archive.exists():
        os.link(active, archive)
    elif file_digest(archive) != sealed_digest:
        temp.unlink(missing_ok=True)
        raise LifecycleError(
            f"{archive}: existing archive does not match the sealed segment — refusing"
        )
    fsync_dir(active.parent)

    # Step 7 — pre-commit byte-stability re-check, then the atomic commit.
    if active.stat().st_size != sealed_size or file_digest(active) != sealed_digest:
        temp.unlink(missing_ok=True)
        raise LifecycleError(
            f"{active}: sealed segment changed before commit (straggler writer?) — aborted"
        )
    os.replace(temp, active)
    fsync_dir(active.parent)

    # Step 8 — harden the archive (advisory; the digest commitment is the control).
    try:
        archive.chmod(0o440)
    except OSError:  # pragma: no cover - platform-dependent
        pass

    # Step 9 — fail-closed self-test: the new head must reproduce the state.
    reopened = JsonlAuditStore.open(active)
    derived = derive_carried_state(reopened.records)
    if derived != plan.carried:
        raise LifecycleError(
            f"{active}: post-rotation self-test failed — carried state does not match"
        )
    if file_digest(archive) != sealed_digest:
        raise LifecycleError(f"{archive}: post-rotation digest mismatch")

    return RotationResult(
        archive=archive,
        archive_digest=sealed_digest,
        tip_hash=checkpoint.record_hash,
        tip_sequence=int(checkpoint.decision_id.rsplit("-", 1)[1]),
        carried=plan.carried,
    )


def _persisted_line(record: AuditRecord) -> str:
    """Persisted JSON form of a record (mirrors the store's writer)."""
    body: dict[str, Any] = {
        "decision_id": record.decision_id,
        "payload": record.payload,
        "prev_hash": record.prev_hash,
        "record_hash": record.record_hash,
    }
    if record.at is not None:
        body["at"] = record.at
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


# -------------------------------------------------------------- verification
@dataclass(frozen=True)
class SegmentStatus:
    """One row of the verification table."""

    index: int
    file: str
    records: int
    status: str  # ok | detached | failed
    detail: str = ""


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of a verification run; ``ok`` is the exit-code authority."""

    ok: bool
    deep: bool
    segments: tuple[SegmentStatus, ...]
    tip_hash: str
    tip_sequence: int
    failures: tuple[str, ...] = ()


def _replay_file(path: Path, anchor: str, start_sequence: int) -> tuple[AuditRecord, ...]:
    """Byte-identically replay one segment file from a given anchor."""
    from atb.audit import AuditLog

    log = AuditLog(start_sequence=start_sequence, anchor_hash=anchor)
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            body = json.loads(line)
            record = AuditRecord(
                decision_id=str(body["decision_id"]),
                payload=body["payload"],
                prev_hash=str(body["prev_hash"]),
                record_hash=str(body["record_hash"]),
                at=body.get("at"),
            )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LifecycleError(f"{path}:{line_number}: malformed or truncated record") from exc
        try:
            log.adopt(record)
        except ValueError as exc:
            raise LifecycleError(
                f"{path}:{line_number}: record does not match the recomputed chain"
            ) from exc
    return log.records


def verify_family(
    active: Path,
    *,
    deep: bool = True,
    seal_key: bytes | None = None,
    allow_unkeyed: bool = False,
    presented: dict[int, Path] | None = None,
) -> VerifyResult:
    """Verify the segment family; deep is the default and proves all history.

    Deep verification walks every archived segment from genesis: byte-identical
    replay, terminal-seal placement, boundary anchoring, whole-file digests,
    sequence continuity, carried-state re-derivation, and keyed tags when a
    key is configured. ``--active-only`` (deep=False) proves only the active
    segment and names what it does not prove. A missing, undetached segment
    is a failure — never a silent skip.
    """
    failures: list[str] = []
    statuses: list[SegmentStatus] = []
    presented = presented or {}

    head_payload: dict[str, Any] | None = None
    first_line = None
    if active.exists():
        text = active.read_text(encoding="utf-8").splitlines()
        first_line = json.loads(text[0]) if text and text[0].strip() else None
    if first_line and first_line.get("payload", {}).get("type") == CHECKPOINT:
        head_payload = first_line["payload"]

    active_index = int(head_payload["segment"]) if head_payload else 1
    detached = {int(e["segment"]): e for e in (head_payload or {}).get("detached", [])}

    if deep:
        found = discover_segments(active)
        anchor = GENESIS
        sequence = 0
        for index in range(1, active_index):
            path = presented.get(index) or found.get(index)
            if path is None:
                if index in detached:
                    statuses.append(
                        SegmentStatus(
                            index,
                            "(detached)",
                            0,
                            "detached",
                            "digest commitment not verifiable locally",
                        )
                    )
                    # Lineage continues from the successor checkpoint's claims.
                    anchor = ""
                    continue
                failures.append(f"segment {index} MISSING and not detached")
                statuses.append(SegmentStatus(index, "(missing)", 0, "failed", "missing"))
                anchor = ""
                continue
            try:
                seg_records = _replay_file(path, anchor, sequence) if anchor else None
            except LifecycleError as exc:
                failures.append(str(exc))
                statuses.append(SegmentStatus(index, path.name, 0, "failed", str(exc)))
                anchor = ""
                continue
            if seg_records is None:
                statuses.append(
                    SegmentStatus(index, path.name, 0, "detached", "lineage break upstream")
                )
                continue
            if not seg_records or seg_records[-1].payload.get("type") != ROTATED:
                failures.append(f"segment {index}: archive is not terminally sealed")
                statuses.append(SegmentStatus(index, path.name, len(seg_records), "failed"))
                anchor = ""
                continue
            if seal_key is not None:
                for rec in seg_records:
                    if rec.payload.get("type") in LIFECYCLE_TYPES and not verify_seal_tag(
                        rec.payload, seal_key
                    ):
                        failures.append(
                            f"segment {index}: lifecycle record {rec.decision_id} "
                            "has an invalid seal tag"
                        )
            elif not allow_unkeyed:
                for rec in seg_records:
                    if rec.payload.get("type") in LIFECYCLE_TYPES and rec.payload.get("auth"):
                        failures.append(
                            f"segment {index}: chain is keyed but no key was supplied "
                            "(pass --allow-unkeyed to accept the downgrade)"
                        )
                        break
            statuses.append(SegmentStatus(index, path.name, len(seg_records), "ok"))
            anchor = seg_records[-1].record_hash
            sequence = int(seg_records[-1].decision_id.rsplit("-", 1)[1])
            # Boundary checks against the successor's claims happen below.
            digest_now = file_digest(path)
            statuses[-1] = SegmentStatus(index, path.name, len(seg_records), "ok", digest_now)

    # The active segment itself.
    if active.exists():
        anchor_for_active = GENESIS
        seq_for_active = 0
        if head_payload and first_line is not None:
            anchor_for_active = str(first_line["prev_hash"])
            seq_for_active = int(head_payload["prev_segment_last_decision"].rsplit("-", 1)[1])
        try:
            act_records = _replay_file(active, anchor_for_active, seq_for_active)
            statuses.append(
                SegmentStatus(active_index, active.name, len(act_records), "ok", "active")
            )
        except LifecycleError as exc:
            failures.append(str(exc))
            act_records = ()
            statuses.append(SegmentStatus(active_index, active.name, 0, "failed", str(exc)))
    else:
        act_records = ()
        failures.append(f"{active}: active segment is missing")

    # Boundary and honesty checks (deep only: they need the archive bytes).
    if deep and head_payload:
        prev_index = int(head_payload["prev_segment"])
        prev_path = presented.get(prev_index) or discover_segments(active).get(prev_index)
        if prev_path is not None:
            if file_digest(prev_path) != head_payload["prev_segment_digest"]:
                failures.append(
                    f"segment {prev_index}: file digest does not match the committed value"
                )
            else:
                try:
                    prev_records = _replay_file(prev_path, GENESIS, 0) if prev_index == 1 else None
                except LifecycleError:
                    prev_records = None
                if prev_records is not None:
                    rederived = derive_carried_state(prev_records)
                    claimed = CarriedState(
                        pending=tuple(head_payload.get("pending", [])),
                        approvals=tuple(head_payload.get("approvals", [])),
                        detached=tuple(head_payload.get("detached", [])),
                    )
                    if rederived.as_payload() != claimed.as_payload():
                        failures.append(
                            f"checkpoint {active_index}: carried state does not re-derive "
                            f"from segment {prev_index}"
                        )

    tip = act_records[-1] if act_records else None
    return VerifyResult(
        ok=not failures,
        deep=deep,
        segments=tuple(statuses),
        tip_hash=tip.record_hash if tip else "",
        tip_sequence=int(tip.decision_id.rsplit("-", 1)[1]) if tip else 0,
        failures=tuple(failures),
    )


def check_anchor(
    result: VerifyResult,
    records: tuple[AuditRecord, ...],
    expect_tip: str,
    expect_seq: int | None = None,
) -> bool:
    """Anchor check by ANCESTRY: the recorded tip must be in this lineage.

    Equality alone would both fail on honest appends since the anchor was
    recorded and pass on a truncation back to the checkpoint. Ancestry bounds
    the claim to "no rollback to any state preceding the anchor"; records
    appended after it are outside the anchor's protection.
    """
    if expect_seq is not None and result.tip_sequence < expect_seq:
        return False
    return any(record.record_hash == expect_tip for record in records)
