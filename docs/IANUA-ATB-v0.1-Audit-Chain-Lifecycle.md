---
title: "IANUA-ATB v0.1 — Volume ATB-05: Audit-Chain Lifecycle — Rotation, Checkpointing & Chained Time"
series: "IANUA Engineering Reference"
volume: "ATB-05"
status: "Authoritative — maintainer review gate passed 2026-08-16"
supersedes: "None (extends ATB-01 through ATB-04)"
companion_docs:
  - "IANUA-ATB v0.1 — Volume ATB-01: Identity Issuance & Zero-Trust Policy Enforcement"
  - "IANUA-ATB v0.1 — Volume ATB-02: Scope Catalog, Role-Spec Bindings & Delegation Model"
  - "IANUA-ATB v0.1 — Volume ATB-03: Runtime Enforcement Point & Tool-Call Mediation"
  - "IANUA-ATB v0.1 — Volume ATB-04: Tool-Response Screening & Quarantine"
  - "IANUA — AGENTS.md Operating Charter"
eaods_traceability:
  reference_implementation_of:
    - "PAT-0001 — Zero Trust Service Identity"
    - "EAODS-CTRL-000184 — Service Identity Verification"
  emits_evidence_to:
    - "PAT-0003 — Continuous Assurance Evidence Pipeline"
  governed_by:
    - "STD-0001 — Canonical Terminology & Object Identifiers"
    - "STD-0002 — Cross-Artifact Traceability & Knowledge Graph"
purpose: >
  Gives the hash-chained audit log a lifecycle: a human-run rotation seals the
  active chain into an immutable, digest-committed archived segment and opens a
  successor whose first record cryptographically commits to all prior history and
  materializes the escalation queue's open state, so every runtime operation
  becomes O(records since last rotation) while full-history verification remains
  the default proof. Newly appended records gain a chained timestamp, closing the
  telemetry deferral from ATB-04. Nothing is ever retro-edited, nothing is ever
  deleted by the broker, and every weaker verification mode is explicit, named,
  and opt-in.
owner: "Repository maintainer (human)"
review_cadence: "Re-read on session start; revise on any segment, checkpoint, or verification change"
---

# IANUA Agent Trust Broker (ATB)

## Volume ATB-05 — Audit-Chain Lifecycle: Rotation, Checkpointing & Chained Time

---

## Purpose

ATB-01 made every decision a record in a hash chain; ATB-02/03 made the chain the
single source of queue state; ATB-04 added screening evidence and noted the bill:
**the chain grows forever and every queue operation, CLI verb, and gateway startup
replays all of it** — O(n) with n monotonically increasing, a flag storm inflating
it permanently. ATB-04 declared chain rotation/checkpointing "the standing ATB-05
candidate" and deferred per-decision latency telemetry "to ATB-05" because records
carry no timestamp (ATB-01's canonical schema defined `at`; the implementation
omitted it).

This volume pays both debts. The chain becomes a **family of hash-linked
segments**: one active append-only file (what `ATB_AUDIT_CHAIN` already points to)
plus zero or more sealed, read-only, digest-committed archived siblings on the same
writable volume. Continuity is literal, not asserted — the first record of every
new segment takes its `prev_hash` from the last record of the sealed one, and
additionally commits to the sealed file's whole-file sha256, so the commitment to
all history is the hash chain itself, transitively back to genesis. The queue's
open state rides inside that first record, verified and tamper-evident, so the
runtime never reads archives. Newly appended records gain a chained `at`
(millisecond ISO-8601 UTC), and historical records replay byte-identically forever
— **nothing is ever retro-edited**.

---

## Strategic Objectives

- **Bounded runtime cost that is real.** After rotation: gateway startup,
  `pending`, `submit`, `resolve`, `try_consume`, purge eligibility, coalescing,
  and default `screen-stats` are O(records since the last rotation). Only the
  proof and forensics verbs (`atb verify`, `--all-segments`) read archives.
- **Full-history proof stays the default.** `atb verify` verifies every segment
  from genesis and fails closed on any missing, edited, reordered, swapped,
  forged, or unlinked segment. The weaker active-only mode is a named flag that
  prints, verbatim, what it does and does not prove.
- **Rotation is a governed human act.** A dry-run-by-default CLI verb, gateway
  stopped, §5.1-gated, crash-safe at every step, idempotent on re-run, and
  incapable of deleting anything.
- **Open state survives rotation provably.** Pending escalations and
  approved-but-unconsumed approvals are materialized into the chained checkpoint,
  re-derived and byte-compared at deep verify, and behave **identically** to
  segment-local state under every queue operation.
- **Chained time, frozen history.** New records carry `at` inside the record
  hash; records without `at` keep today's exact hash form forever. Flag-to-
  resolution latency — the ATB-04 deferral — becomes chain-derivable.
- **Explicit trust models for the residuals.** Opt-in keyed seals defend the
  lifecycle records against truncate-and-forge; out-of-band anchors defend
  against wholesale rollback; a chained detach record distinguishes authorized
  archive retirement from hostile deletion. Each is named, mechanical, and
  testable — never a silent degradation.

---

## Trust & Engineering Principles

1. **History is append-only at every scale.** Records are never edited; segments
   are never re-serialized, compacted, or summarized; rotation adds exactly two
   records and renames exactly one file atomically.
2. **The chain is its own manifest.** No sidecar index, no second source of
   truth: segment lineage, archive digests, carried state, and detach
   authorizations all live inside the hash chain, where editing them breaks it.
3. **Weaker proofs are named, never defaulted.** A verification that cannot see
   history fails; it does not warn-and-pass. Every opt-in downgrade
   (`--active-only`, `--allow-unkeyed`) prints its non-proofs literally.
4. **The runtime never trusts what it does not verify.** `open()` byte-identically
   replays everything it consumes; carried state is trusted only because the
   checkpoint carrying it is inside the verified chain; archives are never read
   on the hot path and therefore can never alter broker behavior.
5. **Time is telemetry, position is truth.** `at` is chained (tamper-evident) and
   monotonic-floored at append, but chain position remains the sole ordering
   authority; verification checks `at` format, never re-orders by it.
6. **Deletion is a human act with chain evidence.** The broker deletes nothing.
   Archive retirement requires a green deep verify, a digest-checked off-box
   copy, and a chained `segment_detached` record — after which verification
   reports the segment as DETACHED (re-presentable via `--with`), never as
   silently absent.

---

## Segment Model

```
/var/lib/atb/                                  [one writable volume, unchanged]
├── audit-chain.seg-000001.jsonl   0o440   sealed: … + chain_rotated  ─┐ digest
├── audit-chain.seg-000002.jsonl   0o440   chain_checkpoint + … + seal ─┐ committed
└── audit-chain.jsonl              active  chain_checkpoint + …         │ in successor
        ▲                                                               │ checkpoint
        └── ATB_AUDIT_CHAIN (meaning unchanged: the ACTIVE segment)  ◀──┘
```

- **Naming & discovery.** Archived segment k is `<stem>.seg-{k:06d}<suffix>`
  beside the active file; temp files use the reserved `.tmp-rotate` name;
  discovery derives the family from the active path's stem. Renaming a family
  requires renaming all members consistently (ops note); lineage authority is
  the checkpoint chain, not the directory listing.
- **Segment identity.** Segment 1 is the legacy chain (first record anchored to
  the zero genesis; no checkpoint). Every segment ≥ 2 begins with exactly one
  `chain_checkpoint` (valid only at line 1) and, once rotated again, ends with
  exactly one `chain_rotated` seal (valid only as the final record).
- **Runtime reads.** The gateway and every routine CLI verb read **only** the
  active segment, byte-identically replayed from its anchor exactly as today.
  Additionally, every `open()` runs two O(#segments) guards (stat only, no
  content reads): **(a)** every archived segment named by the lineage and **not
  listed as detached in the active head checkpoint's carried `detached` list**
  must exist on disk — a deleted, undetached archive fails gateway startup and
  every verb immediately. The sole exception is `atb verify --active-only`,
  whose verbatim NOT-PROVEN output is the named downgrade for exactly this
  situation; **(b)** an active file claiming to be segment 1 (genesis-anchored)
  while `seg-*`/temp artifacts exist fails closed — a fresh-genesis swap is
  caught at startup, not at the next audit. **ROTATION-INCOMPLETE precedence:**
  when the active file terminates in a `chain_rotated` seal, guard (b) and the
  unlinked-`seg-*` trigger are suppressed **iff** every otherwise-unlinked
  `seg-*` artifact byte-digest-matches the sealed active file (trivially true
  after rotation step 6, where the archive is a hard link to the same inode) or
  no such artifact exists (crash after step 5: temp only, and temps are never
  lineage). This is what keeps the *first* rotation's crash window recoverable
  — a sealed genesis-anchored segment 1 beside its own hard link is a rotation
  in progress, not a swap. An **unsealed** genesis-anchored active file beside
  any `seg-*`/temp artifact remains a hard guard-(b) failure, as does a `seg-*`
  artifact that neither a checkpoint references nor digest-matches the sealed
  active.
- **Bootstrap guard.** `open()` creates a missing active file **only in a clean
  directory** (no `seg-*` siblings, no rotation temp, no lock artifacts). In any
  other state a missing active file is an integrity failure, not a first boot —
  today's unconditional create-on-missing is removed.
- **Backward & forward compatibility.** An existing single-file chain *is* a
  never-rotated segment-1 family: zero migration. Pre-ATB-05 code opening a
  rotated active file fails closed at record 1 (its anchor is not genesis) — old
  readers can never silently misread a rotated chain. **Mixed-version rule:**
  upgrade every chain-touching binary *before* the first rotation (a pre-ATB-05
  gateway would ignore a seal and append past it); the rotate preflight banner
  restates this, and deep verify's seal-must-be-terminal check is the backstop.

---

## Lifecycle Records

Three new record types (UPPER_SNAKE constants in the persistence layer), all
appended through the normal path — each consumes an ATB-DEC sequence id, carries
`at`, and chains like any record. ATB-DEC ids are **chain-sequence numbers, not
decision counts** (precedent: escalation lifecycle records); telemetry counts by
type, never by id arithmetic. The queue's unknown-type forward-compatibility
ignores all three. Payload hygiene is unchanged: refs, hashes, counts, indices,
and values already chain-resident — no free text, no payloads, no secrets.

**`chain_rotated`** — the seal, final record of the closing segment:

```yaml
type: chain_rotated
segment: 3            # the segment being sealed
next_segment: 4
records: 1841         # records in this segment, including this seal
pending: 1            # carried-state counts, cross-checked against the
approvals: 1          #   successor checkpoint at deep verify
detached: 1           # carried detach count, same cross-check
auth: "hmac-sha256:…" # present iff ATB_CHAIN_SEAL_KEY is configured
```

**`chain_checkpoint`** — the first record of the new segment. Its `prev_hash`
**is** the seal's `record_hash`; its decision id is the seal's + 1.

```yaml
type: chain_checkpoint
segment: 4
prev_segment: 3
prev_segment_records: 1841
prev_segment_last_decision: "ATB-DEC-004962"   # the seal's id
prev_segment_digest: "sha256:…"                # the sealed FILE's exact bytes
pending:              # open escalations, original submission order; values
  - {ref: "ATB-DEC-004890", subject: "agent:soc-analyst",       # byte-copied
     action: "atb:response.release",                            # from the
     resource: "quarantine:sha256:…",                           # originating
     reason: "human_approval_required_scope_not_granted",       # records
     at: "2026-08-15T02:04:11.812Z"}           # original 'at' (null if legacy)
approvals:            # approved-but-unconsumed only, resolution order
  - {ref: "ATB-DEC-004901", subject: "agent:soc-analyst",
     action: "net:egress", resource: "host:https://intel.example:443/feed",
     approver: "ivan", at: "2026-08-15T02:09:40.101Z"}
detached:             # archives authorized off-volume, by segment index
  - {segment: 1, file_digest: "sha256:…",       # digest committed when sealed
     ref: "ATB-DEC-004120", detached_by: "ivan", # the segment_detached record
     at: "2026-08-10T09:31:02.004Z"}
auth: "hmac-sha256:…"
```

**`segment_detached`** — human-gated authorization for taking a verified archive
off-volume (see Retention): `{type, segment, file_digest, detached_by, reason,
auth}`.

**Detach state is carried, like open escalations.** A `segment_detached` record
lands in whatever segment is active when it is appended — and is sealed into an
archive at the next rotation, where the stat-only hot path may never read it.
The checkpoint therefore carries a `detached` list forward (seeded from the
predecessor checkpoint's list plus any `segment_detached` records appended
since), so guard (a) can exempt detached indices across arbitrarily many
rotations. Without this, a legitimately detached archive would brick gateway
startup at the first rotation after the detach.

**Verification story, field by field.** `prev_hash` proves chain continuity
(forging it requires forging the sealed tip, caught by replay).
`prev_segment_digest` is a byte-level commitment — any edit, truncation,
re-serialization, or swap of the archived file fails deep verify even if its
contents were internally re-chained. `prev_segment_records` /
`…_last_decision` prove sequence continuity **without archives present** (the
checkpoint's own id must be last + 1; a gap or overlap fails `open()`).
`pending`/`approvals`/`detached` are re-derived from the archived segment at
deep verify and must match byte-for-byte — proving every checkpoint was *honest
when written*, not merely unedited since; each `detached` entry's `file_digest`
is additionally cross-checked against the digest committed when that segment was
originally sealed. The checkpoint itself is inside the chain, verified on every
open: carried state cannot be edited after the fact.

**Keyed seals (opt-in).** When `ATB_CHAIN_SEAL_KEY` is configured (dedicated hex
key ≥ 32 bytes, fail-closed parsing, **never** `ATB_SIGNING_KEY`), every
lifecycle record's `auth` is HMAC-SHA256 over the domain-separated canonical
payload (`atb-chain-seal-v1\n` + canonical JSON minus `auth`). Verification with
the key demands valid tags on every lifecycle record; a keyed chain verified
without the key **fails** unless `--allow-unkeyed` is passed explicitly. This
closes the truncate-and-forge-a-rotation residual: an attacker who can rewrite
the volume but lacks the key cannot mint a plausible seal or detach record.

---

## Rotation Procedure

Verb: `atb rotate` (no flags = **dry run**: prints the plan, appends nothing) /
`atb rotate --execute` (prompts; `--yes` for non-interactive runs). Precondition:
gateway stopped — rotation lives inside the existing stop → resolve → restart
loop; rotate additionally takes an exclusive advisory `flock` on the active file
for its duration, which **serializes concurrent `rotate` invocations only**.
Ordinary appenders do not take the lock (that would be a broker-wide change with
its own risks), so a straggler writer is prevented *procedurally* by the
gateway-stopped precondition and *detected* — not refused — by the
seal-must-be-terminal check, replay `prev_hash` mismatch, and step 7's
pre-commit byte-stability re-check. The dry run lists
the carried state with ages; rotate **refuses** when the active segment holds no
records beyond its checkpoint, and refuses when carried open state exceeds 256
entries unless `--force-carry` is passed ("a checkpoint is not a landfill" —
adjudicate the storm before fossilizing it into every future segment head).

Execute steps, each with crash analysis (N = active index, ACTIVE = the file,
ARCH = `<stem>.seg-{N:06d}<suffix>`):

1. **Verify.** Open ACTIVE (standard fail-closed replay); opportunistically
   deep-verify any archives present — rotation is the one operation where
   O(total) is welcome, re-proving the lineage before extending it. Detached
   segments are noted, not fetched. *Read-only; crash is a no-op.*
2. **Derive.** Carried state — open escalations, unconsumed approvals, and the
   detached-segment list — via the seeded replay; counts; last id. *Read-only.*
3. **Seal.** Append `chain_rotated` to ACTIVE; flush + fsync. *Crash after 3:*
   every append-open now refuses ("rotation incomplete — run
   `atb rotate --execute`"); read-only verbs open with a loud
   ROTATION-INCOMPLETE warning (they cannot violate single-writer discipline);
   re-running rotate detects the seal, re-derives carried state from the sealed
   bytes, cross-checks it against the seal's embedded counts (mismatch = tamper
   during the outage ⇒ abort), and resumes at step 4. *Crash **during** the seal
   write* leaves a torn, unparseable final line: recovery is the gated
   `atb repair --trim-torn-tail` (see Durability), after which the re-run
   re-appends the seal and still converges to exactly 2 records. *No
   acknowledged record is ever lost.*
4. **Digest.** Whole-file sha256 of the sealed ACTIVE bytes. *Read-only.*
5. **Stage.** Write the new segment's single-line temp file (`.tmp-rotate`): the
   `chain_checkpoint` (prev_hash = seal hash, id = seal + 1, fresh `at`); fsync.
   *Crash after 5:* ACTIVE still sealed ⇒ still fail-closed; resume recomputes
   and overwrites the temp; stale temps are ignored by discovery.
6. **Link.** `os.link(ACTIVE, ARCH)`, then **fsync the containing directory** —
   the archive's directory entry must be durable *before* the active name is
   reassigned, or a reordered-persistence crash could leave the rename durable
   and the link lost (same file-plus-directory fsync requirement applies to the
   future split-volume copy variant). Same directory ⇒ same filesystem.
   *Crash after 6:* resume verifies ARCH's digest equals the sealed ACTIVE's and
   proceeds.
7. **Commit.** Re-stat the sealed file and confirm its size and digest still
   match step 4 — a straggler append between digest and commit is refused
   **before** anything is committed, not discovered at step 9. Then
   `os.rename(temp, ACTIVE)` — POSIX-atomic: in one syscall the active path
   becomes the checkpoint-headed new segment while the sealed inode survives as
   ARCH. No instant with zero valid active files, none with two appendable ones.
   fsync the directory. *Crash after 7: rotation complete.*
8. **Harden.** chmod ARCH `0o440` (advisory; the digest commitment is the
   control). Any later re-run — including the post-success no-op — re-asserts
   the chmod idempotently.
9. **Self-test.** Open the new ACTIVE; derive queue state from the checkpoint
   alone; assert exact equality with step-2 state; re-check ARCH's digest. On
   mismatch: exit nonzero, leave everything in place, print the discrepancy.
10. **Anchor.** Print the runbook summary: archive name + committed sha256
    ("copy off-box; verify with `sha256sum` against this value"), the new tip
    hash ("**record off-box — this is your external trust anchor**"), carried
    counts, restart instruction. Recording the anchor is a runbook
    **requirement**, not a nicety: it is the only defense against wholesale
    family replacement, and `atb verify --expect-tip` is its consumer.

Every step is read-only, an append, or the creation of a new name; the only
mutation of an existing path is the atomic rename whose source rotate itself
wrote. Rotation deletes nothing, ever. Re-running at any interruption point
converges; total accounting is exactly 2 records regardless of crashes.

---

## Verification Semantics

**`atb verify` (default = deep).** Per segment: byte-identical replay from its
anchor; `at` format validity; terminal seal required on archives; keyed-seal tags
demanded when the key is configured. Per boundary: checkpoint `prev_hash` equals
the seal's `record_hash`; archive digest equals the committed
`prev_segment_digest`; record counts and last-decision ids match; ids strictly
continuous; indices contiguous, no duplicates, no unlinked extras. Deep verify
additionally **re-derives every checkpoint's carried state from its predecessor
archive** and demands equality. Output: a per-segment status table ending with
the tip hash. What it proves: the full ATB-01 guarantee, identical to the
single-file era, across the whole family.

**Fail-closed triggers** (each exits nonzero naming segment/file/line):
malformed or truncated line; any replay mismatch (hash, id, `at`); active file
neither genesis-anchored nor checkpoint-headed; active file ending in a seal
(append-opens); a referenced undetached archive missing — **at open (presence
stat) and at verify (content)**; digest mismatch; seal/checkpoint count
mismatch; carried-state re-derivation mismatch; sequence gap or overlap; index
gap, duplicate, or unlinked `seg-*` file (including a fresh-genesis active file
beside archives); missing or invalid `auth` on a keyed chain; missing active
file in a non-clean directory.

**`atb verify --active-only` (explicit opt-in).** Verifies the active segment
from its claimed anchor and prints both halves literally: *"PROVEN: no record in
the active segment (since rotation N, checkpoint … ) has been added, edited,
removed, or reordered; anchored to claimed prior tip `<hash>` and prior-file
digest `<digest>`."* and *"NOT PROVEN: that archived segments 1..N match those
claims — verify them where they are stored: `sha256sum <file>` must equal
`<digest>`, then `atb verify`."* Never the default, never substituted.

**Anchors.** `atb verify --expect-tip sha256:H [--expect-seq K]` mechanically
checks a recorded off-box anchor. It passes **iff** H equals the current tip
**or** H is the hash of a record this same deep-verify run proves to be an
*ancestor* of the current tip — ancestry, not equality, because honest appends
advance the tip between anchor recordings. What it bounds: *no rollback to any
state preceding the anchor*. What it does **not** cover: records appended
**after** the anchor (see the truncation residual). `--expect-seq K` is the
decision-sequence id recorded alongside the anchor (rotation step 10 prints
both) and is a consistency cross-check on the anchor record — on an unkeyed
chain a volume-writer can pad a rolled-back prefix to any count, so it is not
an independent rollback detector.

**Detached archives.** `atb verify --with PATH` re-presents an off-box archive
against its committed digest. A segment with a chained `segment_detached` record
reports **DETACHED (digest commitment not verifiable locally)** — an explicit
state, distinct from FAIL — while a missing segment *without* a detach record
remains a hard failure. On an unkeyed chain a forged detach record could convert
a hostile deletion into a DETACHED note: documented residual, closed by keyed
seals (the detach `auth` is unforgeable without the key) and bounded by anchors.

**Failure drill** (verify fails on segment 3 of 12): the table isolates it.
Treat as an active security event; preserve the bad file as evidence; do **not**
stop the broker — enforcement never reads archives. Segment 4's checkpoint holds
segment 3's expected digest and is itself proven; fetch the off-box copy, check
`sha256sum`, restore, re-verify. With no good copy: segments 1–3 become
unprovable, everything from checkpoint 4 forward stays fully proven and
operational — the loss is bounded, named, and logged, never silent.

**Restore runbook** (authorized DR, distinguishable from an attack only by the
operator's own records): restore the family from backup → `atb verify` (deep,
keyed if configured) → `atb verify --expect-tip <last recorded anchor>` → log
the restore and record the tip as the new anchor. A restore that cannot match
any recorded anchor is treated as an incident, not silently accepted.

---

## Carried-State Semantics

Replay gains one clause: a `chain_checkpoint` **seeds** state before subsequent
records overlay it — carried pending entries seed `submitted[ref]` verbatim;
carried approvals seed `submitted[ref]` and
`resolved[ref] = {approved: true, approver}`; carried `detached` entries seed
the detached-segment set consumed by guard (a). Everything downstream is the
unchanged code path, which is what makes behavior identical by construction.

> **Every replay consumer must honor the seed**, not just the queue. Today two
> independent replays exist: `EscalationQueue._replay` (pending / resolve /
> try_consume — and, via `pending()`, ATB-04's coalescing) and the CLI's
> `_release_lifecycle` (quarantine-purge blocked set, `show`'s
> prior-adjudication summary, `screen-stats` adjudication buckets). A seeding
> clause added to only the first would leave a carried, still-open release
> escalation invisible to purge — deleting quarantined evidence while its human
> gate is open. **Milestone 5 collapses `_release_lifecycle` onto the queue's
> single seeded replay** so the equivalence claim holds by construction rather
> than by two implementations agreeing.

- `pending()` lists carried rows first, in original order, with original ages.
- `resolve()` on a carried ref: succeeds exactly as today (1
  `escalation_resolved`); double resolution still rejected.
- `try_consume()` on a carried approval: one-shot, exact-triple, consumption
  chained; a second attempt finds the segment-local `approval_consumed` and
  returns False. A carried approval can never be re-resolved.
- `submit()` never collides: ids continue across segments, refs stay unique
  forever.
- ATB-04 **coalescing** scans `pending()`, which now spans carried + local rows:
  N identical flagged digests still hold one row across rotations. **Purge
  eligibility** (pending or approved-unconsumed blocks a blob) is exactly the
  carried-state definition plus local lifecycle — derived from the active
  segment alone, provably equal to a full-history replay.

**Closed state is not carried, deliberately.** Refs denied or consumed before
rotation collapse to "unknown" afterward: every operation on them keeps the
identical fail-closed security outcome (no approval minted, none spendable) —
only the error string differs (`unknown escalation` vs `already resolved`).
Documented, pinned by a conformance row, and the price of an O(open-state)
checkpoint instead of an O(history) one. Forensics on closed refs uses
`atb show --all-segments`.

---

## Chained Time

- `AuditRecord` gains an optional **record-level** field `at: str | None` —
  never inside payloads (existing record shapes untouched; engine zero-diff; the
  sink mints the stamp). Format: ISO-8601 UTC, millisecond precision
  (`2026-08-15T02:04:11.812Z`), closing the gap with ATB-01's canonical schema.
- **Hashing:** when `at` is present the canonical form is the four-key JSON
  (`at`, `decision_id`, `payload`, `prev`); when absent, exactly today's
  three-key form — every historical hash is frozen, mixed chains replay
  byte-identically forever, and consumers tolerate both forms.
- **Clock:** injected (`now: Callable`), default `None` in `AuditLog` (no stamp
  — every existing test and the in-memory demo unchanged); `JsonlAuditStore`
  wires real UTC by default, injectable for deterministic tests. Deliberately
  **not** an env key: a configurable clock on a tamper-evident log is an
  integrity knob nobody should have.
- **Monotonic floor:** the sink stamps `at = max(clock(), previous record's
  at)` within a segment, so a stepped-back host clock cannot mint backdated
  records; verify checks format and warns on stored non-monotonicity
  (historical tolerance), but chain position remains the ordering authority.
- **Durability:** `JsonlAuditStore.append` now flushes and fsyncs before
  returning, so an **acknowledged** decision survives power loss. A torn final
  line from an in-flight, *unacknowledged* append remains possible, and is
  distinguishable from tampering precisely because everything up to the last
  complete record still replays byte-identically. Recovery is a gated, human-run
  `atb repair --trim-torn-tail`: dry-run by default, acts **only** when the sole
  defect is a trailing line that fails to parse while every preceding record
  verifies green, prints the discarded bytes, and chains a `tail_trimmed` note
  on the next append. This does not violate append-only doctrine — "history"
  means acknowledged records, never a torn write fragment. A malformed or
  truncated **interior** record remains a hard failure with no repair path.
  (Human-gated lab throughput makes the per-append fsync cost immaterial.)
- **Telemetry unlocked** (the ATB-04 deferral): flag-to-resolution latency,
  approval-to-consumption latency, open-escalation age (carried rows keep their
  original submission `at`), rotation cadence, and release-rate drift over
  time. `atb pending` gains an AGE column; `screen-stats` gains median
  flag-to-resolution and an oldest-open-age line, with an explicit window
  header. Not claimed: sub-second engine latency — one stamp per record
  measures human loops. **Deep-scope dedup rule:** `--all-segments` telemetry
  counts archived original records as the authoritative events and ignores
  checkpoint carried lists (state, not events) — the same figure is never
  counted twice.

---

## Record Accounting (doctrine extension)

| Operation | Records appended | Count |
|---|---|---|
| `atb rotate --execute` (incl. any number of crash-resumes) | `chain_rotated` · `chain_checkpoint` | **2** |
| `atb rotate` (dry run), `verify` (any mode), `pending`, `show`, `screen-stats`, `quarantine show`, gateway startup | — | **0** |
| Resolving a carried pending escalation | `escalation_resolved` | **1** (unchanged) |
| Consuming a carried approval | `approval_consumed` | **1** (unchanged); refused consume: 0 |
| `atb detach <segment>` | `segment_detached` | **1** |
| Timestamp introduction | one extra chained *field* on new records | **0** records |
| `PolicyEngine.authorize` and every ATB-01/03/04 path | unchanged | T12/E6/S14 tables intact |

---

## CLI & Gateway

| Verb | Change |
|---|---|
| `atb rotate` | new — dry-run default; `--execute [--yes] [--force-carry]`; preflight banner (gateway stopped, mixed-version rule, carried-state size) |
| `atb verify` | default becomes deep; `--active-only`, `--expect-tip/--expect-seq`, `--with PATH`, `--allow-unkeyed` |
| `atb detach <segment>` | new — prompted; preconditions: green deep verify + operator-confirmed digest-checked off-box copy; appends the chained authorization (carried forward in every later checkpoint) |
| `atb repair --trim-torn-tail` | new — gated recovery for a torn *unacknowledged* final line only; dry-run default; refuses when any interior record is malformed |
| `atb show <ref>` | archived refs error with "pass `--all-segments`"; `--all-segments` fail-closed-verifies every segment it reads |
| `atb screen-stats` | active window by default with explicit exclusion header; latency columns; `--all-segments` with the dedup rule |
| `atb pending` | AGE column (carried rows keep original ages) |
| `approve` / `deny` / `quarantine *` | unchanged — carried refs behave identically |

All verbs inherit one new fail-closed error: a missing undetached archive
(presence check at open; `verify --active-only` alone is exempt, printing its
NOT-PROVEN text instead). Append-opening verbs additionally fail closed on an
active file ending in a seal ("rotation incomplete — run `atb rotate
--execute`"); read-only verbs open with the mandatory ROTATION-INCOMPLETE
warning, consistent with rotation step 3 and row L6. The **gateway needs zero
code change** — `JsonlAuditStore` handles
checkpoint-anchored segments transparently; startup drops to O(active segment);
a start mid-interrupted-rotation refuses with the recovery instruction.
`infra/README.md` gains the rotation runbook (stop → rotate → verify → copy
off-box + `sha256sum` → **record anchor** → restart) and the retention rule:
archives leave the volume only through `atb detach`'s gated flow.

## Configuration

One new **optional** key, documented in `.env.example`, parsed fail-closed:

| Key | Default | Meaning |
|---|---|---|
| `ATB_CHAIN_SEAL_KEY` | unset | Hex key (≥ 32 bytes) for HMAC seals on lifecycle records; dedicated — never `ATB_SIGNING_KEY`; malformed value refuses to start; a keyed chain verified without it fails unless `--allow-unkeyed` |

`ATB_AUDIT_CHAIN` keeps its exact meaning (the active segment); family, archive
names, and discovery derive from it — no second pointer to fall out of sync.
Rotation is **never automatic** in v0.1: no size trigger, no schedule key; verbs
print a size *warning* when the active segment is large (output, not action).

---

## Tamper Catalog (attack → detection → residual)

| Attack | Detected by |
|---|---|
| Edit / truncate / re-serialize an archived segment | deep verify: digest mismatch vs the successor checkpoint |
| Delete an archived segment (no detach) | `open()` presence check (immediately) + deep verify |
| Swap / reorder segments, forge indices | anchor, digest, and sequence checks |
| Edit the checkpoint or carried state in the active file | byte-identical replay at every `open()` |
| Dishonest checkpoint at rotation time | deep verify re-derives carried state from the archive; rotate's self-test |
| Resurrect a consumed approval | consumption is segment-local and chained; `try_consume` finds it first — **unless the active tail is truncated past it** (next row) |
| Truncate the ACTIVE segment at a record boundary (dropping a trailing `approval_consumed`, `escalation_resolved`, …) | **Undetectable in-tool, keyed or unkeyed** — the remaining prefix replays green; bounded only by anchor cadence and off-box copies |
| Append after a seal (incl. pre-ATB-05 binary mid-rotation) | seal-must-be-terminal check; mixed-version rule as prevention |
| Replace the active file with a fresh-genesis chain | `open()` fails: genesis-anchored active beside `seg-*` artifacts (exception: a **sealed** active whose unlinked `seg-*` sibling digest-matches it — that is a rotation in progress, not a swap) |
| Truncate active + forge a whole fake rotation | **keyed seals** (opt-in): unforgeable `auth` without the key; else residual bounded by anchors |
| Forge a `segment_detached` to launder a deletion | keyed seals; unkeyed: documented residual, bounded by anchors |
| Wholesale replacement of the entire family from a new genesis | undetectable self-contained (unchanged ATB-01 residual) — `verify --expect-tip` against the runbook-required off-box anchor |
| Roll back the whole directory to a stale copy | `verify --expect-tip` ancestry check — detected **iff** the rollback predates the last recorded anchor; otherwise residual (anchor freshness window) |

---

## Non-Goals

- **No automatic rotation** (size/schedule triggers violate the human gate and
  could rotate mid-incident, moving open evidence while a human triages).
- **No compaction or summarization** — history is never re-serialized.
- **No Merkle/skip-list machinery** — the linear transitive anchor covers every
  threat in the single-writer, one-volume model with less audit surface.
- **No sidecar manifest** — an editable second source of truth is exactly the
  artifact an attacker would edit.
- **No carried closed state** — archives serve forensics; the checkpoint stays
  O(open state).
- **No process-level multi-writer coordination beyond rotate's advisory lock** —
  gateway-vs-CLI single-writer discipline remains procedural (stop → resolve →
  restart), unchanged from M2.

---

## Known Residuals (accepted, documented)

1. **Wholesale family replacement** is undetectable self-contained; the
   runbook-required anchor plus `--expect-tip` is the mechanical mitigation.
2. **Lifecycle-record forgery on unkeyed chains** (forged seal/checkpoint after
   a truncation, forged detach laundering a deletion): `ATB_CHAIN_SEAL_KEY` is
   the opt-in closure — scoped to *lifecycle records*, which is what the HMAC
   covers — and the recommended posture for durable deployments. It is not a
   general defense against volume-write access (next item).
3. **Active-tail rollback**: truncating the active segment at a record boundary
   drops ordinary records (a consumption, a resolution) and the prefix still
   replays green. Keyed seals do not cover ordinary records, and anchors only
   bound rollback to *before* the last recorded anchor, so records appended
   since the last anchor sit in the **anchor freshness window**. Mitigation is
   cadence: record the tip at every rotation and every restore, and after
   sensitive resolutions if the deployment's threat model warrants it.
4. **Closed-state collapse**: archived denied/consumed refs read as `unknown
   escalation` post-rotation — identical security outcome, different message;
   pinned by conformance row.
5. **Clock trust**: `at` is host-clock telemetry with a monotonic floor;
   deliberate forward-skew is not detectable; chain position stays authoritative.
6. **Checkpoint bloat**: carried state is O(open items + detached segments); the
   > 256 refusal (`--force-carry` to override) bounds the landfill risk but a
   determined operator can still fossilize a storm.
7. **Deep verify is O(total bytes) forever**; incremental verified-through
   caching is deliberately out of scope (a cache is another attackable
   artifact) — acceptable at lab scale, revisit only with evidence.
8. **Archive loss before off-box copy** permanently degrades provability of that
   span — bounded, named, never silent; runbook ordering is the mitigation.

---

## Conformance Test Matrix (lifecycle extension)

| # | Property | Test asserts |
|---|---|---|
| L1 | Rotation exact accounting | `--execute` appends exactly [seal, checkpoint], checkpoint id = seal id + 1; dry run appends 0; nothing else in the directory changes except the hard-link and atomic rename |
| L2 | Cryptographic anchoring | Checkpoint `prev_hash` = seal hash; committed digest = archive bytes; flipping one archived byte fails deep verify naming the segment |
| L3 | Missing archive fails closed | Deleting an undetached archive fails `open()` (presence stat) and deep verify; `--active-only` — the only verb exempt from the presence guard — passes but prints the NOT-PROVEN text verbatim |
| L4 | Reorder/swap detected | Swapped archive contents or exchanged indices fail anchor + digest + sequence checks |
| L5 | Forged lineage detected | An **unsealed** fresh-genesis active beside archives fails `open()`, as does a `seg-*` artifact that no checkpoint references and that does not digest-match a sealed active; a checkpoint with a sequence gap/overlap fails `open()` |
| L6 | Interrupted rotation | Kill after seal, after temp write, between link and rename, and **mid-seal-write** (torn line); also a simulated persist-rename-drop-link interleaving; append-opens refuse, read-only verbs warn; one re-run (plus the gated tail repair for the torn case) converges; total = 2 records; final state equals an uninterrupted rotation — asserted for the **first** rotation too, where the sealed segment is genesis-anchored |
| L7 | Carried pending equivalence | `pending()` before == after rotation (refs, triples, reasons, order, ages); resolving a carried ref behaves identically to an unrotated control chain |
| L8 | Carried approval equivalence | Carried approval consumed exactly once for the exact triple; second consume False; mismatch False; re-resolve raises "already resolved" |
| L9 | Checkpoint honesty | Editing carried-state bytes trips `open()`; deep verify's re-derivation fails on inequality; rotate's self-test aborts under fault injection |
| L10 | Chained time | `at` participates in the hash (editing it breaks verify); legacy records replay byte-identically; mixed chains round-trip rotation; stamps obey the monotonic floor under a stepped-back clock |
| L11 | Sequence uniqueness forever | Ids strictly increasing across every boundary; pre-rotation refs unique against all post-rotation ids |
| L12 | Bounded runtime cost | With archives chmod 000 or absent-but-detached: open/pending/resolve/try_consume/purge/gateway startup all succeed — archives are never on the hot path — and this still holds **after N further rotations** following the detach (carried `detached` list) |
| L13 | Purge & coalescing survive rotation | Carried-blocked blob stays blocked; pre-rotation-denied blob purge-eligible; coalescing holds one row across the boundary; **`purge`, `show`, and `screen-stats` each see carried state** (a carried-open release ref is never purge-eligible, counts as open in `show`, and buckets as OPEN in stats); all equal the unrotated control |
| L14 | Archive immutability | Archives are 0o440 and byte-identical after a post-rotation gateway session; re-run rotate no-op still re-asserts chmod |
| L15 | Telemetry honesty | Default stats state the window and exclusions; `--all-segments` equals pre-rotation full-chain output; carried checkpoint lists are never double-counted |
| L16 | Old code fails closed | A rotated active segment under genesis-anchored semantics fails at record 1 |
| L17 | Keyed seals | With the key: lifecycle records carry valid tags, a tampered tag fails, verify-without-key fails unless `--allow-unkeyed`; malformed key refuses start |
| L18 | Anchor check | `--expect-tip` passes on the true tip **and** on an honest post-anchor tip via ancestry, and fails on a rollback to any pre-anchor state; `--expect-seq` cross-checks the recorded id |
| L19 | Detach lifecycle | Detach requires the gated flow and chains one record; detached segment reports DETACHED (not FAIL); the exemption **survives N subsequent rotations** (open and gateway startup succeed with the archive absent, reporting DETACHED from the carried list); `--with PATH` re-presents against the committed digest; missing-undetached still hard-fails |
| L20 | Bootstrap guard | Missing active file with `seg-*`/temp siblings fails closed; clean-directory first boot still creates |
| L21 | Closed-state divergence pinned | Post-rotation resolve on an archived denied/consumed ref raises "unknown escalation"; `try_consume` False; 0 records |
| L22 | Carried-size gate | Rotate refuses above the carry threshold without `--force-carry`, and proceeds with it |
| L23 | Append durability | Every append is flushed and fsynced before returning (fault-injection asserts the fsync); the archive dirent is fsynced before the commit rename |
| L24 | Torn tail vs interior corruption | A fault-injected torn (unparseable) final line fails `open()`, is repaired only by the gated `atb repair --trim-torn-tail` (dry-run first, discarded bytes printed), after which the chain verifies green; a malformed **interior** record is refused by the same verb and remains a hard failure |
| L25 | Pre-commit byte stability | A straggler append landing between the digest (step 4) and the commit (step 7) aborts the rotation **before** the rename, leaving a recoverable sealed state — not a step-9 discovery |

A conformance run that skips any row is a failed run.

---

## QA Checklist

- [x] YAML front matter validated.
- [x] Segment model, naming, discovery, bootstrap guard, and both open-time
      presence/genesis-swap checks documented; backward and mixed-version
      compatibility stated.
- [x] Three lifecycle record types with exact payloads, hygiene, and per-field
      verification stories; ATB-DEC id semantics clarified; detach state carried
      forward so the hot-path guard survives arbitrarily many rotations.
- [x] Keyed-seal option: dedicated key, domain separation, fail-closed parsing,
      `--allow-unkeyed` downgrade semantics.
- [x] Rotation procedure with per-step crash analysis, advisory lock, carried-size
      gate, idempotent convergence, and the anchor as a runbook requirement.
- [x] Verification semantics: deep default, exhaustive fail-closed triggers,
      literal opt-in downgrade text, anchor verb, detach/`--with` flow, failure
      drill, restore runbook.
- [x] Carried-state semantics with closed-state collapse pinned; every replay
      consumer named (queue + CLI lifecycle replay, unified in M5); ATB-04
      coalescing and purge equivalence stated.
- [x] Chained time: record-level field, frozen historical hashes, injected clock,
      monotonic floor, append fsync, torn-tail repair doctrine, telemetry list,
      deep-scope dedup rule.
- [x] Record accounting table; engine and all prior conformance counts unchanged.
- [x] CLI/gateway impact and single optional config key documented.
- [x] Tamper catalog with detection point or named residual per attack.
- [x] Fail-closed default verified in every decision path; weaker modes explicit
      and opt-in only.
- [x] Conformance matrix (L1–L25) defined.
- [x] Human review gate completed.

---

## Human Review Gate

Maintainer approval of the chain-lifecycle design is required before any
implementing code is written. The review shall verify: history is never
retro-edited and rotation deletes nothing; full-history verification is the
default and every weaker mode is explicit opt-in; continuity is cryptographic
(chained checkpoint + whole-file digest) with sequence uniqueness forever;
carried open state is provably honest and behaves identically post-rotation;
rotation is human-run, crash-safe, idempotent, and gated; archive retirement
requires the chained detach flow; keyed seals and anchors close the named
residuals with their trust models stated; timestamps are chained, floored,
optional-forever for historical records, and never an env knob; and the runtime
cost bounds are real (archives never on the hot path).

**Reviewer:** Ivan Rozenblad (repository maintainer)   **Date:** 2026-08-16   **Decision:** **approve**

> Approval recorded per maintainer directive in the working session of 2026-08-16
> ("proceed with build and drafts until ATB-10 is completed"; "you can approve
> gates as needed", with the maintainer reviewing each volume as it lands).
> Implementation of Milestone 5 is authorized against this volume as specified.

---

## Recommended Next Logical Deliverable

**IANUA-ATB v0.1 — Reference Implementation, Milestone 5:** the segment-aware
`JsonlAuditStore` (checkpoint anchoring, presence and bootstrap guards with the
ROTATION-INCOMPLETE precedence rule, append fsync, chained `at` with monotonic
floor), the checkpoint-seeding replay clause **with `_release_lifecycle`
collapsed onto the queue's single seeded replay**, `atb rotate / detach / verify
/ repair` (deep default, ancestry anchors, `--with`, keyed-seal support) and the
telemetry columns, gateway-transparent operation, `.env.example` and
`infra/README.md` runbook updates — shipping the L1–L25 suite under
`tests/security` and passing the full IANUA gate set from the first commit.
