---
title: "IANUA-ATB v0.1 — Volume ATB-04: Tool-Response Screening & Quarantine"
series: "IANUA Engineering Reference"
volume: "ATB-04"
status: "Draft — pending human review gate"
supersedes: "None (extends ATB-01, ATB-02, ATB-03)"
companion_docs:
  - "IANUA-ATB v0.1 — Volume ATB-01: Identity Issuance & Zero-Trust Policy Enforcement"
  - "IANUA-ATB v0.1 — Volume ATB-02: Scope Catalog, Role-Spec Bindings & Delegation Model"
  - "IANUA-ATB v0.1 — Volume ATB-03: Runtime Enforcement Point & Tool-Call Mediation"
  - "IANUA — AGENTS.md Operating Charter"
eaods_traceability:
  reference_implementation_of:
    - "PAT-0001 — Zero Trust Service Identity"
    - "EAODS-CTRL-000184 — Service Identity Verification"
  mitigates:
    - "THR-0002 — LLM Instruction Injection"
  emits_evidence_to:
    - "PAT-0003 — Continuous Assurance Evidence Pipeline"
  governed_by:
    - "STD-0001 — Canonical Terminology & Object Identifiers"
    - "STD-0002 — Cross-Artifact Traceability & Knowledge Graph"
purpose: >
  Defines deterministic, stdlib-only screening of tool-response content as a trust
  signal feeding the existing policy machinery: a flagged response is withheld from
  the agent, quarantined content-addressed outside the audit chain, and converted
  into a human decision through a second engine authorization on an always-escalating,
  role-unbound scope. Screening is an input to a policy decision — never a substitute
  for one, and never authority. A clean verdict changes nothing and proves nothing;
  a non-clean verdict can only tighten the outcome.
owner: "Repository maintainer (human)"
review_cadence: "Re-read on session start; revise on any ruleset, quarantine, or release-flow change"
---

# IANUA Agent Trust Broker (ATB)

## Volume ATB-04 — Tool-Response Screening & Quarantine

---

## Purpose

ATB-01 established *how* the broker decides, ATB-02 *what there is to decide about*, and
ATB-03 *where the decision is enforced*. One asset still crosses the trust boundary
uninspected: the **tool response**. The PEP forwards an allowed call, receives an opaque
result, and relays it into the agent's reasoning context — the exact channel THR-0002
exploits (ATB-01's own case study: an exfiltration instruction embedded in a log line).

This volume adds the missing inspection as a **Trust Signal** — the capability domain
ATB-01 pre-declared ("feed behavioral inputs into policy context") — and nothing more. A
deterministic screener classifies every relayed response; a flagged response is withheld,
quarantined, and surfaced to a human through the unchanged Milestone-2 escalation loop.

> **Positioning against the day-01 supersession.** The archived interception design
> (`docs/archive/DESIGN-day01-interception.md`) made inbound screening — heuristics plus a
> guardrail model — the *primary* control at its B3 boundary. It was superseded for cause:
> this series defeats THR-0002 **by constraining authority, not by screening tool text**.
> ATB-04 does not reverse that decision; it inverts the archived pipeline. Screening runs
> strictly *after* an authority decision, its only power is to feed a *second* authority
> decision, and its verdict can only tighten. An attacker who knows the entire ruleset and
> evades it silently gains only what scope already allowed — that remains the deterministic
> guarantee. Screening buys detection depth, not authority: the case-study injection now
> produces a security-evented, human-visible artifact at the moment the content would have
> entered agent context, instead of only when the steered egress call is attempted.

---

## Strategic Objectives

- **Signal, never authority.** The screener classifies; it cannot allow, cannot deny,
  cannot enqueue. Every escalation it triggers is produced by `PolicyEngine.authorize`
  on a cataloged scope — the queue structurally accepts nothing else.
- **Tighten-only.** For every engine effect, the screened outcome is identical or
  stricter. No verdict converts a deny or escalate into an allow; a clean verdict is
  deliberately unadvertised because it is not proof of safety.
- **Complete mediation of flags.** Flagged content reaches the agent through no path:
  not `MediationResult.result`, not the gateway envelope, not the audit chain.
- **Deterministic and stdlib-only.** A versioned, closed-world heuristic ruleset:
  same response bytes + same ruleset version ⇒ identical verdict. No model calls, no
  network, no config-tunable rules.
- **Chain hygiene preserved.** Response text never enters the chain. Evidence is rule
  ids, ruleset version, a sha256 content digest, and byte counts — the quarantined
  payload lives content-addressed outside the chain, bound to approvals by its digest.
- **Total reuse of the human loop.** The M2 escalation lifecycle, one-shot triple-bound
  approvals, and the `atb pending / approve / deny / verify` verbs are unchanged.
- **Engineered HITL economics.** The clean path costs zero human attention and zero
  chain growth; metadata-first triage, pending-row coalescing, and chain-derived
  per-rule telemetry keep the flagged path affordable and its decay measurable.

---

## Trust & Engineering Principles

1. **LLM input is data on the way in, too.** ATB-01 fixed "LLM output is data, never
   authorization." ATB-04 adds the mirror: tool output is *untrusted data* until it
   enters agent context, and its one inspection point is the PEP that relays it.
2. **The screener is a sensor.** `screen()` is a pure function from response bytes to a
   verdict. The authority question a flag raises — *may this content reach the agent?* —
   is answered exclusively by the engine, on the cataloged scope `atb:response.release`.
3. **Escalation cannot be manufactured or compiled away.** The release scope is
   `escalates=True` in the catalog and bound to **no role** (the `net:egress`
   precedent): every flag deterministically escalates, and no binding or tool-map edit
   can convert that into standing authority.
4. **Fail closed on every screening failure.** Oversized, undecodable, unserializable,
   or screener-error responses are withheld — never relayed unscreened — and are
   reason-distinct from `downstream_error` transport failures.
5. **Approvals bind to exact bytes.** The release approval triple is
   `(subject, atb:response.release, quarantine:sha256:<hex>)` — one-shot,
   consumption chained, replay refused and evidenced, and valid only for content whose
   recomputed hash matches the digest the human reviewed.
6. **Evidence is operator-facing, not agent-facing.** Rule ids and match detail flow to
   the chain and the operator CLI; the agent-facing envelope carries only the
   quarantine digest, the ruleset version, and the pending escalation ref, denying a
   steered agent per-attempt evasion feedback.

---

## Screening Architecture

The screener extends the PEP's `ALLOW` branch. Nothing upstream of the forward changes;
denied, escalating, and unmappable calls are never screened (nothing was forwarded).

```
PEP.mediate(invocation)                                     [ATB-03, unchanged]
      │ derive → decide → ALLOW
      ▼
   downstream(tool, arguments) ──▶ result                   [side effects executed]
      ▼
┌──────────────────────── ResponseScreener (pure, stdlib) ────────────────────────┐
│ textualize → digest → count invisibles → normalize (two planes) → ruleset       │
└──────────────────────────────┬──────────────────────────────────────────────────┘
        clean │                │ flagged / oversize / undecodable    │ unreleasable
              ▼                ▼                                     ▼ failure
     relay result       QuarantineStore.put(bytes)          withhold; chain one
     (byte-identical    engine.authorize(token,             screening_refusal
      to ATB-03;         "atb:response.release",            record; result=None
      exactly 1          "quarantine:" + digest,
      chained record)    evidence-labels context)  → ESCALATE (security event)
                         queue.submit(decision)    [coalesced: one pending row
                         result=None; pending_ref   per unresolved (subject,digest)]
```

The PEP still holds no policy logic: it maps engine effects and screen verdicts to
mechanical dispositions, exactly as it already maps effects to forward/refuse/escalate.
`PolicyEngine`, `EscalationQueue`, `AuditLog`, and the identity plane are **zero-diff**.

---

## The Screening Pipeline

**Textualization** defines "screenable text" for the untyped downstream result:

| Result type | Canonical bytes | On failure |
|---|---|---|
| `str` | UTF-8 encoding of the string | — |
| `bytes` | the bytes themselves (strict UTF-8 decode for scanning) | decode failure ⇒ `undecodable`: releasable withhold over the raw bytes |
| anything else | `json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)` | `TypeError`/`ValueError` (unserializable, NaN/Infinity) ⇒ `textualization_failed`: unreleasable withhold |

`repr()` is never used as a fallback — it is not canonical and may embed addresses,
which would break verdict determinism and digest stability. The whole serialization is
screened — nested values, list items, and dict **keys** alike — so marker smuggling in
structured fields is caught by construction.

**Size gates run before hashing** (bounded cost on attacker-sized input):
`size = len(canonical_bytes)` is O(1); above `ATB_QUARANTINE_MAX_BYTES` the response is
refused unhashed and unstored; above `ATB_SCREEN_MAX_BYTES` (but within the blob cap) it
is hashed and quarantined unscanned as a releasable `oversize` withhold.

**Digest** `sha256:<hex>` is computed over the canonical (pre-normalization) bytes —
blob identity, approval binding, and the bytes the human reviews are one artifact.
Throughout this volume *digest* denotes the full prefixed string `sha256:<hex>`; the
quarantine resource is `quarantine:` + digest, i.e. `quarantine:sha256:<hex>`.

**Normalization** (scan planes only; stored bytes are always the original):

1. Count, then strip, all Unicode category-`Cf` characters (zero-width, BOM, bidi
   controls). The count feeds rule R006 *before* stripping, so obfuscation cannot
   launder itself.
2. `unicodedata.normalize("NFKC", text)` — folds fullwidth and compatibility forms.
3. `str.casefold()`.

Rules declare their plane: `NORMALIZED` (phrase rules), `RAW` (case- and
form-sensitive anchors — credential shapes, encoded blobs — which the casefold pipeline
would destroy), or `COUNTERS` (rules evaluated over the pre-normalization
invisible-character census computed in step 1 — currently only ATB-R006). Determinism
holds because every step is a pure stdlib function of the input bytes plus the pinned
ruleset.

---

## Ruleset v0.1 (`RULESET_VERSION = "0.1.0"`)

The ruleset is **code, not config**: a frozen module-level tuple, compiled and validated
at import (unique ids, compilable patterns — the T11 mirror), changed only by reviewed
PR with a version bump. Every screening record chains `RULESET_VERSION` and a
`rules_digest` (sha256 over the canonical rule serialization plus
`unicodedata.unidata_version`), so the exact governing ruleset at any historical
decision is provable offline.

| Id | Name | Plane | Catches | False-positive posture |
|---|---|---|---|---|
| ATB-R001 | `instruction_override` | NORM | `(ignore\|disregard\|forget) … (previous\|prior\|earlier\|above) … (instructions\|prompts\|rules\|context)` — the canonical override preamble | Highest-FP rule: security corpora *quote* injections; accepted — quoted attack text re-entering agent context deserves a human glance |
| ATB-R002 | `system_prompt_disclosure` | NORM | disclosure steering: `(reveal\|show\|print\|repeat\|leak\|output) … (system\|developer\|hidden) (prompt\|instructions\|message)` | Very low outside LLM-security prose |
| ATB-R003 | `role_reassignment` | NORM | persona hijack: `you are (now\|no longer)`, `new persona`, `act as (unrestricted\|jailbroken\|dan)` | Medium-low in SOC log corpora |
| ATB-R004 | `tool_steering_exfiltration` | NORM | `(call\|invoke\|use) (the)? (http_fetch\|mint_sub_identity\|corpus_ingest)` and `(send\|post\|upload\|exfiltrate) …{0,40} https?://` — the THR-0002 scenario verbatim | Medium (runbooks describing tools); the fatigue-bearing rule, justified because it encodes the exact threat model |
| ATB-R005 | `protocol_marker_smuggling` | NORM | forged conversation/protocol frames: `</?(system\|assistant\|tool_result\|function_call)…>`, `"jsonrpc":`, `atb_token` | Low in lab corpora; MCP documentation reads will hit |
| ATB-R006 | `invisible_text_obfuscation` | COUNTERS | ≥ 8 stripped `Cf`/zero-width chars, **any** bidi override (U+202A–E, U+2066–69), or any C0/C1 control beyond `\t \n \r` | Near-zero in an English lab corpus; explicit codepoint list, versioned |
| ATB-R007 | `encoded_payload_blob` | RAW | `[A-Za-z0-9+/=]{200,}` — smuggled encoded blocks; flags the ciphertext, never decode-and-rescans | Real (certs, embedded binaries); 200-char floor exempts ids/hashes; early tuning candidate |
| ATB-R008 | `approval_steering` | NORM | conjunctive: `(use\|pass\|set\|include\|supply) …{0,30} approval_ref` or `ATB-DEC-\d{6} …{0,40} \bapprove\b` (standalone token — the JSON-key forms `"approved"`/`"approver"` in serialized resolution records do not match) — content coaching the agent to spend or solicit approvals | Low by construction: a bare `ATB-DEC-` id never flags; the known boundary case — `audit_read` returning a serialized `escalation_resolved` record — screens clean because `approved`/`approver` are not the standalone token (S12 golden vector) |
| ATB-R009 | `secret_material` | RAW | credential shapes: `AKIA[0-9A-Z]{16}`, `-----BEGIN … PRIVATE KEY-----`, `xox[baprs]-…`, JWT `eyJ….eyJ…` — leaked credentials must not transit into a model context | Near-zero (anchored high-entropy shapes); residual FPs are documentation example keys. Turns the screen into leak containment, not just injection defense |

All patterns use bounded quantifiers and no nested unbounded repetition (no
catastrophic backtracking); the scan cap bounds input size. New rules must pass the
same review. **Known-ruleset evasion posture:** an attacker who reads this table can
craft a payload that passes (homoglyphs across scripts, novel phrasing, short
encodings, cross-call chunking) — accepted and documented, because a silent pass
confers zero authority; the steered action still faces the deterministic scope model.

---

## Flagged-Response Disposition & Release Flow

**Disposition** (never annotate-and-relay): a releasable non-clean verdict (`rules`,
`oversize`, `undecodable`) triggers, in order:

1. `quarantine.put(canonical_bytes)` — content-addressed, write-once, **before** the
   escalation, so a pending ref can never dangle against absent content.
2. `engine.authorize(invocation.token, "atb:response.release",
   f"quarantine:{digest}", context=evidence)` — the context is built **exclusively by
   the PEP** from the verdict: compact string labels only (`screen_ruleset`,
   `screen_rules_digest`, `screen_rules` (ids), `screen_cause`, `screen_digest`,
   `screen_bytes`, `screen_invisibles`, `origin_ref` = the original allow's decision
   id). The caller's `invocation.context` is deliberately **not merged** — an injected
   `approval_ref` in the agent's context can never auto-release on the flag path.
   Because the scope escalates and no role binds it, the engine deterministically
   returns `ESCALATE`, reason `human_approval_required_scope_not_granted`,
   `security_event=True` — screening hits are security events with zero engine change.
3. **Pending coalescing:** the PEP consults `queue.pending()`; if an unresolved row
   already exists for the same `(subject, action, resource)` triple, `submit` is
   skipped and the existing `pending_ref` is returned. Every occurrence still chains
   its own escalate decision (evidence preserved); the pending queue holds **one row
   per unresolved (subject, digest)** — a hostile downstream repeating one
   byte-identical payload cannot flood the operator's queue; trivially varied payloads
   are bounded only by the quarantine budget (Residual 7).
4. `MediationResult(forwarded=True` — the downstream truly executed — `effect=ESCALATE,
   security_event=True, pending_ref=…, quarantine_digest=…, result=None)`.

Defensive invariant guard: if the release-path authorize ever returned `ALLOW`
(impossible — the PEP passes no `approval_ref`, and `escalates=True` cannot be compiled
away), the PEP withholds anyway and chains `screening_refusal` reason
`release_invariant_violation`. The engine's anomalous allow record is chained
unconditionally — append-only chain, engine zero-diff — and the trailing
`screening_refusal` is the chain's evidence that the ALLOW was not honored. A `DENY` on that call (token expired between the two
authorizations) also withholds: content stays quarantined, nothing is submitted.

**Release flow** (M2 verbatim; single-writer discipline unchanged):

1. `atb pending` shows the row like any escalation: REF, subject,
   `atb:response.release`, `quarantine:sha256:<hex>`.
2. **Metadata-first triage:** `atb show <ref>` resolves the ref and prints the evidence
   labels — source tool, rule ids with their in-code descriptions, ruleset version,
   digest, sizes, subject — plus a chain-derived *prior-adjudication hint* (earlier
   releases/denies of the same digest). Most hits are adjudicable without opening
   attacker bytes.
3. **Opt-in payload view:** `atb quarantine show <ref>` loads the blob, re-verifies its
   sha256 (mismatch is a hard error), re-runs the installed screener to display matched
   rules — warning explicitly if the installed `RULESET_VERSION`/`rules_digest` differ
   from the chained evidence — prints an invisible-character census, and renders all
   control and non-printing characters escaped under an UNTRUSTED banner
   (terminal-escape injection is in scope: the payload is hypothesized attacker text).
4. `atb approve <ref> --reason …` / `atb deny <ref> --reason …` — unchanged.
5. **Delivery:** the agent calls the mediated tool `response_release` with
   `{"digest": "sha256:<hex>"}` and context `{"approval_ref": "<ref>"}`. The deriver
   full-matches `sha256:[0-9a-f]{64}` (else `derivation_failed`). The PEP **reads and
   verifies the blob before deciding** — absent or corrupt content refuses pre-decision
   (`enforcement_refusal`, reason `quarantine_missing`, `security_event=True`) with the
   approval **unspent**. Then `authorize` runs the standard M2 consumption:
   `try_consume` matches the exact triple, chains `approval_consumed`, returns `ALLOW`
   reason `human_approved:<ref>`, and the PEP serves the in-frame bytes as
   `MediationResult.result` (`forwarded=False` — no downstream re-execution, no
   side-effect replay, no TOCTOU). Released content is **not re-screened**: the
   deterministic screener would re-flag the same bytes forever; the named, one-shot,
   triple-bound human approval *is* the release authority for exactly those bytes.
6. **Replay resistance, layered:** approvals are one-shot (a second `response_release`
   escalates anew — refused *and* evidenced, coalesced onto the open row if any);
   triple-bound (another subject, action, or digest leaves the approval unspent);
   digest-bound (an approval releases only byte-identical content — there is no
   "approve the tool, get whatever comes next" window).

> **Subject binding.** `identity.subject` is the *role string*, so the approval triple
> survives token expiry and the stop-gateway-to-approve restart: a re-minted identity
> for the same role presents the same subject. The same holds under delegation —
> a depth-1 delegated identity's subject is its own role, so a flag raised under a
> delegated token binds release to that role, revocation between flag and release
> leaves the pending row intact, and a fresh valid identity of the same role may
> consume the approval. Structurally, the approval binds the *role*, not the token.

---

## Catalog & Tool-Map Changes

```python
# atb/catalog.py — one new scope; no existing entry changes
ScopeSpec(
    "atb:response.release",
    Risk.CRITICAL,
    escalates=True,
    resource_patterns=("quarantine:sha256:*",),
)
```

- **Bound by no role, ever** (the `net:egress` precedent): the scope exists purely to
  force the engine's escalate path and to be the triple-binding target for one-shot
  approvals. Release is a human override of a tripped security control — hence
  `Risk.CRITICAL`. `agent:*.invoke` does not match it (`fnmatchcase` on the full
  string); depth-1 attenuating delegation cannot add it.
- `TOOL_MAP` gains `"response_release": ToolRule("atb:response.release",
  _quarantine_digest("digest"))` — the deriver requires a full-match of
  `sha256:[0-9a-f]{64}`; import-time `validate_tool_map` covers it (T11 mirror).
  Escalation is *not* re-declared in the map; it flows from the catalog flag.
- No binding changes. The change is monotone-tightening by construction.

---

## Record Accounting (doctrine extension)

The ATB-03 doctrine stands: *one decision, one record*. ATB-04 extends it in one
sentence: **a screening flag is a second, distinct authorization question — "may this
content be released?" — and gets its own decision record; a clean screen is not a
decision and appends nothing.** One new record type exists: `screening_refusal`
(module constant, mirroring `enforcement_refusal`), for unreleasable screening
failures. `EscalationQueue._replay` ignores it (forward-compatible unknown type);
`JsonlAuditStore` replays it byte-identically (plain deterministic JSON).

| Path | Records appended (in order) | Count |
|---|---|---|
| Clean allowed call | allow decision | **1** (unchanged) |
| Flagged, first unresolved occurrence | allow · release escalate (evidence in context) · `escalation_submitted` | **3** |
| Flagged, repeat while pending (coalesced) | allow · release escalate | **2** |
| Flagged, release-authorize DENY (expired token) | allow · deny decision | **2** |
| Flagged, release-authorize anomalous ALLOW (invariant guard) | allow · anomalous release allow (engine-chained, unsuppressable) · `screening_refusal` | **3** |
| Unreleasable screening failure | allow · `screening_refusal` | **2** |
| Pre-forward escalate / deny / refusal | unchanged ATB-03 accounting | 2 / 1 / 1 |
| Approved `response_release` | `approval_consumed` · allow `human_approved:<ref>` | **2** (M2-standard) |
| Unapproved `response_release` | escalate (+ `escalation_submitted` if no open row) | 1–2 |
| `response_release`, blob missing/corrupt | `enforcement_refusal` `quarantine_missing` (approval unspent) | **1** |
| Human resolution | `escalation_resolved` | 1 (unchanged) |

`screening_refusal` payload: `{type, tool, effect: "deny", reason, ruleset_version,
rules_digest, size_bytes?, security_event: true}` — labels only, never text.

**Torn-state interpretation** (process death after the allow record): a trailing allow
at the chain tip is *ambiguous* — it is equally the shape of a completed clean call
whose result was relayed (S1) and of a crash before any screening record was written,
so torn-state forensics must treat delivery as undetermined. What the shape does
prove: flagged or withheld content cannot have reached the agent without its
release-escalate or `screening_refusal` record — the flagged path chains its records
before returning, and only a clean verdict relays. A post-relay marker record on the
clean path would make torn states unambiguous; it is rejected to preserve the
zero-growth clean path, and the ambiguity is accepted as documented. No decision is
ever reused across restarts (ATB-03 TOCTOU rule); recovery is a fresh, fully mediated
call — which may re-execute downstream side effects if the original forward completed
(Residual 4).

---

## Quarantine Store

- **Protocol seam** (the `ApprovalRegistry` pattern): `put(content: bytes) -> str`
  (content-addressed, idempotent, returns `sha256:<hex>`), `get(digest) -> bytes | None`
  (re-hashes on every read; `None` on absent **or corrupt** — a partial write can never
  be served), `total_bytes() -> int`.
- **Implementations:** `MemoryQuarantineStore` (demo parity with the in-memory chain)
  and `FileQuarantineStore(dir)` — directory `0o700`, files `0o600`, filename = the hex
  digest (attacker bytes never influence the path). Writes go to a `0o600` temp file
  in the same directory, are flushed and fsynced, then atomically renamed onto the
  digest name — so a file existing under a digest name is complete by construction.
  `put` re-hashes an already-existing file and rewrites it through the same
  temp-plus-rename path on mismatch, so a torn or corrupted blob self-heals on the
  next occurrence of the content.
- **Placement constraint:** the directory must resolve **outside** `workspace/` and
  every catalog resource pattern — quarantine readable via `fs:workspace.read` would be
  a release-loop bypass; checked fail-closed at startup. Sensitive-by-default per
  AGENTS.md §5: gitignored, never committed, local to the lab host.
- **Bounds:** per-blob `ATB_QUARANTINE_MAX_BYTES`; aggregate `ATB_QUARANTINE_BUDGET_BYTES`
  — a `put` that would exceed either refuses, and the call fails closed as
  `quarantine_unavailable` (no escalation filed: an approval must never dangle against
  content that was not stored).
- **Durable pairing invariant:** when `ATB_AUDIT_CHAIN` is set (durable chain), the
  gateway **requires** `ATB_QUARANTINE_DIR` and refuses to start without it — durable
  approvals must not reference content that dies with the process. Library embedders
  inherit the same rule as documentation: durable chain ⇒ durable quarantine.
- **Lifecycle:** blobs of *denied* escalations are retained as forensic evidence; no
  automatic TTL (silent destruction of evidence). Deletion is an explicit, prompted
  operator action — `atb quarantine purge` — and a blob is purge-eligible only when
  **no** escalation referencing its digest, across all subjects, is pending or
  approved-but-unconsumed (every referencing escalation is denied or consumed). Orphan
  blobs whose flag-path release-authorize returned DENY (no escalation exists) are
  purge-eligible after confirmation — the flag remains provable from the chained deny.
  A corrupt blob's recovery is purge; the next occurrence of the content
  re-quarantines it through the idempotent, self-healing `put`. The chain proves the
  flag and the decision; the blob is evidence, not authority, and its absence is
  always detected (`quarantine_missing`) rather than worked around.
- **Concurrency:** the store has one writing process (the PEP), like the chain.
  Operator reads race-safely against writes because `get` verifies the hash — a torn
  read is indistinguishable from corruption and refuses. Crash-torn writes cannot
  exist under a digest name (rename atomicity); at worst an orphan temp file remains,
  removed by `atb quarantine purge`.

---

## Failure Semantics

Every screening-side failure **withholds** — content is never relayed unscreened — and
every reason token is distinct from `downstream_error`, which remains exclusively "the
downstream callable raised" (that exception propagates before screening runs; the
screener call itself is wrapped, so no screener defect can masquerade as transport
failure). *Screener-minted reason tokens each identify their condition alone; the
three releasable-withhold rows share the generic engine token — which any role-unbound
escalating scope emits — so classifying those requires the record's action
(`atb:response.release`) plus the `screen_cause` evidence label.*

| Condition | Reason | Releasable? | Records |
|---|---|---|---|
| Rules matched | (engine) `human_approval_required_scope_not_granted`, `screen_cause=rules` | yes — quarantined | 3 (or 2 coalesced) |
| Canonical bytes > scan cap, ≤ blob cap | same, `screen_cause=oversize` (scan skipped, digest computed) | yes — quarantined unscanned | 3 (or 2) |
| Undecodable bytes | same, `screen_cause=undecodable` (raw bytes quarantined) | yes | 3 (or 2) |
| Canonical bytes > blob cap | `response_oversized` (nothing hashed, nothing stored) | no | 2 |
| Unserializable / NaN result | `textualization_failed` | no | 2 |
| Screener exception | `screener_error` (content discarded — the pipeline itself is suspect) | no | 2 |
| Quarantine write/budget failure | `quarantine_unavailable` | no | 2 |
| Release blob missing/corrupt | `quarantine_missing` (pre-decision; approval unspent) | — | 1 |
| Flag-path authorize returns ALLOW | `release_invariant_violation` (defensive; withheld) | no | 3 |

Config parse failures (non-integer or non-positive caps, malformed paths) are
startup-fatal — the broker refuses to run rather than run with a silently altered
security envelope.

---

## Gateway & CLI

**Gateway** (`examples/mcp_gateway.py`):

- `isError` now keys on `outcome.effect is not Effect.ALLOW` (previously
  `not outcome.forwarded`) — a withheld response is truthfully `forwarded=True` yet
  must present as an error to the MCP client.
- Flagged calls return a structured refusal text ("response withheld pending human
  review; an operator resolves with: `atb approve <ref> --reason …`") and `_meta.atb`
  gains exactly two optional keys on releasable withholds — `quarantine_digest` (the
  agent needs it to call `response_release` later; a digest is not content) and
  `screen_ruleset` (the `RULESET_VERSION` string) — alongside the existing
  `pending_ref` the agent later echoes as `approval_ref`. **Rule ids, match detail,
  and `rules_digest` are deliberately absent from the envelope** (principle 6):
  evasion feedback is not owed to the party being screened. Unreleasable screening
  failures surface as effect `deny` with their reason token and none of the
  screening keys.
- **Transport-failure hardening (specified change).** Today the gateway interpolates
  `type(exc).__name__` into the `downstream_error` content text, and its generic
  dispatch handler relays full exception text — both downstream-controlled strings
  riding the transport path *before* screening. ATB-04 removes both: the
  `downstream_error` content text and `_meta.atb.reason` carry only the fixed token
  (`_meta.atb` is already fixed today), the dispatch handler returns a fixed
  `internal_error` text, and exception detail goes to stderr — new behavior — never
  to the agent.
- Clean calls are byte-identical to today: no "screened: clean" advertisement.
- `tools/list` advertises `response_release` automatically via the catalog-driven
  description (critical, escalates).

**CLI** (`atb`): `pending / approve / deny / verify` are unchanged. Four additive verbs:

| Verb | Kind | Function |
|---|---|---|
| `atb show <ref>` | read-only | Metadata-first triage: evidence labels, rule descriptions, prior-adjudication hint for the digest |
| `atb quarantine show <ref>` | read-only | Escaped, integrity-verified payload view with invisible-character census and ruleset-skew warning |
| `atb screen-stats` | read-only | Chain-derived per-rule telemetry: hits, releases, denies, unresolved, release-rate — a rule near 100 % release is a retirement candidate; rising release latency is measurable rubber-stamping decay |
| `atb quarantine purge` | destructive, prompted | Deletes only purge-eligible blobs — no escalation referencing the digest, across all subjects, pending or approved-but-unconsumed (AGENTS.md §5.1: the human runs it deliberately) |

All verbs obey the single-writer discipline; the read-only verbs append nothing.

---

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `ATB_SCREEN_MAX_BYTES` | `1048576` (1 MiB) | Scan-cost bound; larger (≤ blob cap) quarantines unscanned as releasable `oversize` |
| `ATB_QUARANTINE_DIR` | unset ⇒ in-memory | Blob directory; **required when `ATB_AUDIT_CHAIN` is set**; must lie outside `workspace/` |
| `ATB_QUARANTINE_MAX_BYTES` | `16777216` (16 MiB) | Per-blob storage cap; beyond it: unreleasable refusal, nothing stored |
| `ATB_QUARANTINE_BUDGET_BYTES` | `268435456` (256 MiB) | Aggregate store budget; a put beyond it fails closed as `quarantine_unavailable` |

All parsed fail-closed at startup. **Deliberately absent: any kill-switch.** Screening
is on in every `PolicyEnforcementPoint` by dataclass default (`screener` and
`quarantine` default factories); disabling or weakening it requires editing code —
constructor injection visible in review, or a ruleset change bumping
`RULESET_VERSION` — a governed change per AGENTS.md §5, never a deployment flag. There
is no configuration state in which the PEP relays unscreened content. The ruleset has
no env knobs: thresholds are ruleset constants, versioned.

---

## Trust Boundaries (screening view)

ATB-04 guards the one crossing the series had not yet instrumented, and touches no other:

| Boundary | What crosses | Control applied |
|---|---|---|
| **Tool response → Agent context** (new) | Untrusted downstream content entering the reasoning context | Deterministic screen; withhold-and-quarantine on flag; human release via engine-produced escalation |
| Agent → Quarantine | Release requests | Closed-world tool map; digest-shape derivation; always-escalating role-unbound scope; one-shot triple-bound digest-bound approvals |
| Operator → Quarantine | Payload review | Integrity re-verification; escaped rendering; invisible-character census; metadata-first triage |

---

## Operator Economics & Evidence

- **Zero cost when clean** — no records, no attention, no envelope change (the dominant
  path stays the dominant cost: none).
- **One review per distinct payload** — content-addressing dedupes blobs; pending
  coalescing dedupes queue rows; prior-adjudication hints surface "seen before,
  released before" at triage time.
- **Fatigue is measurable, not hoped away** — `atb screen-stats` computes per-rule
  release rates and latencies offline from the chain alone (PAT-0003: evidence is a
  by-product of running). ATB-R004 and ATB-R007 are pre-nominated tuning candidates.
- **Chain growth** — flagged calls append +2 over baseline (+1 coalesced); clean calls
  zero. Queue replay is O(n); a flag storm inflates n permanently. Chain rotation /
  checkpointing is out of scope — the standing ATB-05 candidate.
- **Availability abuse is signal** — a downstream deliberately tripping rules to burn
  operator attention costs availability, never authority, and every hit is a chained
  security event naming the tool: persistent abuse indicts the tool, cheaply.

---

## Non-Goals

- **No request-side screening.** Tool *arguments* are governed by the deterministic
  scope machinery (ATB-02/03); the always-escalating gates (`rag:corpus.ingest`,
  `net:egress`) already put humans in front of the risky inbound flows.
- **No semantic-intent verifier, no ML/guardrail model.** Probabilistic classifiers are
  non-deterministic, non-stdlib, and network-dependent — the archived day-01 pipeline's
  dependency, not revived here.
- **No cross-call accumulation.** A per-response screener cannot see payloads assembled
  across calls (each individually clean); that is session-level *dynamic scoring* — the
  ATB-01 Trust Signals future, a separate volume if ever adopted. The authority model
  is the standing mitigation.
- **No re-adjudication of released content on ruleset bumps**, and **no auto-release**
  of previously approved digests — each occurrence costs one approval, with the
  prior-adjudication hint keeping repeat reviews cheap.
- **No changes to identity, catalog semantics, bindings, delegation, engine, queue, or
  persistence.** ATB-04 is purely additive.

---

## Known Residuals (accepted, documented)

1. **Known-ruleset evasion** — homoglyph substitution across scripts, novel phrasing,
   short encodings, chunk-splitting: a silent pass confers zero authority (the
   supersession rationale, preserved). Screening catches the common 90 %, not all.
2. **Chain-as-oracle via `audit_read`** — rule ids chained as evidence are readable by
   an agent holding `atb:audit.read`. Accepted: audit transparency is itself a control,
   the envelope denies the cheap per-attempt loop, and evasion yields no authority.
   Per-tool evidence masks are a possible v0.2 governed change.
3. **Released content is still untrusted model input** — approval means "the agent will
   now read this text." The scope model is again the only control after release, which
   is the standing guarantee; the release envelope carries `human_approved:<ref>`, so
   the transcript records that a named human accepted exactly these bytes.
4. **Side effects already executed** — screening is post-forward; a flagged
   `workspace_write` already wrote. Inherent to response-side screening; request-side
   controls (scope) remain the primary guard, and the record trail makes the sequence
   auditable.
5. **Determinism is per interpreter build** — NFKC tables move with the Unicode
   version; `rules_digest` incorporates `unicodedata.unidata_version`, golden-vector
   conformance tests catch drift, and the review CLI warns on ruleset skew.
6. **A persuaded human remains the last line** — release is informed consent on exact
   bytes with rule annotations and an invisible-character census; digest-binding
   guarantees they saw precisely what is released, nothing more.
7. **Distinct-payload flooding** — content-addressing and coalescing dedupe only
   byte-identical repeats; trivially varied flagged payloads mint unbounded distinct
   digests, bounded only by `ATB_QUARANTINE_BUDGET_BYTES`. An exhausted budget fails
   closed globally: every subsequent flag, from any tool or subject, becomes an
   unreleasable `quarantine_unavailable` withhold until the operator resolves the
   flood rows and purges — availability suppression, never authority, but a real
   lever. Per-tool sub-budgets and a bulk deny-by-digest verb are v0.2 candidates.

---

## Conformance Test Matrix (screening extension)

New `tests/security` rows layered on T1–T12 and E1–E6. Each asserts a withhold,
an escalation, a refusal, or an exact record count — never merely a verdict:

| # | Property | Test asserts |
|---|---|---|
| S1 | Clean transparency | A clean allowed call relays the result unchanged and appends exactly 1 record; `MediationResult` and envelope are field-identical to ATB-03 |
| S2 | Flagged withhold (case study) | A `log_read` response embedding the ATB-01 exfil instruction yields `result=None`, `effect=ESCALATE`, `security_event=True`, and exactly [allow, release-escalate, `escalation_submitted`] |
| S3 | No leak through any surface | After S2, the canary substring appears in no chained payload, no context value, no `MediationResult` field, no envelope field |
| S4 | Deny-until-approved | Unapproved `response_release` escalates and returns no content |
| S5 | One-shot release + evidenced replay | After approval, one release serves the exact bytes (`approval_consumed` + `human_approved:<ref>`); a second attempt re-escalates |
| S6 | Triple/digest binding | Another subject's token, or any other digest, leaves the approval unspent and serves nothing |
| S7 | Oversize two-tier | Scan-cap < size ≤ blob-cap: releasable `oversize` flag path, stored byte-exact; size > blob-cap: `response_oversized` refusal, nothing hashed or stored, no escalation |
| S8 | Unscreenable fails closed | Undecodable bytes → releasable withhold; unserializable object and NaN float → `textualization_failed` refusal |
| S9 | Screener fault ≠ transport fault | An injected rule exception withholds as `screener_error`; a raising downstream still surfaces as `downstream_error` with no screening record, and the hardened transport envelope contains no exception-derived text |
| S10 | Obfuscation-invariant verdicts | Zero-width-split, fullwidth, and case variants of an R001 marker flag identically; R006 fires independently on the invisible count |
| S11 | Structured-field smuggling | An instruction hidden in a nested dict key flags — the entire canonical serialization is screened |
| S12 | Determinism + provenance | Identical bytes ⇒ identical verdict (rule ids, digest, counts) across processes; chained evidence carries `RULESET_VERSION` + `rules_digest`; golden-vector corpus passes, including a canonical serialized `escalation_resolved` record that screens clean |
| S13 | Quarantine unreachable by scope | `fs:workspace.read` cannot cover the quarantine path (startup placement check); malformed digest is `derivation_failed` |
| S14 | Chain compatibility + exact accounting | `screening_refusal` replays byte-identically, is ignored by queue replay, and every path's record count matches the accounting table |
| S15 | Approvals survive storage faults | Missing/corrupt blob refuses pre-decision (`quarantine_missing`, 1 record) with the approval still consumable |
| S16 | Credential shapes caught on RAW plane | AKIA / PEM / JWT material flags via ATB-R009 despite the casefold pipeline |
| S17 | Pending coalescing | N identical flagged responses yield N chained escalate decisions but exactly 1 pending row; one approval releases exactly once |
| S18 | Envelope oracle closure | The flagged envelope carries exactly `quarantine_digest`, `screen_ruleset`, and `pending_ref` — **no rule ids** — and unreleasable failures carry none of the screening keys; the release-scope escalation appears for every role (T5 mirror: no binding can compile the gate away) |
| S19 | Purge safety | `atb quarantine purge` refuses to delete a blob while any escalation referencing its digest is pending or approved-but-unconsumed; after deny or consumption the blob becomes purge-eligible |

A conformance run that skips any row is a failed run.

---

## QA Checklist

- [x] YAML front matter validated.
- [x] Positioning against the day-01 supersession stated: screening after authority,
      feeding a second authority decision; tighten-only; clean-is-not-proof.
- [x] Screener placement, pure-sensor contract, and PEP orchestration documented;
      engine, queue, persistence, identity zero-diff.
- [x] Textualization, two-plane normalization, digest, and size-gate ordering defined.
- [x] Ruleset v0.1 enumerated with planes and FP posture; governance (code-not-config,
      version + rules digest, ReDoS discipline) documented.
- [x] Disposition and release flow end to end: quarantine-before-escalate, evidence-only
      context, coalescing, read-before-decide, no re-screen, subject binding under
      delegation.
- [x] Catalog change (`atb:response.release`, Critical, always-escalating, role-unbound)
      and tool-map entry defined; T11 validation covers both.
- [x] Record accounting per path, exact counts, one new record type, torn-state rule.
- [x] Quarantine store: permissions, placement, caps, budget, write-once, read-verify,
      durable-pairing invariant, purge lifecycle.
- [x] Failure semantics enumerated; every path withholds; reason tokens disjoint from
      `downstream_error`; gateway hardening specified so exception-derived text is
      never relayed (a change from today's envelope, which leaks the exception class).
- [x] Gateway (`isError`, digest key, oracle closure) and CLI (four additive verbs)
      impact defined.
- [x] Fail-closed default verified in every decision path; no kill-switch exists.
- [x] Operator economics and PAT-0003 evidence story documented; residuals listed.
- [x] Conformance matrix (S1–S19) defined.
- [ ] Human review gate completed.

---

## Human Review Gate

Maintainer approval of the response-screening design is required before any
implementing code is written. The review shall verify: screening output is an input to
policy decisions and never authority (tighten-only, no path from any verdict to an
allow); flagged content reaches the agent through no surface; the release scope is
always-escalating, role-unbound, Critical, and its approvals are one-shot,
triple-bound, and digest-bound; response text never enters the audit chain; every
screening failure fails closed and remains distinct from transport failure; record
accounting is exact and the one new record type is queue-inert; the quarantine store is
bounded, placement-checked, write-once, and read-verified; screening has no
kill-switch and its default is on; and the volume's residual risks are accepted as
documented.

**Reviewer:** ____________________   **Date:** __________   **Decision:** approve / revise

---

## Recommended Next Logical Deliverable

**IANUA-ATB v0.1 — Reference Implementation, Milestone 4:** a stdlib-only
`atb/screening.py` (ruleset, normalization planes, screener, quarantine stores) plus
the PEP integration in `atb/enforcement.py`, the `atb:response.release` catalog scope
and `response_release` tool-map entry, the four additive CLI verbs, gateway wiring with
the `isError` and envelope changes, `.env.example` documentation of the four new keys —
shipping the S1–S19 screening suite under `tests/security` and passing the full IANUA
gate set (`compileall`, `pytest` with coverage, `ruff`, `mypy`, `bandit`,
`detect-secrets`) from the first commit.
