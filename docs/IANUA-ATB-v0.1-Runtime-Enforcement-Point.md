---
title: "IANUA-ATB v0.1 — Volume ATB-03: Runtime Enforcement Point & Tool-Call Mediation"
series: "IANUA Engineering Reference"
volume: "ATB-03"
status: "Authoritative — maintainer review gate passed 2026-08-14"
supersedes: "None (extends ATB-01 and ATB-02)"
companion_docs:
  - "IANUA-ATB v0.1 — Volume ATB-01: Identity Issuance & Zero-Trust Policy Enforcement"
  - "IANUA-ATB v0.1 — Volume ATB-02: Scope Catalog, Role-Spec Bindings & Delegation Model"
  - "IANUA — AGENTS.md Operating Charter"
eaods_traceability:
  reference_implementation_of:
    - "PAT-0001 — Zero Trust Service Identity"
    - "EAODS-CTRL-000184 — Service Identity Verification"
  mitigates:
    - "THR-0001 — Compromised Service Identity"
    - "THR-0002 — LLM Instruction Injection"
  emits_evidence_to:
    - "PAT-0003 — Continuous Assurance Evidence Pipeline"
  governed_by:
    - "STD-0001 — Canonical Terminology & Object Identifiers"
    - "STD-0002 — Cross-Artifact Traceability & Knowledge Graph"
purpose: >
  Defines where and how the ATB's policy decisions are enforced at runtime: the Policy
  Enforcement Point (PEP) that mediates every agent tool call on the MCP path, the
  closed-world mapping from tool invocations to catalog scopes and resources, and the
  fail-closed forward / refuse / escalate semantics that make an authorization decision
  binding. This volume converts the ATB from a decision service into an inline reference
  monitor without changing the ATB-01 decision engine or the ATB-02 authority model.
owner: "Repository maintainer (human)"
review_cadence: "Re-read on session start; revise on any tool-mapping or transport change"
---

# IANUA Agent Trust Broker (ATB)

## Volume ATB-03 — Runtime Enforcement Point & Tool-Call Mediation

---

## Purpose

ATB-01 established *how* the broker decides. ATB-02 established *what there is to decide
about*. This volume establishes **where the decision is enforced**: an inline Policy
Enforcement Point (PEP) sitting on the path between an IANUA agent and the MCP tools it
calls, so that no privileged tool call reaches a tool without first passing
`PolicyEngine.authorize`.

The ATB-01 `PolicyEngine` is a **Policy Decision Point (PDP)** — a pure function that
answers *allow / deny / escalate*. A decision that is not enforced is advice. The PEP is
the arm that makes the decision binding: it intercepts the tool call, asks the PDP, and
**forwards, refuses, or escalates** accordingly. Together they form a classic reference
monitor: complete mediation, tamper-resistance (fail-closed), and verifiability (the
existing hash-chained audit).

This is also the concrete answer to **THR-0002 (LLM Instruction Injection)**. The ATB does
not defend against a hijacked agent by inspecting tool *text* for malicious instructions —
a probabilistic filter. It defends by ensuring a hijacked agent **cannot make an
out-of-scope tool call at all**: the PEP refuses to forward it. ATB-02's T6 moves from an
asserted property to an enforced one.

---

## Strategic Objectives

- **Complete mediation.** Every privileged tool call is authorized before it executes;
  there is no path from agent to tool that bypasses the PDP.
- **No new trust.** The PEP adds enforcement only. It does not decide, does not widen
  scope, and does not modify the ATB-01 engine or the ATB-02 catalog/bindings.
- **Fail closed by default.** An unmapped tool, an unverifiable identity, or any error in
  derivation results in denial — never a silent forward.
- **One decision, one record.** Each mediated call yields exactly one hash-chained
  *decision* record — the PDP's for mapped calls, a single PEP-authored enforcement
  refusal for unmappable ones — preserving T12. Escalating calls additionally append the
  unchanged Milestone-2 escalation lifecycle records (`escalation_submitted`;
  `escalation_resolved` / `approval_consumed` on resolution) to the same verifiable
  chain. The PEP never double-audits a decision.
- **Transport-agnostic core, SDK at the edge.** The enforcement logic stays stdlib-only in
  `atb/`; the concrete MCP wire binding lives in `examples/`, honoring the package invariant.

---

## Trust & Engineering Principles

1. **The reference monitor is inline, not advisory.** If the PEP is not on the path, the
   call does not happen. Bypass is a defect, not a configuration.
2. **LLM output is data, never authorization.** A tool call is a *request*; the requester's
   minted identity and scopes — not the model's intent — determine the outcome.
3. **Closed-world tools.** As with scopes (ATB-02), a tool not present in the tool map
   cannot be invoked through the broker. Adding a mapping is a governed change.
4. **Escalation cannot be compiled away.** A call that maps to an escalating scope is
   refused-until-approved regardless of policy match — identical to ATB-02 rule 2.
5. **Enforcement is deterministic.** Same invocation, same identity, same catalog ⇒ same
   decision. No time-of-check/time-of-use gap between decision and forward.

---

## Enforcement Architecture

```
IANUA agent (may be LLM-driven, therefore untrusted intent)
      │  tool call: (token, tool_name, arguments)
      ▼
┌─────────────────────────── Policy Enforcement Point (PEP) ──────────────────────────┐
│  1. Derive (action, resource, context) from the invocation via the closed-world map  │
│  2. decision = PolicyEngine.authorize(token, action, resource, context)   ← PDP      │
│  3. Act on decision.effect:                                                            │
│        ALLOW    → forward to downstream MCP tool, return its result                    │
│        DENY     → refuse; do NOT forward; return structured denial                     │
│        ESCALATE → submit Decision to EscalationQueue; refuse now; return pending ref   │
└───────────────────────────────────────────────────────────────────────────────────────┘
      │ (ALLOW only)                                   ▲
      ▼                                                │ exactly one hash-chained record
   downstream MCP tool / server                    atb.audit (unchanged)
```

The PEP is a thin wrapper over a **downstream callable** (the real tool transport). It
holds no policy logic of its own; every judgment is delegated to the ATB-01 engine and the
ATB-02 catalog. The result is that the interception layer and the decision engine are the
same system viewed from two sides — enforcement and decision — rather than two products.

---

## Tool → Action / Resource Mapping

The PEP translates an MCP tool invocation into the `(action, resource)` pair the PDP
evaluates. This mapping is **closed-world**: a tool with no mapping entry is denied
(`unknown_tool`), the enforcement analogue of ATB-02's `unknown_scope`.

### Derivation grammar

```
invocation(tool_name, arguments) ──▶ (action ∈ CATALOG, resource, context)
```

- `action` is a catalog scope name from ATB-02 — never invented at runtime.
- `resource` is derived from the invocation's arguments by a per-tool rule (e.g. a path
  argument for `fs:*`, a host for `net:egress`, a target name for `agent:*.invoke`).
- `context` carries non-authoritative metadata (e.g. `approval_ref` for the M2 human-loop
  closure), exactly as `PolicyEngine.authorize` already accepts.

### Draft tool map v0.1 — FOR MAINTAINER REVIEW

Representative tool names bound to the existing ATB-02 catalog. Tool names are placeholders
to be reconciled against the actual IANUA command-center MCP servers; the **scope column is
authoritative** and must reference only cataloged scopes.

| MCP tool (draft) | Catalog action | Resource derivation | Escalates |
|---|---|---|---|
| `log_read` | `tool:log.read` | fixed `logs/lab/<name>` from `name` arg | No |
| `report_write` | `tool:report.write` | `reports/<name>` from `name` arg | No |
| `corpus_search` | `rag:corpus.security.read` | fixed `rag:corpus:security` | No |
| `corpus_ingest` | `rag:corpus.ingest` | `rag:corpus:<target>` from `corpus` arg | **Yes** |
| `invoke_mitre_mapper` | `agent:mitre-mapper.invoke` | fixed `agent:mitre-mapper` | No |
| `invoke_threat_intel` | `agent:threat-intel.invoke` | fixed `agent:threat-intel` | No |
| `invoke_kb` | `agent:kb.invoke` | fixed `agent:kb` | No |
| `workspace_read` | `fs:workspace.read` | `path` arg passed unrewritten (PDP requires canonical form) | No |
| `workspace_write` | `fs:workspace.write` | `path` arg passed unrewritten (PDP requires canonical form) | No |
| `http_fetch` | `net:egress` | `host:<scheme>://<host>:<port><path>` from URL (query/fragment/userinfo excluded — never chained) | **Always** |
| `policy_read` | `atb:policy.read` | fixed `atb:policy` | No |
| `audit_read` | `atb:audit.read` | fixed `atb:audit` | No |
| `mint_sub_identity` | `atb:identity.mint` | fixed `atb:identity` | No |

**Mapping rules.**

1. The scope column may only name scopes present in the ATB-02 catalog; a mapping to an
   uncataloged scope fails static validation at import (mirrors T11).
2. Resource derivation for `fs:*` tools passes the path through **unrewritten** (shape
   validation only): the PDP's T3 gate requires an already-canonical path and denies
   everything else as a `path_traversal` security event. Normalizing on the caller's
   behalf would mask traversal attempts from the audit trail; passing the raw path is
   what makes the T3 denial fire as designed.
3. There is **no mapping to secrets, keys, or `.env`** material — unrepresentable by design
   (ATB-02 rule 3); such tools must not exist in the map.
4. A tool that could touch multiple resources is mapped per-argument, not with a wildcard
   that would widen scope.

---

## Enforcement Semantics

For each mediated invocation the PEP performs, in order:

1. **Derive** `(action, resource, context)`. Any failure (unmapped tool, missing required
   argument, uncanonicalizable path) ⇒ **refuse**, reason `derivation_failed` /
   `unknown_tool`; nothing is forwarded.
2. **Decide** via `PolicyEngine.authorize(token, action, resource, context)`. This appends
   exactly one hash-chained audit record — the single source of truth for the call.
3. **Enforce** on `decision.effect`:
   - `ALLOW` → invoke the downstream callable; return its result to the agent.
   - `DENY` → return a structured denial (effect, reason, audit ref); **do not** forward.
   - `ESCALATE` → hand the `Decision` to the `EscalationQueue`; return a pending reference;
     **do not** forward. The call completes only if a human later approves (M2 loop), on a
     subsequent invocation carrying the `approval_ref` in context.

The PEP never converts a `DENY`/`ESCALATE` into a forward, never retries a denied call, and
never swallows a downstream error (a forwarded call that raises is surfaced unchanged — the
authorization already succeeded and is already recorded).

---

## Trust Boundaries (enforcement view)

The PEP is where ATB-01's boundaries are *crossed under guard*. It introduces no new
boundary; it makes the existing ones binding at runtime:

| ATB-01/02 boundary | Enforced at the PEP by |
|---|---|
| Agent → Tool (T1) | refusing tool calls whose derived scope is not granted |
| Agent → RAG (T2) | resource derivation pinned to the exact corpus qualifier |
| Agent → Filesystem (T3) | paths presented unrewritten; the PDP denies non-canonical paths as traversal |
| Agent → Agent (T4) | requiring a verifiable token on every invocation |
| Agent → External host (T5) | mapping all egress tools to `net:egress` (always escalate) |
| LLM output → Action (T6) | refusing to forward any out-of-scope tool call, flagged security event |

---

## Canonical Tool-Invocation Record

The PEP's input, for reference (the *decision* record is the unchanged ATB-01 audit record):

```json
{
  "token": "<opaque minted identity token>",
  "tool": "corpus_ingest",
  "arguments": { "corpus": "security", "document_ref": "…" },
  "context": { "approval_ref": "" }
}
```

Derivation yields `action = rag:corpus.ingest`, `resource = rag:corpus:security`, which the
PDP evaluates to `escalate` (High-risk, escalating scope) — refused until human approval.

---

## Integration Points

- **`atb/` stays stdlib-only.** The PEP core operates on an abstract invocation and a
  downstream callable; it imports nothing beyond the standard library and the existing
  `atb` modules.
- **MCP SDK lives in `examples/`.** The concrete binding — a real MCP server/client that
  feeds invocations into the PEP and forwards allowed calls — is an edge adapter with its
  own dependency (`mcp`), never imported by the core package.
- **Audit is reused, not duplicated.** The PEP emits no log of its own; the ATB-01 chain is
  already the complete exchange record. It feeds PAT-0003 evidence unchanged.
- **Operator CLI is unchanged.** Escalations raised by the PEP appear in the same
  `atb pending / approve / deny` queue built in M2.

---

## Non-Goals (and a note on tool-output screening)

- **Tool-response content screening is out of scope for ATB-03.** Inspecting returned tool
  *text* for injection payloads is defense-in-depth, not the primary control: policy-scoping
  a minted identity is a deterministic guarantee, while content screening is probabilistic.
  If adopted, screening belongs in a later volume (candidate **ATB-04**) as an *input to* a
  policy decision — never as a substitute for one, and never as authority.
- **No outbound "plan-vs-action" verifier here.** Under the ATB model, an agent that acts
  outside its declared plan is simply an agent making an out-of-scope call, already denied by
  the PEP. A separate semantic-intent verifier remains optional future work.
- **No changes to identity, catalog, bindings, or delegation.** ATB-03 is purely additive.

---

## Conformance Test Matrix (enforcement extension)

New `tests/security` cases proving enforcement, layered on the T1–T12 decision matrix. Each
asserts an enforcement outcome (forward vs. refuse), not merely a decision:

| # | Property | Test asserts |
|---|---|---|
| E1 | Unmapped tool | A tool absent from the map is refused (`unknown_tool`); downstream never called |
| E2 | In-scope forward | A mapped, in-scope tool call is authorized `allow` and the downstream callable is invoked exactly once |
| E3 | Out-of-scope refusal (T6) | An out-of-scope / injected tool call is refused, downstream never called, `security_event` recorded |
| E4 | Escalation holds (T5) | An egress tool call is refused-until-approved; downstream not called; a pending ref is returned |
| E5 | Approval closes the loop | Re-invoking with a valid `approval_ref` forwards exactly once (consumes one approval); a same-host invocation with a different path/port/scheme does **not** consume it and re-escalates |
| E6 | One record per call (T12) | Each mediated call appends exactly one hash-chained *decision* record (escalating calls add exactly the M2 `escalation_submitted` lifecycle record); chain re-verifies |

A conformance run that skips any row is a failed run.

---

## QA Checklist

- [x] YAML front matter validated.
- [x] PDP/PEP split documented; PEP is inline and delegates every judgment.
- [x] Tool → action/resource mapping grammar documented; map is closed-world.
- [x] Draft tool map references only cataloged scopes; secrets remain unrepresentable.
- [x] `fs:*` paths pass through unrewritten; the PDP's T3 gate denies non-canonical paths.
- [x] Forward / refuse / escalate semantics fail closed on every path.
- [x] Exactly one hash-chained decision record per mediated call (no double-audit);
      escalation lifecycle records are the unchanged M2 design.
- [x] `atb/` core remains stdlib-only; MCP SDK confined to `examples/`.
- [x] Enforcement conformance matrix (E1–E6) defined.
- [x] Human review gate completed.

## Human Review Gate

Maintainer approval of the runtime enforcement design is required before any implementing
code is written. The review shall verify: complete mediation (no bypass path); the tool map
is closed-world and references only cataloged scopes; `fs:*` paths reach the PDP
unrewritten and non-canonical paths are denied as traversal; escalation cannot be
converted to a forward; exactly one decision record per call; the core stays stdlib-only;
and that LLM-expressed intent is treated as a request, never as authorization.

**Reviewer:** Ivan Rozenblad (repository maintainer)   **Date:** 2026-08-14   **Decision:** **approve**

> Approval recorded per maintainer directive in the working session of 2026-08-14
> ("Complete the steps in order", covering the ATB-03 review gate). Implementation of
> Milestone 3 is authorized against this volume as specified.
>
> **Post-implementation amendment (2026-08-14):** after the multi-lens adversarial
> review of the Milestone-3 implementation, this volume was reconciled with the
> enforced (and reviewed-as-safer) design: `fs:*` paths pass through unrewritten so
> T3 fires with evidence; per-call record accounting counts one *decision* record
> plus the unchanged M2 escalation lifecycle records; egress resources carry a
> reviewable `scheme://host:port/path` summary the approval is bound to. Same
> session, same approval basis.

---

## Amendment — Day-01 D3 plan MVP & demo mint gate (2026-09-10)

- **Outbound plan declaration.** Agents may declare a closed MCP tool allowlist
  via `atb/declare_plan` (`atb.plan.PlanBook`). Once declared for a subject,
  any tool call outside the set is mediated through catalog scope
  `atb:plan.override` (always escalates to HITL). Optional `ATB_REQUIRE_PLAN=1`
  refuses calls until a plan exists (`plan_required`).
- **Demo mint off by default.** The lab-only `atb/mint` JSON-RPC method is
  refused unless the gateway is constructed with `demo_mint=True` or
  `ATB_DEMO_MINT=1`. Production mints identities out of band.

## Recommended Next Logical Deliverable

With enforcement fixed in design, the series returns to code:

**IANUA-ATB v0.1 — Reference Implementation, Milestone 3:** a stdlib-only `atb/enforcement`
module implementing the PEP as a wrapper over a downstream callable, a validated closed-world
tool map, and forward/refuse/escalate semantics that reuse the ATB-01 engine and ATB-02
authority model unchanged — shipping the E1–E6 enforcement suite under `tests/security` and
passing the IANUA required checks (`compileall`, `pytest`, `ruff`, `mypy`, `bandit`) from the
first commit. A runnable MCP edge adapter lands separately under `examples/`.
