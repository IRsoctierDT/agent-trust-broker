# DESIGN.md — MCP Sentinel · Agent Trust Broker™

> Architecture, trust boundaries, and threat model for this repository.
> Read this **before** any change (see [`AGENTS.md`](./AGENTS.md) §2). Update it whenever the
> architecture, a trust boundary, or the threat model changes.
>
> **Status:** Day 1 baseline (CP-1 target: Day 7). Version 0.1.

---

## 1. Executive Summary

The **Agent Trust Broker** is a **bidirectional, inline trust gate** that sits between an AI
agent and the MCP tools it uses. It exists to enforce one principle the current generation of
agents cannot enforce for themselves: **an agent cannot reliably tell the data it reads from an
instruction to act.**

The Broker mediates every exchange across that boundary in both directions:

- **Inbound** — every MCP tool *response* is treated as hostile input: schema-validated,
  screened for injection, and integrity-checked **before** it is allowed into the agent's
  context. This defeats the tool-output-injection class (the "Agentjacking" pattern) and
  tool-description poisoning.
- **Outbound** — every tool *call* the agent attempts is checked against a plan the agent
  declared in advance. Divergence is flagged and routed to a **mandatory human approval gate**
  before the call reaches the tool.

One interception point, one policy engine, one audit log. The safe path is the default path.

---

## 2. Objectives & Non-Objectives

### Objectives
1. **Inbound trust enforcement** — no MCP tool response reaches the agent's reasoning context
   without validation, injection screening, and metadata-integrity verification.
2. **Outbound intent verification** — no tool call executes unless it matches the agent's
   declared plan or is explicitly human-approved.
3. **Human-in-the-loop enforcement** — any trust violation, in either direction, halts and
   routes to a human. This is **architectural, not configurable**.
4. **Auditability** — every exchange, decision, and approval is recorded in a tamper-evident
   log sufficient for after-the-fact oversight.
5. **Portfolio-grade** — typed, tested, documented, CI-gated throughout.

### Non-Objectives (v0.x)
- Full *semantic* intent inference. The Day-16 verifier is an allowlist + plan-divergence MVP;
  semantic modeling is a **Future Enhancement**, not attempted in the 21-day window.
- Protecting agents against attacks that do not cross the agent↔tool boundary (e.g. weights
  exfiltration, host compromise).
- Offensive use against systems the operator does not own.

---

## 3. Interception Architecture

The Broker is a man-in-the-middle **by design and by consent** — the operator inserts it into
their own agent's tool path.

```
                          ┌───────────────────────────────────────────┐
                          │                  HUMAN                     │
                          │   approves on any trust violation;         │
                          │   owns secrets; reviews the audit log      │
                          └───────────────▲───────────────────────────┘
                                          │ escalate (HITL gate)
                                          │
  ┌──────────────┐   1. declared plan     │
  │              │ ──────────────────┐    │
  │   AI AGENT   │                   ▼    │                        ┌──────────────┐
  │  (untrusted  │            ┌─────────────────────┐   4. verified │  MCP TOOLS   │
  │   reasoning) │  2. tool   │   AGENT TRUST       │   tool call   │  (clean +    │
  │              │ ─ call ───▶│      BROKER         │ ─────────────▶│   malicious  │
  │              │            │                     │               │   testbed)   │
  │              │◀─ 6. safe ─│  ┌───────────────┐  │◀── 5. raw ────│              │
  │              │   response │  │ policy engine │  │    response   └──────────────┘
  └──────────────┘            │  └───────────────┘  │
                              │  ┌───────────────┐  │
                              │  │  audit log    │  │  ← every exchange, tamper-evident
                              │  └───────────────┘  │
                              └─────────────────────┘
        OUTBOUND path: 1 → 2 → (verify vs plan) → 4  | violation → HITL
        INBOUND  path: 5 → (validate/screen/verify) → 6 | violation → HITL
```

### Outbound pipeline (agent → tool)
`declare_plan` → `intercept_call` → `verify_against_plan` (allowlist + divergence diff) →
`policy_decision` → **allow / block / escalate-to-HITL** → forward to tool.

### Inbound pipeline (tool → agent)
`receive_response` → `schema_validate` → `injection_screen` (heuristics + guardrail model) →
`verify_tool_metadata` (signature/hash) → `policy_decision` → **allow / block / escalate** →
return sanitized response to agent.

---

## 4. Trust Boundaries

| # | Boundary | Trust level of what crosses it | Control applied |
|---|----------|-------------------------------|-----------------|
| B1 | Agent → Broker (outbound call) | Semi-trusted: agent may be hijacked | Verify against declared plan; policy engine |
| B2 | Broker → MCP tool | Trusted egress (operator-owned or allow-listed) | Allowlist; signed tool manifest |
| B3 | MCP tool → Broker (inbound response) | **Untrusted** — primary attack surface | Schema validation, injection screen, metadata integrity |
| B4 | Broker → Agent (sanitized response) | Trust *established by the Broker* | Only validated content passes |
| B5 | Broker → Human (escalation) | Trusted, out-of-band | Approval gate; no bypass path |
| B6 | Broker → Audit log | Append-only | Tamper-evident, run-scoped IDs |

The **critical boundary is B3.** Everything the industry is currently being burned by —
Agentjacking, tool poisoning, poisoned telemetry/error reports — crosses B3.

---

## 5. Threat Model

Grounded in the Q3 2026 agentic-AI threat landscape. Each threat maps to a control and to the
charter day that builds it.

| ID | Threat | Vector across boundary | Control | Built |
|----|--------|------------------------|---------|-------|
| T1 | **Tool-output injection ("Agentjacking")** — malicious instructions embedded in a tool/telemetry response the agent then executes | B3 | Inbound injection screen + schema validation | Day 9–10 |
| T2 | **Tool-description / metadata poisoning** — swapped or malicious tool metadata carries instruction-level authority | B2/B3 | Cryptographic verify-before-execute of tool manifests | Day 11 |
| T3 | **Intent divergence** — hijacked agent issues a tool call it never declared it would make | B1 | Outbound plan-vs-action diff → HITL | Day 15–17 |
| T4 | **Memory poisoning** — untrusted input persists into agent memory and corrupts later sessions | B3 → context | Treat inbound as untrusted at write time; regression cases | Day 19 |
| T5 | **Unauthenticated / rogue MCP server** — agent connected to an exposed or shadow server | B2 | Allowlist; connection policy; signed manifest | Day 6, 11 |
| T6 | **Silent/unauditable action** — a consequential action leaves no oversight trail | B6 | Tamper-evident audit log; run IDs | Day 18 |
| T7 | **Lethal trifecta** — private-data access + untrusted content + outbound action combined in one flow | design-wide | Self-scan of the Broker's own config; policy separation | Day 19 |

**Assumption (explicit):** the agent's *reasoning model* is not itself adversarial; the Broker
defends the agent from hostile **inputs and hijack**, not from a maliciously trained model.

---

## 6. Data Flows (sensitive-data view)

- **Plans and tool calls** — may contain operator context; stay local; logged with run IDs.
- **Inbound tool responses** — untrusted until validated; never persisted to memory pre-screen.
- **Secrets / credentials** — never in code or logs; injected via environment; redacted in the
  audit trail (see `AGENTS.md` §5).
- **Audit log** — append-only, local-first; the record of record for oversight.

---

## 7. Decision Log

| # | Decision | Rationale | Date |
|---|----------|-----------|------|
| D1 | Bidirectional gate (not inbound-only) | The two hottest 2026 threats sit on opposite sides of the same boundary; one mediation point serves both | 2026-07-08 |
| D2 | HITL enforcement is architectural, not a config flag | A bypassable gate is not a control; matches operator's standing requirement | 2026-07-08 |
| D3 | Intent verifier ships as allowlist + divergence MVP | Semantic intent is an open research problem; a shippable, honest MVP beats an unfinished ambition | 2026-07-08 |
| D4 | Framework substrate deferred to CP-1 (Day 7) | Choose LangGraph vs AutoGen vs CrewAI on evidence after building the real gate loop in each | 2026-07-08 |
| D5 | Local-first (Ollama), no required paid inference | Auditability, cost, and lab-scoping; guardrail model runs locally | 2026-07-08 |
| D6 | Portfolio intake is event-driven staging behind the HITL gate | Fires on the build commit (after tests pass) and only *stages* a manifest; publishing stays human-approved, consistent with D2 | 2026-07-08 |

---

## 8. Open Risks (see also charter §10)

- **Intent-verifier scope creep** — mitigated by the D3 MVP boundary.
- **Guardrail-model latency/accuracy** under local models — measured at Day 13, documented.
- **False-positive HITL fatigue** — policy tuning tracked as a first-class concern, not an
  afterthought; measured against the Day-8 attack reproduction.
