---
title: "IANUA-ATB v0.1 — Volume ATB-02: Scope Catalog, Role-Spec Bindings & Delegation Model"
series: "IANUA Engineering Reference"
volume: "ATB-02"
status: "Draft — pending human review gate"
supersedes: "None (extends ATB-01)"
companion_docs:
  - "IANUA-ATB v0.1 — Volume ATB-01: Identity Issuance & Zero-Trust Policy Enforcement"
  - "IANUA — AGENTS.md Operating Charter"
eaods_traceability:
  reference_implementation_of:
    - "PAT-0001 — Zero Trust Service Identity"
    - "EAODS-CTRL-000184 — Service Identity Verification"
  governed_by:
    - "STD-0001 — Canonical Terminology & Object Identifiers"
    - "STD-0002 — Cross-Artifact Traceability & Knowledge Graph"
purpose: >
  Defines the concrete authority model the ATB enforces: the canonical catalog of every
  grantable scope, the binding of each IANUA agent role to exactly the scopes it needs,
  the rules under which scope may be delegated, and the conformance tests that prove
  the model holds at every trust boundary.
owner: "Repository maintainer (human)"
review_cadence: "Re-read on session start; revise on any scope or role change"
---

# IANUA Agent Trust Broker (ATB)

## Volume ATB-02 — Scope Catalog, Role-Spec Bindings & Delegation Model

---

## Purpose

ATB-01 established *how* the broker decides — identity, policy, fail-closed evaluation,
audit. This volume establishes *what there is to decide about*: the complete, closed
catalog of grantable scopes, the least-privilege binding of every IANUA agent role to
that catalog, and the delegation and revocation semantics that govern authority as it
moves between agents.

The catalog is closed-world: **a scope that does not appear in this catalog cannot be
granted, requested, or delegated.** Adding a scope is a governed change (human review
gate), never a runtime action.

---

## Scope Catalog

### Scope naming grammar

```
<domain>:<capability>[.<qualifier>]
```

- `domain` — the resource family (`tool`, `rag`, `agent`, `fs`, `net`, `atb`).
- `capability` — the action within the family (`read`, `invoke`, `write`, `egress`).
- `qualifier` — optional narrowing (`security`, `lab`, a named corpus or agent).

Scopes are matched exactly or by explicit resource pattern in policy — never by prefix
inference. `rag:corpus.security.read` does not imply `rag:corpus.legal.read`.

### Canonical scope catalog v0.1

| Scope | Grants | Risk tier | Escalation |
|---|---|---|---|
| `tool:log.read` | Read lab log files via allow-listed MCP tools | Low | No |
| `tool:report.write` | Write generated reports into the reports output area | Medium | No |
| `rag:corpus.security.read` | Query/retrieve from the security knowledge corpus | Low | No |
| `rag:corpus.ingest` | Add documents to a corpus (provenance recorded) | High | Yes — human gate |
| `agent:mitre-mapper.invoke` | Invoke the MITRE Mapper agent | Low | No |
| `agent:threat-intel.invoke` | Invoke the Threat Intel agent | Medium | No |
| `agent:kb.invoke` | Invoke the Knowledge Base agent | Low | No |
| `agent:*.invoke` | Invoke any registered agent (orchestrator only) | High | No |
| `fs:workspace.read` | Read within the project workspace (canonicalized paths) | Low | No |
| `fs:workspace.write` | Write within the project workspace | Medium | No |
| `net:egress` | Any network request to a non-lab host | Critical | **Always** — AGENTS.md §5.1 |
| `atb:policy.read` | Read policy set and scope catalog | Low | No |
| `atb:audit.read` | Read the decision/audit log | Medium | No |
| `atb:identity.mint` | Request identities for sub-agents (orchestrator only) | High | No |

**Catalog rules.**

1. Risk tier is assigned at registration and reviewed when the scope's blast radius changes.
2. `Escalation: Yes/Always` scopes produce `escalate` decisions regardless of policy match —
   the human gate cannot be compiled away by a permissive policy.
3. No scope grants access to secrets, keys, or `.env` material; those are human-only
   per AGENTS.md §5.1 and have **no scope by design** — an unrepresentable request.

---

## Role-Spec → Scope Bindings

Each IANUA agent role binds to the minimal scope set that its published function requires.
Bindings are the source from which the Identity Authority mints — an agent cannot request
a scope outside its binding.

```yaml
role_bindings_version: "0.1.0"
bindings:
  - role: agent:soc-analyst
    scopes: [tool:log.read, rag:corpus.security.read, agent:mitre-mapper.invoke]
    delegatable: false

  - role: agent:mitre-mapper
    scopes: [rag:corpus.security.read]
    delegatable: false

  - role: agent:threat-intel
    scopes: [rag:corpus.security.read, tool:log.read]
    delegatable: false
    note: "IOC enrichment against external feeds requires net:egress — not bound; every request escalates."

  - role: agent:incident-report
    scopes: [rag:corpus.security.read, agent:kb.invoke, tool:report.write]
    delegatable: false

  - role: agent:kb
    scopes: [rag:corpus.security.read]
    delegatable: false

  - role: agent:knowledge-curator
    scopes: [rag:corpus.security.read, rag:corpus.ingest]
    delegatable: false
    note: "corpus.ingest is High risk — every ingest passes the human gate."

  - role: agent:orchestrator
    scopes: [agent:*.invoke, atb:identity.mint, atb:policy.read]
    delegatable: true
    delegation_bound: "subset of the invoked role's own binding — never the orchestrator's"
```

**Binding rules.**

1. **Bindings are reviewed like code** — a pull request changing a binding names the
   affected trust boundaries and requires the human review gate.
2. **No role binds `net:egress`.** External network access is never standing authority;
   it exists only as an escalation path.
3. **The orchestrator is not a super-user.** `agent:*.invoke` lets it *start* agents;
   the identities it requests for them are minted from *their* bindings, not its own.

---

## Delegation Model

Delegation is how the orchestrator gives a sub-agent authority without becoming an
authority-laundering path.

### Rules

1. **Off by default.** Only roles marked `delegatable: true` may delegate — currently
   the orchestrator alone.
2. **Attenuation only.** A delegated identity's scopes must be a strict subset of the
   *target role's* binding. Delegation can narrow authority; it can never widen it or
   transfer the delegator's own scopes.
3. **Depth 1.** Delegated identities are non-delegatable. A → B is permitted;
   A → B → C is not representable.
4. **Provenance recorded.** Every delegated identity carries `delegated_by` (the
   orchestrator's identity_id) in its record; audit decisions show the full chain.
5. **Lifetime nested.** A delegated identity's `not_after` may not exceed the
   delegator's remaining lifetime.

### Canonical delegated identity record

```yaml
identity_id: ATB-ID-000431
subject: agent:mitre-mapper
issued_by: ATB/identity-authority
delegated_by: ATB-ID-000429          # orchestrator's identity
issued_at: 2026-07-23T10:02:00Z
not_after: 2026-07-23T10:12:00Z      # ≤ delegator's remaining lifetime
scopes: [rag:corpus.security.read]   # ⊆ mitre-mapper's own binding
delegation:
  delegatable: false                  # depth 1 — always false on delegated identities
revocation:
  status: active
```

---

## Revocation Propagation

- **Direct revocation** of any identity takes effect on next verification (no caching
  of verification results — ATB-01).
- **Cascade:** revoking a delegator immediately revokes every identity carrying its
  `identity_id` in `delegated_by`. One orchestrator revocation cleans up its whole run.
- **Binding change:** editing a role's binding revokes all active identities minted from
  the old binding. Agents re-mint against the new binding on next request — a
  fail-closed reload, not a hot patch.
- **Catalog removal:** retiring a scope from the catalog revokes every identity holding
  it and marks every policy referencing it as a validation error until amended.

---

## Policy Authoring & Review Workflow

```
Draft policy (YAML, version-controlled)
        │
        ▼
Static validation ── scope exists in catalog? subjects exist in bindings?
        │                       resources match declared patterns?
        ▼
Least-privilege diff ── what NEW authority does this grant, to whom?
        │
        ▼
Human review gate ── reviewer sees the diff, not the whole policy set
        │
        ▼
Merge → broker reloads policy set (deterministic, versioned, auditable)
```

Policies, bindings, and the catalog live in the repository and change only through
reviewed commits. The broker never accepts a runtime policy mutation.

---

## Conformance Test Matrix

One security test per ATB-01 trust boundary, plus the delegation invariants. These are
the `tests/security` cases the implementation must ship with — each proves a *denial*,
because fail-closed behavior is the property under test.

| # | Boundary / invariant | Test asserts |
|---|---|---|
| T1 | Agent → Tool | Unbound scope request (`soc-analyst` → `tool:report.write`) is denied and audited |
| T2 | Agent → RAG | Cross-corpus retrieval outside qualifier (`rag:corpus.legal.read`) is denied |
| T3 | Agent → Filesystem | Path traversal outside canonicalized workspace is denied before policy match |
| T4 | Agent → Agent | Invocation without verified caller identity is denied |
| T5 | Agent → External host | `net:egress` always yields `escalate`, never silent `allow`, for every role |
| T6 | LLM output → Action | Injected instruction requesting out-of-scope action is denied and logged as security event |
| T7 | Delegation: attenuation | Delegated scopes ⊄ target binding is rejected at mint time |
| T8 | Delegation: depth | Delegated identity attempting to delegate is rejected |
| T9 | Delegation: lifetime | Delegated `not_after` exceeding delegator's is rejected |
| T10 | Revocation cascade | Revoking delegator invalidates delegatee on next verification |
| T11 | Catalog closed-world | Policy referencing an uncataloged scope fails static validation |
| T12 | Audit integrity | Any decision path (allow/deny/escalate) appends exactly one hash-chained record |

A conformance run that skips any row is a failed run.

---

## QA Checklist

- [ ] YAML front matter validated.
- [ ] Scope naming grammar documented.
- [ ] Canonical scope catalog completed with risk tiers and escalation flags.
- [ ] Role-spec bindings defined for every IANUA agent.
- [ ] No role binds `net:egress`; secrets remain unrepresentable.
- [ ] Delegation rules completed (attenuation, depth 1, provenance, nested lifetime).
- [ ] Revocation propagation semantics documented.
- [ ] Policy authoring workflow documented.
- [ ] Conformance test matrix covers every ATB-01 trust boundary.
- [ ] Human review gate completed.

## Human Review Gate

Maintainer approval of the scope catalog, role bindings, and delegation model is required
before implementation. The review shall verify: the catalog is closed-world; every binding
is minimal for its role's published function; escalation flags cannot be bypassed by
policy; delegation only attenuates; and every conformance test asserts a denial.

**Reviewer:** ____________________   **Date:** __________   **Decision:** approve / revise

---

## Recommended Next Logical Deliverable

With the authority model fixed, the series moves from documentation to code:

**IANUA-ATB v0.1 — Reference Implementation, Milestone 1:** a typed Python package
(`atb/`) implementing the Identity Authority and Policy Engine as pure, deterministic
functions over the catalog and bindings defined here, shipping the T1–T12 conformance
matrix as its `tests/security` suite, and passing the IANUA required checks
(`compileall`, `pytest`, `ruff`, `mypy`, `bandit`) from the first commit.
