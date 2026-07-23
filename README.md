# IANUA Agent Trust Broker (ATB)

Identity issuance and Zero-Trust policy enforcement for the IANUA agent fleet:
every privileged agent action requires a verifiable, short-lived, scoped identity
and a per-action **allow / deny / escalate** decision, recorded in a hash-chained
audit log. Fail-closed by construction.

EAODS reference implementation of **PAT-0001 (Zero Trust Service Identity)** and
**EAODS-CTRL-000184 (Service Identity Verification)**; mitigation architecture for
**THR-0001** and **THR-0002**. See [EAODS-v3](https://github.com/IRsoctierDT/EAODS-v3).

## Design volumes

| Volume | Contents |
|---|---|
| [ATB-01](docs/IANUA-ATB-v0.1-Identity-and-Policy-Broker.md) | Identity issuance, policy evaluation, escalation, audit model |
| [ATB-02](docs/IANUA-ATB-v0.1-Scope-Catalog-and-Delegation-Model.md) | Scope catalog, role bindings, delegation, conformance matrix |

## Package

| Module | Responsibility |
|---|---|
| `atb.catalog` | Closed-world scope catalog; escalation flags; static validation |
| `atb.bindings` | Least-privilege role → scope bindings (validated at import) |
| `atb.identity` | Mint / verify / revoke; depth-1 attenuating delegation; cascade revocation |
| `atb.policy` | Deterministic authorize → allow / deny / escalate; always audited |
| `atb.audit` | Append-only, hash-chained decision log with chain verification |
| `atb.persistence` | Durable JSONL audit storage; chain re-verified fail-closed on load |
| `atb.escalation` | Persistent escalation queue; human approve/deny recorded in the chain |

Stdlib only. Signing keys are supplied at construction — never hard-coded, never logged.

## Conformance

`tests/security/test_conformance.py` implements the ATB-02 **T1–T12 matrix** —
one test per trust boundary, each asserting a denial, an escalation, or chain
integrity.

```bash
python -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest
```

## Demo

An end-to-end narrated run — allow, escalate-on-injection, deny, delegation,
cascade revocation, and tamper detection on the persisted audit chain:

```bash
.venv/bin/python -m examples.demo
```

## Security invariants

- No role binds `net:egress`; external network access **always** escalates to a human.
- Secrets and keys have no scope — the request is unrepresentable.
- LLM output is data, never authorization: out-of-scope requests are denied/escalated
  and flagged as security events.
- Delegation only attenuates, is depth-1, and revocation cascades.
- Escalations close the loop in the chain: a named human's approve/deny is a
  chained record, and an approval is **one-shot and triple-bound** — it converts
  exactly one matching `(subject, action, resource)` escalate into an allow,
  with the consumption itself recorded. Replay is refused and evidenced.
