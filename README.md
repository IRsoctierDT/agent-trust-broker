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
| [ATB-03](docs/IANUA-ATB-v0.1-Runtime-Enforcement-Point.md) | Runtime enforcement point (PEP), tool-call mediation, closed-world tool map |
| [ATB-04](docs/IANUA-ATB-v0.1-Response-Screening-and-Quarantine.md) | Tool-response screening, quarantine, human release loop (screening as input, never authority) |
| [ATB-05](docs/IANUA-ATB-v0.1-Audit-Chain-Lifecycle.md) | Audit-chain lifecycle: segment rotation, checkpointing, chained time, deep verification |

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
| `atb.enforcement` | ATB-03 PEP: closed-world tool map; forward / screen / refuse / escalate mediation |
| `atb.screening` | ATB-04 response screener: versioned closed-world ruleset; content-addressed quarantine stores |
| `atb.lifecycle` | ATB-05 chain lifecycle: segments, seals/checkpoints, crash-safe rotation, deep verification |
| `atb.cli` | Operator CLI (`atb pending / show / approve / deny / verify / rotate / detach / repair / screen-stats / quarantine`) |

Stdlib only. Signing keys are supplied at construction — never hard-coded, never logged.

## Conformance

`tests/security/test_conformance.py` implements the ATB-02 **T1–T12 matrix** —
one test per trust boundary, each asserting a denial, an escalation, or chain
integrity. `tests/security/test_enforcement.py` adds the ATB-03 **E1–E6
enforcement matrix** — each row asserting a forward-vs-refuse outcome, not
merely a decision. `tests/security/test_screening.py` adds the ATB-04
**S1–S19 screening matrix** — each row asserting a withhold, a release-loop
property, or an exact record count, never merely a verdict.
`tests/security/test_lifecycle.py` adds the ATB-05 **L1–L25 lifecycle matrix** —
each row asserting fail-closed detection, cryptographic continuity across a
rotation, or carried-state equivalence against an unrotated control.

```bash
python -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest
```

## Operator CLI

Resolve escalations without writing Python. Install the package
(`pip install -e .`), point `ATB_AUDIT_CHAIN` at the broker's audit file
(or pass `--chain`), then:

```bash
atb pending
```

```bash
atb approve ATB-DEC-000123 --reason "known safe intel feed"
```

```bash
atb deny ATB-DEC-000123 --reason "unknown destination"
```

```bash
atb verify
```

Rotate the chain when it grows (gateway stopped; dry run first, nothing deleted):

```bash
atb rotate
```

```bash
atb rotate --execute
```

Approvals are recorded in the hash chain, attributed to `--approver` (default:
the OS user), require a reason, and remain one-shot and triple-bound. Every
failure path — missing or tampered chain, unknown ref, double resolution —
exits non-zero.

## Demo

An end-to-end narrated run — allow, escalate-on-injection, deny, delegation,
cascade revocation, and tamper detection on the persisted audit chain:

```bash
.venv/bin/python -m examples.demo
```

## Enforcement gateway

`examples/mcp_gateway.py` puts the ATB-03 PEP on the wire: an MCP-shaped
JSON-RPC stdio server whose every `tools/call` is mediated before anything
executes — allowed calls forward, denials return the audit ref, escalations
land in the same queue `atb approve` resolves. Stdlib only; configuration via
`ATB_AUDIT_CHAIN` / `ATB_SIGNING_KEY` (see `.env.example`). A rootless podman
recipe (read-only rootfs, `--network=none`, one writable volume for the chain)
lives in [`infra/`](infra/README.md).

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
- Tool responses are screened before relay (ATB-04): a flagged response is
  **withheld and quarantined**, never annotated-and-delivered; release requires
  a named human approval digest-bound to the exact reviewed bytes. Screening is
  an input to a policy decision, never authority — verdicts only tighten, a
  clean verdict proves nothing, and there is **no screening off-switch**.
- The chain has a lifecycle (ATB-05): rotation seals the active segment into a
  read-only, digest-committed archive and opens a successor whose first record
  chains to the sealed tip — so segments cannot be dropped, swapped, or forged
  undetected. Deep, full-history verification is the **default**; every weaker
  mode is an explicit flag that prints what it does not prove. Rotation is
  human-run, crash-safe, and **deletes nothing**.
