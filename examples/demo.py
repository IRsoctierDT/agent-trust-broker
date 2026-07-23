"""End-to-end ATB demo: identities, decisions, delegation, durable audit.

Run from the repository root:

    .venv/bin/python -m examples.demo

Walks the full trust model with a real IdentityAuthority, PolicyEngine, and
JSONL-persisted audit log, then demonstrates tamper detection on the persisted
chain. Uses a temporary directory; nothing is written into the repository.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from atb.identity import IdentityAuthority, VerificationError
from atb.persistence import AuditIntegrityError, JsonlAuditStore
from atb.policy import PolicyEngine


def banner(title: str) -> None:
    print(f"\n=== {title} " + "=" * max(0, 60 - len(title)))


def main() -> None:
    workdir = Path(tempfile.mkdtemp(prefix="atb-demo-"))
    audit_path = workdir / "audit.jsonl"

    # Signing key supplied at construction — never hard-coded, never logged.
    authority = IdentityAuthority(signing_key=os.urandom(32))
    store = JsonlAuditStore.open(audit_path)
    engine = PolicyEngine(authority=authority, log=store)

    banner("1. SOC analyst: authorized triage (allow)")
    _, soc_token = authority.mint("agent:soc-analyst")
    decision = engine.authorize(soc_token, "tool:log.read", "logs/lab/auth-2026-07-23.jsonl")
    print(f"effect={decision.effect.value}  reason={decision.reason}")

    banner("2. Injection-steered exfiltration attempt (escalate)")
    decision = engine.authorize(
        soc_token, "net:egress", "host:exfil.example", context={"origin": "llm_output"}
    )
    print(f"effect={decision.effect.value}  reason={decision.reason}")
    print(f"security_event={decision.security_event}  (a human sees this before anything moves)")

    banner("3. Out-of-scope write (deny)")
    decision = engine.authorize(soc_token, "tool:report.write", "reports/x.md")
    print(f"effect={decision.effect.value}  reason={decision.reason}")

    banner("4. Orchestrator delegates to MITRE mapper (attenuated)")
    orch_identity, orch_token = authority.mint("agent:orchestrator")
    # Nested lifetime is strict: the delegated TTL must fit inside the
    # delegator's remaining lifetime, so delegate for less than the default.
    _, mapper_token = authority.mint_delegated(
        orch_token, "agent:mitre-mapper", frozenset({"rag:corpus.security.read"}), ttl_seconds=300
    )
    decision = engine.authorize(mapper_token, "rag:corpus.security.read", "rag:corpus:security")
    print(f"delegated mapper read: effect={decision.effect.value}")

    banner("5. Revoking the orchestrator cascades")
    authority.revoke(orch_identity.identity_id)
    try:
        authority.verify(mapper_token)
        raise AssertionError("delegated identity survived revocation")  # pragma: no cover
    except VerificationError as exc:
        print(f"delegated identity now invalid: {exc}")

    banner("6. Audit chain: persisted, verified, tamper-evident")
    print(f"records={len(store.records)}  chain_ok={store.verify_chain()}")
    print(f"audit file: {audit_path}")

    # Tamper with a copy: rewrite the deny into an allow, then try to reload.
    tampered_path = workdir / "audit-tampered.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[2])
    record["payload"]["effect"] = "allow"
    lines[2] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    tampered_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        JsonlAuditStore.open(tampered_path)
        raise AssertionError("tampered chain loaded cleanly")  # pragma: no cover
    except AuditIntegrityError as exc:
        print(f"tampered copy rejected: {exc}")

    banner("Done")
    print("Every decision above fails closed; every path is in the audit chain.")


if __name__ == "__main__":
    main()
