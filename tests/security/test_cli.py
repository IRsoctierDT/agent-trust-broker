"""Security tests for the operator CLI: every failure path exits non-zero.

The CLI is the human side of the escalation gate, so its failure modes are
security behavior: a missing/tampered chain, an unknown ref, or a double
resolution must fail loudly — and a resolution recorded via the CLI must be
indistinguishable from one recorded via the library (same chain, same rules).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from atb.cli import main
from atb.escalation import EscalationQueue
from atb.identity import IdentityAuthority
from atb.persistence import JsonlAuditStore
from atb.policy import Effect, PolicyEngine


def _seed_chain(path: Path) -> str:
    """Create a chain holding one pending escalation; return its ref."""
    authority = IdentityAuthority(
        signing_key=b"test-only-key", now=lambda: datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
    )
    store = JsonlAuditStore.open(path)
    queue = EscalationQueue(log=store)
    engine = PolicyEngine(authority=authority, log=store, approvals=queue)
    _, token = authority.mint("agent:soc-analyst")
    return queue.submit(engine.authorize(token, "net:egress", "host:intel.example"))


def test_missing_chain_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="no audit chain at"):
        main(["--chain", str(tmp_path / "absent.jsonl"), "pending"])


def test_no_chain_configured_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ATB_AUDIT_CHAIN", raising=False)
    with pytest.raises(SystemExit, match="pass --chain or set ATB_AUDIT_CHAIN"):
        main(["pending"])


def test_tampered_chain_fails_closed(tmp_path: Path) -> None:
    chain = tmp_path / "audit.jsonl"
    _seed_chain(chain)
    lines = chain.read_text().splitlines()
    chain.write_text("\n".join(lines[1:]) + "\n")  # drop the first record
    with pytest.raises(SystemExit, match="FAILED verification"):
        main(["--chain", str(chain), "pending"])


def test_pending_lists_the_escalation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    chain = tmp_path / "audit.jsonl"
    ref = _seed_chain(chain)
    assert main(["--chain", str(chain), "pending"]) == 0
    out = capsys.readouterr().out
    assert ref in out and "host:intel.example" in out


def test_approve_records_and_is_consumable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A CLI approval is a real chain record the engine can consume."""
    chain = tmp_path / "audit.jsonl"
    ref = _seed_chain(chain)
    assert (
        main(
            [
                "--chain",
                str(chain),
                "approve",
                ref,
                "--reason",
                "known safe intel feed",
                "--approver",
                "ivan",
            ]
        )
        == 0
    )
    assert f"APPROVED {ref} by ivan" in capsys.readouterr().out

    # Reload as the broker would: the approval closes the loop exactly once.
    store = JsonlAuditStore.open(chain)
    queue = EscalationQueue(log=store)
    assert queue.is_approved(ref) is True
    authority = IdentityAuthority(
        signing_key=b"test-only-key", now=lambda: datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
    )
    engine = PolicyEngine(authority=authority, log=store, approvals=queue)
    _, token = authority.mint("agent:soc-analyst")
    decision = engine.authorize(
        token, "net:egress", "host:intel.example", context={"approval_ref": ref}
    )
    assert decision.effect is Effect.ALLOW


def test_deny_and_double_resolution_fail_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    chain = tmp_path / "audit.jsonl"
    ref = _seed_chain(chain)
    assert (
        main(["--chain", str(chain), "deny", ref, "--reason", "unknown host", "--approver", "ivan"])
        == 0
    )
    assert f"DENIED {ref}" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="already resolved"):
        main(["--chain", str(chain), "approve", ref, "--reason", "retry", "--approver", "ivan"])


def test_unknown_ref_fails_closed(tmp_path: Path) -> None:
    chain = tmp_path / "audit.jsonl"
    _seed_chain(chain)
    with pytest.raises(SystemExit, match="unknown escalation"):
        main(
            [
                "--chain",
                str(chain),
                "approve",
                "ATB-DEC-999999",
                "--reason",
                "x",
                "--approver",
                "ivan",
            ]
        )


def test_reason_is_mandatory(tmp_path: Path) -> None:
    chain = tmp_path / "audit.jsonl"
    ref = _seed_chain(chain)
    with pytest.raises(SystemExit):  # argparse exits 2: --reason is required
        main(["--chain", str(chain), "approve", ref, "--approver", "ivan"])


def test_verify_reports_chain_health(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    chain = tmp_path / "audit.jsonl"
    _seed_chain(chain)
    assert main(["--chain", str(chain), "verify"]) == 0
    out = capsys.readouterr().out
    assert "Chain OK" in out and "1 pending" in out


def test_env_var_supplies_chain_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    chain = tmp_path / "audit.jsonl"
    _seed_chain(chain)
    monkeypatch.setenv("ATB_AUDIT_CHAIN", str(chain))
    assert main(["pending"]) == 0
    assert "ATB-DEC-" in capsys.readouterr().out


def test_approver_defaults_to_os_user(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    chain = tmp_path / "audit.jsonl"
    ref = _seed_chain(chain)
    assert main(["--chain", str(chain), "approve", ref, "--reason", "ok"]) == 0
    out = capsys.readouterr().out
    assert "APPROVED" in out and " by " in out  # attributed to the OS user
