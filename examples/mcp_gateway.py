"""MCP edge adapter (ATB-03): a stdio gateway that puts the PEP on the wire.

Purpose: demonstrate the ATB-03 enforcement path end to end — an MCP-shaped
JSON-RPC 2.0 server over stdin/stdout whose every ``tools/call`` is mediated
by the ``PolicyEnforcementPoint`` before anything executes. Allowed calls
reach lab-scoped stub handlers; denied and escalated calls return structured
refusals carrying the audit reference. Escalations land in the same queue
the ``atb`` operator CLI resolves (``atb pending / approve / deny``).

Risk level: low (lab-scoped stubs — no real filesystem or network side
effects). Skill level: intermediate. Deployment complexity: low (stdlib
only; see ``infra/`` for the rootless container recipe).

Wire protocol: the JSON-RPC subset MCP uses over stdio — ``initialize``,
``tools/list``, ``tools/call`` — implemented with the standard library so
the example runs and type-checks with zero dependencies. Swapping in the
official ``mcp`` SDK is a deliberate follow-up that goes through the
AGENTS.md §5.1 dependency gate; this module keeps the enforcement wiring
identical either way. The agent's minted token travels in MCP ``_meta``
(``_meta.atb_token``), never in tool arguments.

Configuration (environment; see ``.env.example``):

- ``ATB_SIGNING_KEY`` — hex-encoded HMAC key for the identity authority.
  Unset: an ephemeral key is generated and identities die with the process.
- ``ATB_AUDIT_CHAIN`` — path to the durable JSONL audit chain. Unset: the
  chain lives in memory (demo mode). The chain has one writer at a time by
  design; run the operator CLI when the gateway is not actively appending.

Security considerations: tokens are read from ``_meta`` and passed only to
the policy engine — never logged, never echoed. A missing or malformed
token simply fails verification (deny, ``identity_invalid``). The demo
``atb/mint`` method exists so the example is drivable by hand; a production
deployment mints identities out of band and removes it.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from atb.audit import AuditLog, AuditSink
from atb.catalog import CATALOG
from atb.enforcement import PolicyEnforcementPoint, ToolInvocation
from atb.escalation import EscalationQueue
from atb.identity import IdentityAuthority
from atb.persistence import AuditIntegrityError, JsonlAuditStore
from atb.policy import Effect, PolicyEngine

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "ianua-atb-gateway", "version": "0.1.0"}

_PARSE_ERROR = -32700
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602


def _lab_downstream(tool: str, arguments: Mapping[str, Any]) -> object:
    """Lab-scoped stub transport: echoes, never touches real fs or network.

    A real deployment replaces this callable with the actual tool transport;
    the enforcement wiring above it does not change.
    """
    return {"tool": tool, "status": "executed (lab stub)", "arguments": dict(arguments)}


def _str_or_empty(value: object) -> str:
    """Untrusted wire field -> str; anything else becomes the empty string.

    An empty token fails identity verification, so malformed input degrades
    to a denial — never to a crash, never to a forward.
    """
    return value if isinstance(value, str) else ""


def _str_mapping(value: object) -> dict[str, str]:
    """Untrusted wire object -> str->str mapping; non-strings are dropped."""
    if not isinstance(value, dict):
        return {}
    return {k: v for k, v in value.items() if isinstance(k, str) and isinstance(v, str)}


def _dict_or_empty(value: object) -> dict[str, Any]:
    """Untrusted wire field -> object mapping; anything else becomes empty."""
    return value if isinstance(value, dict) else {}


class Gateway:
    """One PEP-mediated MCP session over newline-delimited JSON-RPC."""

    def __init__(self, sink: AuditSink, authority: IdentityAuthority) -> None:
        self.authority = authority
        self.queue = EscalationQueue(log=sink)
        engine = PolicyEngine(authority=authority, log=sink, approvals=self.queue)
        self.pep = PolicyEnforcementPoint(
            engine=engine, queue=self.queue, downstream=_lab_downstream
        )

    # ------------------------------------------------------------ methods
    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "serverInfo": SERVER_INFO,
            "capabilities": {"tools": {}},
        }

    def _tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        tools = []
        for name, rule in sorted(self.pep.tool_map.items()):
            spec = CATALOG[rule.action]
            tools.append(
                {
                    "name": name,
                    "description": (
                        f"action={rule.action} risk={spec.risk.value}"
                        + (" (requires human approval)" if spec.escalates else "")
                    ),
                    "inputSchema": {"type": "object"},
                }
            )
        return {"tools": tools}

    def _tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        meta = _dict_or_empty(params.get("_meta"))
        arguments = params.get("arguments")
        invocation = ToolInvocation(
            token=_str_or_empty(meta.get("atb_token")),
            tool=_str_or_empty(params.get("name")),
            arguments=arguments if isinstance(arguments, dict) else {},
            context=_str_mapping(meta.get("atb_context")),
        )
        outcome = self.pep.mediate(invocation)
        atb_meta = {
            "effect": outcome.effect.value,
            "reason": outcome.reason,
            "audit_ref": outcome.audit_ref,
            "pending_ref": outcome.pending_ref,
        }
        if outcome.effect is Effect.ALLOW:
            text = json.dumps(outcome.result)
        elif outcome.effect is Effect.ESCALATE:
            text = (
                f"held for human approval — pending ref {outcome.pending_ref}; "
                f"an operator resolves it with: atb approve {outcome.pending_ref} --reason ..."
            )
        else:
            text = f"refused: {outcome.reason} (audit {outcome.audit_ref})"
        return {
            "content": [{"type": "text", "text": text}],
            "isError": not outcome.forwarded,
            "_meta": {"atb": atb_meta},
        }

    def _mint(self, params: dict[str, Any]) -> dict[str, Any]:
        """Demo-only identity minting so the gateway is drivable by hand."""
        role = _str_or_empty(params.get("role")) or "agent:soc-analyst"
        identity, token = self.authority.mint(role)
        return {
            "identity_id": identity.identity_id,
            "subject": identity.subject,
            "not_after": identity.not_after.isoformat(),
            "scopes": sorted(identity.scopes),
            "token": token,
        }

    # ------------------------------------------------------------ dispatch
    def handle(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Dispatch one JSON-RPC request; notifications yield no response."""
        method = _str_or_empty(request.get("method"))
        request_id = request.get("id")
        params = _dict_or_empty(request.get("params"))
        if request_id is None:  # notification (e.g. notifications/initialized)
            return None
        try:
            if method == "initialize":
                result = self._initialize(params)
            elif method == "tools/list":
                result = self._tools_list(params)
            elif method == "tools/call":
                result = self._tools_call(params)
            elif method == "atb/mint":
                result = self._mint(params)
            else:
                return _error(request_id, _METHOD_NOT_FOUND, f"unknown method: {method!r}")
        except Exception as exc:  # one bad request must not kill the session
            return _error(request_id, _INVALID_PARAMS, f"{type(exc).__name__}: {exc}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _build_sink() -> AuditSink:
    """Durable chain when ``ATB_AUDIT_CHAIN`` is set; in-memory otherwise."""
    chain = os.environ.get("ATB_AUDIT_CHAIN", "").strip()
    if not chain:
        return AuditLog()
    try:
        return JsonlAuditStore.open(Path(chain))
    except AuditIntegrityError as exc:
        raise SystemExit(f"error: audit chain FAILED verification — {exc}") from exc


def _build_authority() -> IdentityAuthority:
    """Key from ``ATB_SIGNING_KEY`` (hex) or an ephemeral per-process key."""
    raw = os.environ.get("ATB_SIGNING_KEY", "").strip()
    if not raw:
        return IdentityAuthority(signing_key=secrets.token_bytes(32))
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise SystemExit("error: ATB_SIGNING_KEY must be hex-encoded") from exc
    if len(key) < 32:
        raise SystemExit("error: ATB_SIGNING_KEY must be at least 32 bytes")
    return IdentityAuthority(signing_key=key)


def main() -> int:
    """Serve newline-delimited JSON-RPC on stdio until EOF."""
    gateway = Gateway(sink=_build_sink(), authority=_build_authority())
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            print(json.dumps(_error(None, _PARSE_ERROR, "parse error")), flush=True)
            continue
        if not isinstance(request, dict):
            print(json.dumps(_error(None, _PARSE_ERROR, "request must be an object")), flush=True)
            continue
        response = gateway.handle(request)
        if response is not None:
            print(json.dumps(response), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
