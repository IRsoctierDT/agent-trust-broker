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
  design: **stop the gateway before resolving escalations with the operator
  CLI, then restart it** — the fresh open replays the chain (including the
  resolution), whereas appending from two processes forks the chain and
  every subsequent open fails closed.
- ``ATB_QUARANTINE_DIR`` — directory for withheld response payloads
  (ATB-04). Required when ``ATB_AUDIT_CHAIN`` is set; must lie outside
  ``workspace/``. Unset in demo mode: an in-memory store is used.
- ``ATB_SCREEN_MAX_BYTES`` / ``ATB_QUARANTINE_MAX_BYTES`` /
  ``ATB_QUARANTINE_BUDGET_BYTES`` — screening and quarantine bounds; all
  parsed fail-closed (an invalid value refuses to start). Screening itself
  has **no off switch**: disabling it is a code change through review.
- ``ATB_DEMO_MINT`` — set to ``1`` to enable the lab-only ``atb/mint``
  method. Unset/any other value: ``atb/mint`` is refused (production default).
- ``ATB_REQUIRE_PLAN`` — set to ``1`` to require an ``atb/declare_plan``
  before any ``tools/call``. Unset: plans are optional until declared;
  once declared, divergence escalates to HITL.

Security considerations: tokens are read from ``_meta`` and passed only to
the policy engine — never logged, never echoed. A missing or malformed
token simply fails verification (deny, ``identity_invalid``). Demo
``atb/mint`` is **off by default**; enable only for local labs via
``ATB_DEMO_MINT=1``. Production mints identities out of band.
"""

from __future__ import annotations

import base64
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
from atb.screening import (
    DEFAULT_QUARANTINE_BUDGET_BYTES,
    DEFAULT_QUARANTINE_MAX_BYTES,
    DEFAULT_SCREEN_MAX_BYTES,
    FileQuarantineStore,
    MemoryQuarantineStore,
    QuarantineStore,
    ResponseScreener,
)

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "ianua-atb-gateway", "version": "0.2.0"}

_PARSE_ERROR = -32700
_METHOD_NOT_FOUND = -32601
_INTERNAL_ERROR = -32603


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

    def __init__(
        self,
        sink: AuditSink,
        authority: IdentityAuthority,
        screener: ResponseScreener | None = None,
        quarantine: QuarantineStore | None = None,
        *,
        demo_mint: bool = False,
        require_plan: bool = False,
    ) -> None:
        self.authority = authority
        self.demo_mint = demo_mint
        self.queue = EscalationQueue(log=sink)
        engine = PolicyEngine(authority=authority, log=sink, approvals=self.queue)
        from atb.plan import PlanBook

        self.pep = PolicyEnforcementPoint(
            engine=engine,
            queue=self.queue,
            downstream=_lab_downstream,
            screener=screener if screener is not None else ResponseScreener(),
            quarantine=quarantine if quarantine is not None else MemoryQuarantineStore(),
            plans=PlanBook(require_plan=require_plan),
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
        try:
            outcome = self.pep.mediate(invocation)
        except Exception as exc:
            # The PEP surfaces downstream errors unchanged (the forward was
            # already authorized and chained). Report it in-band with the
            # FIXED token only — an exception class name or message is
            # downstream-controlled text riding the transport path (ATB-04
            # hardening). Detail goes to stderr for the operator.
            print(f"downstream error: {type(exc).__name__}: {exc}", file=sys.stderr)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "tool execution failed after the authorization decision "
                            "(any forward was already audited)"
                        ),
                    }
                ],
                "isError": True,
                "_meta": {"atb": {"effect": "error", "reason": "downstream_error"}},
            }
        atb_meta = {
            "effect": outcome.effect.value,
            "reason": outcome.reason,
            "audit_ref": outcome.audit_ref,
            "pending_ref": outcome.pending_ref,
        }
        if outcome.quarantine_digest:
            # Releasable withhold: the agent needs the digest to request
            # release later; rule ids are deliberately absent (evidence is
            # operator-facing, never evasion feedback).
            atb_meta["quarantine_digest"] = outcome.quarantine_digest
            atb_meta["screen_ruleset"] = self.pep.screener.version
        if outcome.effect is Effect.ALLOW:
            if isinstance(outcome.result, (bytes, bytearray)):
                # Released binary content (a human-approved undecodable blob):
                # deliver byte-exact via base64 rather than lossy decoding —
                # the digest already bound the approval to these exact bytes.
                text = json.dumps(
                    {"encoding": "base64", "data": base64.b64encode(outcome.result).decode("ascii")}
                )
            else:
                try:
                    text = json.dumps(outcome.result)
                except (TypeError, ValueError):
                    text = "downstream result is not JSON-serializable"
        elif outcome.effect is Effect.ESCALATE and outcome.quarantine_digest:
            text = (
                f"response withheld pending human review — pending ref {outcome.pending_ref}; "
                f"an operator resolves it with: atb approve {outcome.pending_ref} --reason ..."
            )
        elif outcome.effect is Effect.ESCALATE:
            text = (
                f"held for human approval — pending ref {outcome.pending_ref}; "
                f"an operator resolves it with: atb approve {outcome.pending_ref} --reason ..."
            )
        else:
            text = f"refused: {outcome.reason} (audit {outcome.audit_ref})"
        return {
            "content": [{"type": "text", "text": text}],
            # A withheld response is truthfully forwarded=True yet must
            # present as an error to the client: key on the effect (ATB-04).
            "isError": outcome.effect is not Effect.ALLOW,
            "_meta": {"atb": atb_meta},
        }

    def _mint(self, params: dict[str, Any]) -> dict[str, Any]:
        """Lab-only identity minting — refused unless ``demo_mint`` is enabled."""
        if not self.demo_mint:
            raise PermissionError("atb/mint disabled (set ATB_DEMO_MINT=1 for lab demos only)")
        role = _str_or_empty(params.get("role")) or "agent:soc-analyst"
        identity, token = self.authority.mint(role)
        return {
            "identity_id": identity.identity_id,
            "subject": identity.subject,
            "not_after": identity.not_after.isoformat(),
            "scopes": sorted(identity.scopes),
            "token": token,
        }

    def _declare_plan(self, params: dict[str, Any]) -> dict[str, Any]:
        """Declare the outbound tool allowlist for the caller's subject."""
        meta = _dict_or_empty(params.get("_meta"))
        token = _str_or_empty(meta.get("atb_token"))
        tools = params.get("tools")
        if not isinstance(tools, list):
            raise ValueError("tools must be a list of tool names")
        from atb.plan import PlanError

        try:
            declared = self.pep.declare_plan(token, tools)
        except PlanError as exc:
            raise ValueError(str(exc)) from exc
        return {
            "subject": declared.subject,
            "tools": sorted(declared.tools),
            "audit_ref": declared.audit_ref,
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
            elif method == "atb/declare_plan":
                result = self._declare_plan(params)
            else:
                return _error(request_id, _METHOD_NOT_FOUND, f"unknown method: {method!r}")
        except Exception as exc:  # one bad request must not kill the session
            # Fixed token only: exception text may carry downstream-controlled
            # content (ATB-04 hardening). Detail goes to stderr.
            print(f"internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
            return _error(request_id, _INTERNAL_ERROR, "internal_error")
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


def _positive_int_env(name: str, default: int) -> int:
    """Parse a positive-integer knob fail-closed: invalid is a startup error."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"error: {name} must be a positive integer") from exc
    if value <= 0:
        raise SystemExit(f"error: {name} must be a positive integer")
    return value


def _build_screener() -> ResponseScreener:
    """Screening caps from the environment; screening itself has no off switch."""
    return ResponseScreener(
        max_scan_bytes=_positive_int_env("ATB_SCREEN_MAX_BYTES", DEFAULT_SCREEN_MAX_BYTES),
        max_blob_bytes=_positive_int_env("ATB_QUARANTINE_MAX_BYTES", DEFAULT_QUARANTINE_MAX_BYTES),
    )


def _filesystem_resource_roots() -> dict[str, Path]:
    """Resolved root directory of every path-shaped catalog resource pattern.

    A filesystem-path pattern (e.g. ``logs/lab/*``, ``reports/*``,
    ``workspace/*``) roots a directory a granted ``fs``/``tool`` scope could
    read; scheme-prefixed patterns (``rag:``, ``agent:``, ``host:``,
    ``quarantine:``, ``atb:``) name no path and are skipped. The quarantine
    store must sit outside all of them, or a release-loop bypass exists.
    """
    roots: dict[str, Path] = {}
    for spec in CATALOG.values():
        for pattern in spec.resource_patterns:
            head = pattern.split("/", 1)[0].split("*", 1)[0]
            if not head or ":" in head:
                continue  # scheme-prefixed or wildcard-rooted: not a fs path
            prefix = pattern.split("*", 1)[0].rstrip("/")
            roots[pattern] = (Path.cwd() / prefix).resolve()
    return roots


def _build_quarantine() -> QuarantineStore:
    """Quarantine store from ``ATB_QUARANTINE_DIR``; fail closed on misuse.

    A durable chain requires a durable quarantine — approvals recorded in a
    durable chain must not reference content that dies with the process.
    The directory must lie outside every path-shaped catalog resource
    pattern so no ``fs``/``tool`` scope can ever cover it (release-loop
    bypass).
    """
    raw = os.environ.get("ATB_QUARANTINE_DIR", "").strip()
    budget = _positive_int_env("ATB_QUARANTINE_BUDGET_BYTES", DEFAULT_QUARANTINE_BUDGET_BYTES)
    if not raw:
        if os.environ.get("ATB_AUDIT_CHAIN", "").strip():
            raise SystemExit(
                "error: ATB_QUARANTINE_DIR is required when ATB_AUDIT_CHAIN is set "
                "(a durable chain needs a durable quarantine)"
            )
        return MemoryQuarantineStore(budget_bytes=budget)
    root = Path(raw).resolve()
    for pattern, reachable in _filesystem_resource_roots().items():
        if root == reachable or reachable in root.parents:
            raise SystemExit(
                f"error: ATB_QUARANTINE_DIR must lie outside catalog resource {pattern!r}"
            )
    return FileQuarantineStore(root=root, budget_bytes=budget)


def _parse_request(line: str) -> dict[str, Any] | None:
    """Parse one wire line to a request object; None on any hostile input.

    ``RecursionError`` (deeply nested JSON) is caught alongside parse
    errors: one hostile line must degrade to a parse-error response, never
    kill the session.
    """
    try:
        request = json.loads(line)
    except (ValueError, RecursionError):
        return None
    return request if isinstance(request, dict) else None


def main() -> int:
    """Serve newline-delimited JSON-RPC on stdio until EOF."""
    gateway = Gateway(
        sink=_build_sink(),
        authority=_build_authority(),
        screener=_build_screener(),
        quarantine=_build_quarantine(),
        demo_mint=os.environ.get("ATB_DEMO_MINT", "").strip() == "1",
        require_plan=os.environ.get("ATB_REQUIRE_PLAN", "").strip() == "1",
    )
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        request = _parse_request(line)
        if request is None:
            print(json.dumps(_error(None, _PARSE_ERROR, "parse error")), flush=True)
            continue
        response = gateway.handle(request)
        if response is not None:
            print(json.dumps(response), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
