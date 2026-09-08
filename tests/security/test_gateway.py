"""Wire-boundary tests for the MCP gateway example (ATB-03 edge adapter).

The gateway is the untrusted-input surface in front of the PEP: these tests
drive ``Gateway.handle`` with hostile and edge-shaped JSON-RPC requests and
assert the session survives, refusals stay structured, and post-forward
failures are reported honestly (never as parameter errors).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest

from atb.audit import AuditLog
from atb.identity import IdentityAuthority
from examples.mcp_gateway import (
    _INTERNAL_ERROR,
    _METHOD_NOT_FOUND,
    Gateway,
    _parse_request,
)


@pytest.fixture()
def gateway() -> Gateway:
    return Gateway(sink=AuditLog(), authority=IdentityAuthority(signing_key=b"test-only-key"))


def _mint(gateway: Gateway, role: str = "agent:soc-analyst") -> str:
    response = gateway.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "atb/mint", "params": {"role": role}}
    )
    assert response is not None
    token: str = response["result"]["token"]
    return token


def _call(gateway: Gateway, tool: str, arguments: dict[str, Any], token: str) -> dict[str, Any]:
    response = gateway.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments, "_meta": {"atb_token": token}},
        }
    )
    assert response is not None
    result: dict[str, Any] = response["result"]
    return result


def test_initialize_and_tools_list(gateway: Gateway) -> None:
    """The handshake surfaces the escalation flag per tool."""
    init = gateway.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init is not None and "protocolVersion" in init["result"]
    listing = gateway.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert listing is not None
    by_name = {tool["name"]: tool for tool in listing["result"]["tools"]}
    assert "requires human approval" in by_name["http_fetch"]["description"]
    assert "requires human approval" not in by_name["log_read"]["description"]


def test_allowed_call_carries_audit_ref(gateway: Gateway) -> None:
    token = _mint(gateway)
    result = _call(gateway, "log_read", {"name": "auth.jsonl"}, token)
    assert result["isError"] is False
    assert result["_meta"]["atb"]["effect"] == "allow"
    assert result["_meta"]["atb"]["audit_ref"].startswith("ATB-DEC-")


def test_missing_token_degrades_to_denial(gateway: Gateway) -> None:
    """No token is a verification failure — a structured deny, not a crash."""
    result = _call(gateway, "log_read", {"name": "auth.jsonl"}, token="")
    assert result["isError"] is True
    assert result["_meta"]["atb"]["effect"] == "deny"
    assert result["_meta"]["atb"]["reason"].startswith("identity_invalid")


def test_escalation_returns_pending_ref(gateway: Gateway) -> None:
    token = _mint(gateway)
    result = _call(gateway, "http_fetch", {"url": "https://intel.example/feed"}, token)
    assert result["isError"] is True
    assert result["_meta"]["atb"]["effect"] == "escalate"
    assert result["_meta"]["atb"]["pending_ref"].startswith("ATB-DEC-")


def test_downstream_failure_reported_in_band(gateway: Gateway) -> None:
    """A post-forward failure is downstream_error — never 'invalid params'."""

    def broken(tool: str, arguments: Mapping[str, Any]) -> str:
        raise RuntimeError("transport down")

    gateway.pep.downstream = broken
    token = _mint(gateway)
    result = _call(gateway, "log_read", {"name": "auth.jsonl"}, token)
    assert result["isError"] is True
    assert result["_meta"]["atb"]["reason"] == "downstream_error"
    # The decision itself was chained before the forward failed.
    assert gateway.pep.engine.log.records[-1].payload["effect"] == "allow"


def test_unserializable_downstream_result_withheld(gateway: Gateway) -> None:
    """ATB-04: a non-JSON downstream result is withheld fail-closed, not relayed."""
    gateway.pep.downstream = lambda tool, arguments: object()
    token = _mint(gateway)
    result = _call(gateway, "log_read", {"name": "auth.jsonl"}, token)
    assert result["isError"] is True
    assert result["_meta"]["atb"]["effect"] == "deny"
    assert result["_meta"]["atb"]["reason"] == "textualization_failed"
    assert "refused: textualization_failed" in result["content"][0]["text"]


def test_unknown_method_and_internal_error_codes(gateway: Gateway) -> None:
    bad_method = gateway.handle({"jsonrpc": "2.0", "id": 1, "method": "shutdown", "params": {}})
    assert bad_method is not None and bad_method["error"]["code"] == _METHOD_NOT_FOUND
    bad_mint = gateway.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "atb/mint", "params": {"role": "agent:rogue"}}
    )
    assert bad_mint is not None and bad_mint["error"]["code"] == _INTERNAL_ERROR


def test_notification_yields_no_response_but_id_zero_does(gateway: Gateway) -> None:
    """id-less requests are notifications; a falsy id 0 is still a request."""
    assert gateway.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    response = gateway.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
    assert response is not None and response["id"] == 0


def test_parse_request_survives_hostile_lines() -> None:
    """Deep nesting, garbage, and non-object JSON all degrade to None."""
    assert _parse_request("[" * 100_000) is None  # RecursionError path
    assert _parse_request("not json") is None
    assert _parse_request('"a bare string"') is None
    assert _parse_request(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "x"})) is not None
