"""MCP / OpenClaw integration — wraps MCP server tool handlers with security checks.

Usage:
    from skillsecurity.integrations import install
    install("mcp")   # or install("openclaw")

    from skillsecurity.integrations import uninstall
    uninstall("mcp")
"""

from __future__ import annotations

import functools
from typing import Any

from skillsecurity.integrations._base import (
    _build_pending_approval_payload,
    _format_pending_approval_message,
    _get_or_create_guard,
)

_originals: dict[str, Any] = {}
_guard: Any = None

_MCP_TOOL_MAP: dict[str, str] = {
    "bash": "shell",
    "shell": "shell",
    "run_command": "shell",
    "execute_command": "shell",
    "read_file": "file.read",
    "read": "file.read",
    "write_file": "file.write",
    "write": "file.write",
    "edit_file": "file.write",
    "create_file": "file.write",
    "delete_file": "file.delete",
    "remove": "file.delete",
    "http_request": "network.request",
    "fetch": "network.request",
    "curl": "network.request",
    "browse": "browser",
    "browser": "browser",
    "navigate": "browser",
    "sql_query": "database",
    "query": "database",
    "send_message": "message.send",
}


def _apply_openclaw_default_policy(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Use hardened defaults for MCP/OpenClaw unless user explicitly overrides."""
    if any(k in kwargs for k in ("guard", "policy", "policy_file", "config")):
        return kwargs
    merged = dict(kwargs)
    merged["policy"] = "openclaw-hardened"
    return merged


def install(**kwargs: Any) -> None:
    """Patch MCP server's call_tool handler with security checks.

    If you use the Python MCP SDK, this patches the Server class.
    For custom MCP implementations, use the `wrap_mcp_handler` helper.
    """
    global _guard
    _guard = _get_or_create_guard(**_apply_openclaw_default_policy(kwargs))

    try:
        from mcp.server import Server

        if hasattr(Server, "call_tool"):
            _originals["call_tool"] = Server.call_tool

            original_call_tool = Server.call_tool

            @functools.wraps(original_call_tool)
            async def secured_call_tool(self: Any, name: str, arguments: dict | None = None) -> Any:
                args = arguments or {}
                tool_type = _MCP_TOOL_MAP.get(name, "shell")
                tool_call = {"tool": tool_type, "tool_name": name, **args}
                decision = _guard.check(tool_call)
                if decision.is_blocked:
                    return [{"type": "text", "text": f"[SkillSecurity] Blocked: {decision.reason}"}]
                if decision.needs_confirmation:
                    payload = _build_pending_approval_payload(
                        _guard, tool_call, decision, source="mcp"
                    )
                    return [
                        {
                            "type": "text",
                            "text": _format_pending_approval_message(payload),
                        }
                    ]
                return await original_call_tool(self, name, arguments)

            Server.call_tool = secured_call_tool  # type: ignore[attr-defined]
    except ImportError:
        pass


def uninstall() -> None:
    """Restore MCP server's original call_tool handler."""
    global _guard
    try:
        from mcp.server import Server

        if "call_tool" in _originals:
            Server.call_tool = _originals.pop("call_tool")  # type: ignore[attr-defined]
    except ImportError:
        pass
    _guard = None


def wrap_mcp_handler(handler: Any, **kwargs: Any) -> Any:
    """Wrap an arbitrary async MCP tool handler function with security checks.

    For custom MCP server implementations that don't use the official Python SDK.

    Usage:
        async def my_tool_handler(name, arguments):
            ...

        my_tool_handler = wrap_mcp_handler(my_tool_handler, policy_file="policy.yaml")
    """
    guard = _get_or_create_guard(**_apply_openclaw_default_policy(kwargs))

    @functools.wraps(handler)
    async def secured_handler(name: str, arguments: dict | None = None, **kw: Any) -> Any:
        args = arguments or {}
        tool_type = _MCP_TOOL_MAP.get(name, "shell")
        tool_call = {"tool": tool_type, "tool_name": name, **args}
        decision = guard.check(tool_call)
        if decision.is_blocked:
            raise RuntimeError(f"[SkillSecurity] Blocked: {decision.reason}")
        if decision.needs_confirmation:
            payload = _build_pending_approval_payload(guard, tool_call, decision, source="mcp")
            raise RuntimeError(_format_pending_approval_message(payload))
        return await handler(name, arguments, **kw)

    secured_handler._skillsecurity_original = handler  # type: ignore[attr-defined]
    return secured_handler
