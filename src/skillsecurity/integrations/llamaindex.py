"""LlamaIndex integration — wraps tool execution with security checks.

Usage:
    from skillsecurity.integrations import install
    install("llamaindex")

    from skillsecurity.integrations import uninstall
    uninstall("llamaindex")
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


def install(**kwargs: Any) -> None:
    """Patch LlamaIndex's tool execution to add security checks."""
    global _guard
    try:
        from llama_index.core.tools import FunctionTool
    except ImportError:
        try:
            from llama_index.tools import FunctionTool  # type: ignore[assignment]
        except ImportError:
            raise ImportError(
                "LlamaIndex is not installed. Install it with: pip install llama-index-core"
            ) from None

    _guard = _get_or_create_guard(**kwargs)

    if hasattr(FunctionTool, "call"):
        _originals["call"] = FunctionTool.call

        @functools.wraps(FunctionTool.call)
        def secured_call(self: Any, *args: Any, **kw: Any) -> Any:
            name = getattr(self, "_name", None) or getattr(
                getattr(self, "metadata", None), "name", "unknown"
            )
            tool_type = _infer_tool_type(name)
            params: dict[str, Any] = {"tool_name": name}
            if args:
                params["input"] = args[0] if len(args) == 1 else list(args)
            params.update(kw)

            tool_call = {"tool": tool_type, **params}
            decision = _guard.check(tool_call)
            if decision.is_blocked:
                from llama_index.core.tools import ToolOutput

                return ToolOutput(
                    content=f"[SkillSecurity] Blocked: {decision.reason}",
                    tool_name=name,
                    raw_input=params,
                    raw_output=f"Blocked: {decision.reason}",
                )
            if decision.needs_confirmation:
                from llama_index.core.tools import ToolOutput

                payload = _build_pending_approval_payload(
                    _guard, tool_call, decision, source="llamaindex"
                )
                message = _format_pending_approval_message(payload)
                return ToolOutput(
                    content=message,
                    tool_name=name,
                    raw_input=params,
                    raw_output=message,
                )
            return _originals["call"](self, *args, **kw)

        FunctionTool.call = secured_call  # type: ignore[attr-defined]


def uninstall() -> None:
    """Restore LlamaIndex's original behavior."""
    global _guard
    try:
        from llama_index.core.tools import FunctionTool
    except ImportError:
        try:
            from llama_index.tools import FunctionTool  # type: ignore[assignment]
        except ImportError:
            return

    if "call" in _originals:
        FunctionTool.call = _originals.pop("call")  # type: ignore[attr-defined]
    _guard = None


def _infer_tool_type(name: str) -> str:
    name_lower = name.lower()
    if any(k in name_lower for k in ("shell", "bash", "terminal", "command")):
        return "shell"
    if any(k in name_lower for k in ("read", "file_read")):
        return "file.read"
    if any(k in name_lower for k in ("write", "file_write")):
        return "file.write"
    if any(k in name_lower for k in ("http", "request", "api", "fetch")):
        return "network.request"
    if any(k in name_lower for k in ("browse", "web", "scrape")):
        return "browser"
    if any(k in name_lower for k in ("sql", "database", "query")):
        return "database"
    return "shell"
