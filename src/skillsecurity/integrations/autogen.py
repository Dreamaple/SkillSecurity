"""AutoGen integration — wraps tool execution with security checks.

Usage:
    from skillsecurity.integrations import install
    install("autogen")

    from skillsecurity.integrations import uninstall
    uninstall("autogen")
"""

from __future__ import annotations

import functools
from typing import Any

from skillsecurity.integrations._base import _get_or_create_guard

_originals: dict[str, Any] = {}
_guard: Any = None


def install(**kwargs: Any) -> None:
    """Patch AutoGen's function execution to add security checks."""
    global _guard
    try:
        from autogen import ConversableAgent
    except ImportError:
        raise ImportError(
            "AutoGen is not installed. Install it with: pip install pyautogen"
        ) from None

    _guard = _get_or_create_guard(**kwargs)

    if hasattr(ConversableAgent, "execute_function"):
        _originals["execute_function"] = ConversableAgent.execute_function

        @functools.wraps(ConversableAgent.execute_function)
        def secured_execute(self: Any, func_call: dict, *args: Any, **kw: Any) -> Any:
            name = func_call.get("name", "unknown")
            arguments = func_call.get("arguments", {})
            if isinstance(arguments, str):
                import json

                try:
                    arguments = json.loads(arguments)
                except (json.JSONDecodeError, TypeError):
                    arguments = {"input": arguments}

            tool_type = _infer_tool_type(name)
            decision = _guard.check({"tool": tool_type, "tool_name": name, **arguments})
            if decision.is_blocked:
                return False, {"content": f"[SkillSecurity] Blocked: {decision.reason}"}
            if decision.needs_confirmation:
                return False, {
                    "content": f"[SkillSecurity] Requires confirmation: {decision.reason}"
                }
            return _originals["execute_function"](self, func_call, *args, **kw)

        ConversableAgent.execute_function = secured_execute  # type: ignore[attr-defined]


def uninstall() -> None:
    """Restore AutoGen's original behavior."""
    global _guard
    try:
        from autogen import ConversableAgent
    except ImportError:
        return

    if "execute_function" in _originals:
        ConversableAgent.execute_function = _originals.pop("execute_function")  # type: ignore[attr-defined]
    _guard = None


def _infer_tool_type(name: str) -> str:
    name_lower = name.lower()
    if any(k in name_lower for k in ("shell", "bash", "exec", "command", "terminal")):
        return "shell"
    if any(k in name_lower for k in ("read", "file_read")):
        return "file.read"
    if any(k in name_lower for k in ("write", "file_write")):
        return "file.write"
    if any(k in name_lower for k in ("http", "request", "api", "fetch")):
        return "network.request"
    if any(k in name_lower for k in ("browse", "web")):
        return "browser"
    if any(k in name_lower for k in ("sql", "database", "query")):
        return "database"
    return "shell"
