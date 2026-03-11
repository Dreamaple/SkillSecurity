"""LangChain integration — wraps BaseTool._run and _arun with security checks.

Usage:
    from skillsecurity.integrations import install
    install("langchain")
    # All LangChain tools now pass through SkillSecurity

    from skillsecurity.integrations import uninstall
    uninstall("langchain")
"""

from __future__ import annotations

import functools
from typing import Any

from skillsecurity.integrations._base import _get_or_create_guard

_originals: dict[str, Any] = {}
_guard: Any = None


def install(**kwargs: Any) -> None:
    """Monkey-patch LangChain's BaseTool to add security checks."""
    global _guard
    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        try:
            from langchain.tools import BaseTool
        except ImportError:
            raise ImportError(
                "LangChain is not installed. Install it with: pip install langchain-core"
            ) from None

    _guard = _get_or_create_guard(**kwargs)
    _originals["_run"] = BaseTool._run  # type: ignore[attr-defined]

    @functools.wraps(BaseTool._run)  # type: ignore[attr-defined]
    def secured_run(self: Any, *args: Any, **kw: Any) -> Any:
        tool_call = _build_tool_call(self, args, kw)
        decision = _guard.check(tool_call)
        if decision.is_blocked:
            return f"[SkillSecurity] Blocked: {decision.reason}"
        if decision.needs_confirmation:
            return (
                f"[SkillSecurity] Requires confirmation: {decision.reason}\n"
                f"Suggestions: {'; '.join(decision.suggestions)}"
            )
        return _originals["_run"](self, *args, **kw)

    BaseTool._run = secured_run  # type: ignore[attr-defined]

    if hasattr(BaseTool, "_arun"):
        _originals["_arun"] = BaseTool._arun  # type: ignore[attr-defined]

        @functools.wraps(BaseTool._arun)  # type: ignore[attr-defined]
        async def secured_arun(self: Any, *args: Any, **kw: Any) -> Any:
            tool_call = _build_tool_call(self, args, kw)
            decision = _guard.check(tool_call)
            if decision.is_blocked:
                return f"[SkillSecurity] Blocked: {decision.reason}"
            if decision.needs_confirmation:
                return (
                    f"[SkillSecurity] Requires confirmation: {decision.reason}\n"
                    f"Suggestions: {'; '.join(decision.suggestions)}"
                )
            return await _originals["_arun"](self, *args, **kw)

        BaseTool._arun = secured_arun  # type: ignore[attr-defined]


def uninstall() -> None:
    """Restore LangChain's original BaseTool methods."""
    global _guard
    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        from langchain.tools import BaseTool

    if "_run" in _originals:
        BaseTool._run = _originals.pop("_run")  # type: ignore[attr-defined]
    if "_arun" in _originals:
        BaseTool._arun = _originals.pop("_arun")  # type: ignore[attr-defined]
    _guard = None


def _build_tool_call(tool: Any, args: tuple, kwargs: dict) -> dict:
    name = getattr(tool, "name", "unknown")
    tool_type = _infer_tool_type(name)
    params: dict[str, Any] = {"tool_name": name}
    if args:
        params["input"] = args[0] if len(args) == 1 else list(args)
    params.update(kwargs)
    return {"tool": tool_type, **params}


def _infer_tool_type(name: str) -> str:
    name_lower = name.lower()
    if any(k in name_lower for k in ("shell", "bash", "terminal", "command")):
        return "shell"
    if any(k in name_lower for k in ("file_read", "read_file", "read")):
        return "file.read"
    if any(k in name_lower for k in ("file_write", "write_file", "write")):
        return "file.write"
    if any(k in name_lower for k in ("http", "request", "api", "fetch", "curl")):
        return "network.request"
    if any(k in name_lower for k in ("browse", "web", "scrape")):
        return "browser"
    if any(k in name_lower for k in ("sql", "database", "query", "db")):
        return "database"
    return "shell"
