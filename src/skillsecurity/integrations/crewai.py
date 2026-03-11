"""CrewAI integration — wraps tool invocations with security checks.

Usage:
    from skillsecurity.integrations import install
    install("crewai")

    from skillsecurity.integrations import uninstall
    uninstall("crewai")
"""

from __future__ import annotations

import functools
from typing import Any

from skillsecurity.integrations._base import _get_or_create_guard

_originals: dict[str, Any] = {}
_guard: Any = None


def install(**kwargs: Any) -> None:
    """Patch CrewAI's tool execution to add security checks."""
    global _guard
    try:
        from crewai.tools import BaseTool as CrewBaseTool
    except ImportError:
        try:
            from crewai import Tool as CrewBaseTool  # type: ignore[assignment]
        except ImportError:
            raise ImportError(
                "CrewAI is not installed. Install it with: pip install crewai"
            ) from None

    _guard = _get_or_create_guard(**kwargs)

    if hasattr(CrewBaseTool, "_run"):
        _originals["_run"] = CrewBaseTool._run  # type: ignore[attr-defined]

        @functools.wraps(CrewBaseTool._run)  # type: ignore[attr-defined]
        def secured_run(self: Any, *args: Any, **kw: Any) -> Any:
            name = getattr(self, "name", "unknown")
            tool_type = _infer_tool_type(name)
            params: dict[str, Any] = {"tool_name": name}
            if args:
                params["input"] = args[0] if len(args) == 1 else list(args)
            params.update(kw)
            decision = _guard.check({"tool": tool_type, **params})
            if decision.is_blocked:
                return f"[SkillSecurity] Blocked: {decision.reason}"
            if decision.needs_confirmation:
                return f"[SkillSecurity] Requires confirmation: {decision.reason}"
            return _originals["_run"](self, *args, **kw)

        CrewBaseTool._run = secured_run  # type: ignore[attr-defined]


def uninstall() -> None:
    """Restore CrewAI's original behavior."""
    global _guard
    try:
        from crewai.tools import BaseTool as CrewBaseTool
    except ImportError:
        try:
            from crewai import Tool as CrewBaseTool  # type: ignore[assignment]
        except ImportError:
            return

    if "_run" in _originals:
        CrewBaseTool._run = _originals.pop("_run")  # type: ignore[attr-defined]
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
