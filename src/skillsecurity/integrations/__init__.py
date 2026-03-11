"""Framework integration adapters — one-line protection for popular AI agent frameworks."""

from __future__ import annotations

from skillsecurity.integrations._registry import (
    install,
    installed_frameworks,
    uninstall,
    uninstall_all,
)

__all__ = [
    "install",
    "installed_frameworks",
    "uninstall",
    "uninstall_all",
]
