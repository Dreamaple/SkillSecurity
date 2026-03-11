"""Shared utilities for framework adapters."""

from __future__ import annotations

from typing import Any


def _get_or_create_guard(**kwargs: Any) -> Any:
    """Return the user-supplied guard or create a default one."""
    guard = kwargs.get("guard")
    if guard is not None:
        return guard
    from skillsecurity import SkillGuard

    init_kwargs: dict[str, Any] = {}
    if "policy_file" in kwargs:
        init_kwargs["policy_file"] = kwargs["policy_file"]
    if "policy" in kwargs:
        init_kwargs["policy"] = kwargs["policy"]
    if "config" in kwargs:
        init_kwargs["config"] = kwargs["config"]
    return SkillGuard(**init_kwargs)
