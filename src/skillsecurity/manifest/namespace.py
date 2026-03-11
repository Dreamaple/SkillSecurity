"""Namespace validation for Skill IDs."""

from __future__ import annotations

import re


class NamespaceError(Exception):
    """Raised when a Skill ID fails namespace validation."""


_AUTHOR_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,49}$")
_SKILL_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,99}$")


def validate_skill_id(skill_id: str) -> bool:
    if "/" not in skill_id:
        raise NamespaceError(
            f"Skill ID '{skill_id}' must contain '/' separator (format: author/skill-name)"
        )
    if skill_id != skill_id.lower():
        raise NamespaceError(f"Skill ID '{skill_id}' must be lowercase")

    parts = skill_id.split("/", 1)
    author, name = parts[0], parts[1]

    if not _AUTHOR_PATTERN.match(author):
        if len(author) < 3:
            raise NamespaceError(f"Skill ID author '{author}' must be at least 3 characters")
        if len(author) > 50:
            raise NamespaceError(f"Skill ID author '{author}' exceeds 50 character limit")
        raise NamespaceError(
            f"Skill ID author '{author}' contains invalid characters (allowed: a-z, 0-9, -)"
        )

    if not _SKILL_NAME_PATTERN.match(name):
        if len(name) < 3:
            raise NamespaceError(f"Skill ID skill name '{name}' must be at least 3 characters")
        if len(name) > 100:
            raise NamespaceError(f"Skill ID skill name '{name}' exceeds 100 character limit")
        raise NamespaceError(
            f"Skill ID skill name '{name}' contains invalid characters (allowed: a-z, 0-9, -)"
        )

    return True
