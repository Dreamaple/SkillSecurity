"""Skill manifest parsing and permission checking."""

from __future__ import annotations

from skillsecurity.manifest.namespace import NamespaceError, validate_skill_id
from skillsecurity.manifest.parser import ManifestParser, ManifestValidationError
from skillsecurity.manifest.permissions import PermissionSpec, PermissionType, SkillManifest

__all__ = [
    "ManifestParser",
    "ManifestValidationError",
    "NamespaceError",
    "PermissionSpec",
    "PermissionType",
    "SkillManifest",
    "validate_skill_id",
]
