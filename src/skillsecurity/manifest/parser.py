"""Skill manifest JSON parser with validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skillsecurity.manifest.namespace import NamespaceError, validate_skill_id
from skillsecurity.manifest.permissions import PermissionSpec, SkillManifest


class ManifestValidationError(Exception):
    """Raised when a Skill manifest is invalid."""


class ManifestParser:
    @staticmethod
    def parse_file(path: str | Path) -> SkillManifest:
        path = Path(path)
        if not path.exists():
            raise ManifestValidationError(f"Manifest file not found: {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise ManifestValidationError(f"Invalid JSON in manifest: {e}") from e
        return ManifestParser.parse_dict(data)

    @staticmethod
    def parse_dict(data: dict[str, Any]) -> SkillManifest:
        for field in ("skill_id", "version", "name"):
            if field not in data:
                raise ManifestValidationError(f"Missing required field: {field}")

        skill_id = data["skill_id"]
        try:
            validate_skill_id(skill_id)
        except NamespaceError as e:
            raise ManifestValidationError(f"Invalid skill_id: {e}") from e

        permissions: dict[str, PermissionSpec] = {}
        raw_perms = data.get("permissions", {})
        if isinstance(raw_perms, dict):
            for perm_name, spec_data in raw_perms.items():
                if isinstance(spec_data, dict):
                    permissions[perm_name] = PermissionSpec(
                        description=spec_data.get("description", ""),
                        domains=spec_data.get("domains", []),
                        paths=spec_data.get("paths", []),
                    )
                else:
                    permissions[perm_name] = PermissionSpec()

        return SkillManifest(
            skill_id=skill_id,
            version=data["version"],
            name=data["name"],
            author=data.get("author", ""),
            description=data.get("description", ""),
            permissions=permissions,
            deny_permissions=data.get("deny_permissions", []),
        )
