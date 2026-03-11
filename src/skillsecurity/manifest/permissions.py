"""Permission types and constraint matching."""

from __future__ import annotations

import enum
import fnmatch
from dataclasses import dataclass, field


class PermissionType(enum.StrEnum):
    FILE_READ = "file.read"
    FILE_WRITE = "file.write"
    FILE_DELETE = "file.delete"
    SHELL = "shell"
    NETWORK_READ = "network.read"
    NETWORK_WRITE = "network.write"
    MESSAGE_SEND = "message.send"
    BROWSER = "browser"
    DATABASE_READ = "database.read"
    DATABASE_WRITE = "database.write"
    ENV_READ = "env.read"


TOOL_TYPE_TO_PERMISSION: dict[str, str] = {
    "file.read": "file.read",
    "file.write": "file.write",
    "file.delete": "file.delete",
    "shell": "shell",
    "network.request": "network.read",
    "message.send": "message.send",
    "browser": "browser",
    "database": "database.read",
}


@dataclass
class PermissionSpec:
    description: str = ""
    domains: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)

    def check_domain(self, domain: str) -> bool:
        if not self.domains:
            return True
        return any(fnmatch.fnmatch(domain.lower(), d.lower()) for d in self.domains)

    def check_path(self, path: str) -> bool:
        if not self.paths:
            return True
        return any(fnmatch.fnmatch(path, p) for p in self.paths)


@dataclass
class SkillManifest:
    skill_id: str
    version: str
    name: str
    author: str = ""
    description: str = ""
    permissions: dict[str, PermissionSpec] = field(default_factory=dict)
    deny_permissions: list[str] = field(default_factory=list)

    def has_permission(self, perm_type: str) -> bool:
        return perm_type in self.permissions

    def check_operation(
        self, perm_type: str, domain: str | None = None, path: str | None = None
    ) -> tuple[bool, str]:
        if perm_type in self.deny_permissions:
            return False, f"Skill has explicitly denied '{perm_type}' permission"
        if perm_type not in self.permissions:
            return False, f"Skill has not declared '{perm_type}' permission"
        spec = self.permissions[perm_type]
        if domain and not spec.check_domain(domain):
            return False, f"Domain '{domain}' not in scope for '{perm_type}'"
        if path and not spec.check_path(path):
            return False, f"Path '{path}' not in scope for '{perm_type}'"
        return True, "Permission granted"
