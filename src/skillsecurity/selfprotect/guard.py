from __future__ import annotations

from pathlib import Path

from skillsecurity.models.decision import Decision, RuleRef
from skillsecurity.models.rule import Action, Severity


class SelfProtectionGuard:
    """Unconditionally blocks Agent tool calls targeting SkillSecurity's own files.

    This check runs BEFORE any policy evaluation and cannot be overridden by rules.
    """

    def __init__(self, protected_paths: set[Path] | None = None) -> None:
        self._protected: set[Path] = set()
        if protected_paths:
            for p in protected_paths:
                self._protected.add(Path(p).resolve())

    def add_protected_path(self, path: str | Path) -> None:
        self._protected.add(Path(path).resolve())

    def check(self, target_path: str | None) -> Decision | None:
        """Return a Block decision if the target path is protected, else None."""
        if not target_path:
            return None

        resolved = Path(target_path).resolve()
        for protected in self._protected:
            if resolved == protected or self._is_child_of(resolved, protected):
                return Decision(
                    action=Action.BLOCK,
                    reason=f"Operation targets a protected SkillSecurity path: {protected}",
                    severity=Severity.CRITICAL,
                    rule_matched=RuleRef(
                        id="self-protection",
                        description="Immutable self-protection rule",
                    ),
                    suggestions=[
                        "SkillSecurity configuration files cannot be modified by Agent tool calls",
                        "Modify these files manually if needed",
                    ],
                )
        return None

    @staticmethod
    def _is_child_of(child: Path, parent: Path) -> bool:
        try:
            child.relative_to(parent)
            return True
        except ValueError:
            return False
