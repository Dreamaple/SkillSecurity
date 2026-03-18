"""Normalized path boundary enforcement for file operations."""

from __future__ import annotations

from pathlib import Path

from skillsecurity.models.decision import Decision, RuleRef
from skillsecurity.models.rule import Action, Severity
from skillsecurity.models.tool_call import ToolCall, ToolType

_FILE_TOOLS = {ToolType.FILE_READ, ToolType.FILE_WRITE, ToolType.FILE_DELETE}


class PathBoundaryGuard:
    """Blocks file operations that resolve outside configured allowed roots."""

    def __init__(
        self,
        enabled: bool = False,
        allowed_roots: list[str | Path] | None = None,
    ) -> None:
        self._enabled = enabled
        self._roots: list[Path] = []
        for root in allowed_roots or []:
            try:
                resolved = Path(root).expanduser().resolve(strict=False)
            except OSError:
                continue
            self._roots.append(resolved)

    def check(self, tool_call: ToolCall) -> Decision | None:
        if not self._enabled:
            return None
        if tool_call.tool_type not in _FILE_TOOLS:
            return None
        raw_path = tool_call.params.get("path")
        if not raw_path:
            return None
        if not self._roots:
            return None

        normalized = self._normalize_path(str(raw_path))
        if normalized is None:
            return Decision(
                action=Action.BLOCK,
                reason=f"Invalid path for boundary enforcement: {raw_path}",
                severity=Severity.HIGH,
                rule_matched=RuleRef(id="path-boundary:invalid-path", description="Path boundary"),
                suggestions=["Use a valid filesystem path."],
            )

        if any(self._is_child_of(normalized, root) for root in self._roots):
            return None

        roots = ", ".join(str(r) for r in self._roots[:3])
        return Decision(
            action=Action.BLOCK,
            reason=(
                f"Normalized path '{normalized}' is outside allowed roots ({roots})"
            ),
            severity=Severity.HIGH,
            rule_matched=RuleRef(id="path-boundary:outside-root", description="Path boundary"),
            suggestions=[
                "Restrict file access to configured safe directories.",
                "Update path_boundary.allowed_roots if this path is expected.",
            ],
        )

    @staticmethod
    def _normalize_path(raw: str) -> Path | None:
        try:
            p = Path(raw).expanduser()
            if not p.is_absolute():
                p = (Path.cwd() / p).resolve(strict=False)
            else:
                p = p.resolve(strict=False)
            return p
        except OSError:
            return None

    @staticmethod
    def _is_child_of(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False
