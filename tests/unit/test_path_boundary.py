from __future__ import annotations

from pathlib import Path

from skillsecurity.engine.path_boundary import PathBoundaryGuard
from skillsecurity.models.tool_call import ToolCall, ToolType


class TestPathBoundaryGuard:
    def test_outside_root_blocked(self, tmp_path: Path) -> None:
        allowed_root = tmp_path / "workspace"
        allowed_root.mkdir()
        outside = tmp_path / "outside.txt"

        guard = PathBoundaryGuard(enabled=True, allowed_roots=[allowed_root])
        call = ToolCall(tool_type=ToolType.FILE_READ, params={"path": str(outside)})
        decision = guard.check(call)

        assert decision is not None
        assert decision.is_blocked
        assert decision.rule_matched is not None
        assert decision.rule_matched.id == "path-boundary:outside-root"

    def test_inside_root_allowed(self, tmp_path: Path) -> None:
        allowed_root = tmp_path / "workspace"
        allowed_root.mkdir()
        inside = allowed_root / "safe.txt"

        guard = PathBoundaryGuard(enabled=True, allowed_roots=[allowed_root])
        call = ToolCall(tool_type=ToolType.FILE_READ, params={"path": str(inside)})
        decision = guard.check(call)

        assert decision is None

    def test_disabled_no_effect(self, tmp_path: Path) -> None:
        guard = PathBoundaryGuard(enabled=False, allowed_roots=[tmp_path])
        call = ToolCall(tool_type=ToolType.FILE_DELETE, params={"path": "/etc/passwd"})
        assert guard.check(call) is None
