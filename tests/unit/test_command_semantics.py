from __future__ import annotations

from skillsecurity.engine.command_semantics import CommandSemanticsGuard
from skillsecurity.models.tool_call import ToolCall, ToolType


class TestCommandSemanticsGuard:
    def test_redirection_to_sensitive_path_blocked(self) -> None:
        guard = CommandSemanticsGuard(enabled=True)
        call = ToolCall(
            tool_type=ToolType.SHELL,
            params={"command": "echo test > /etc/passwd"},
        )
        decision = guard.check(call)
        assert decision is not None
        assert decision.is_blocked
        assert decision.rule_matched is not None
        assert "redirection" in decision.rule_matched.id

    def test_attached_output_flag_to_sensitive_path_blocked(self) -> None:
        guard = CommandSemanticsGuard(enabled=True)
        call = ToolCall(
            tool_type=ToolType.SHELL,
            params={"command": "sort -o/etc/cron.d/payload sample.txt"},
        )
        decision = guard.check(call)
        assert decision is not None
        assert decision.is_blocked

    def test_safe_command_no_decision(self) -> None:
        guard = CommandSemanticsGuard(enabled=True)
        call = ToolCall(tool_type=ToolType.SHELL, params={"command": "echo hello"})
        assert guard.check(call) is None
