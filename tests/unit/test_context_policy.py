from __future__ import annotations

from skillsecurity.engine.context_policy import ContextPolicyGuard
from skillsecurity.models.tool_call import ToolCall, ToolType


class TestContextPolicyGuard:
    def test_role_denied_tool_blocked(self) -> None:
        guard = ContextPolicyGuard(
            enabled=True,
            role_permissions={"guest": ["file.read"]},
        )
        call = ToolCall.from_dict(
            {
                "tool": "shell",
                "command": "echo hi",
                "caller_role": "guest",
            }
        )
        decision = guard.check(call)
        assert decision is not None
        assert decision.is_blocked
        assert decision.rule_matched is not None
        assert decision.rule_matched.id == "context-policy:role:guest"

    def test_role_allowed_tool_passes(self) -> None:
        guard = ContextPolicyGuard(enabled=True, role_permissions={"admin": ["*"]})
        call = ToolCall.from_dict(
            {
                "tool": "file.read",
                "path": "/tmp/a.txt",
                "caller_role": "admin",
            }
        )
        assert guard.check(call) is None

    def test_scope_denied_tool_blocked(self) -> None:
        guard = ContextPolicyGuard(
            enabled=True,
            scope_permissions={"operator.write": ["file.read", "network.request"]},
        )
        call = ToolCall.from_dict(
            {
                "tool": "shell",
                "command": "echo hi",
                "caller_scopes": ["operator.write"],
            }
        )
        decision = guard.check(call)
        assert decision is not None
        assert decision.is_blocked
        assert decision.rule_matched is not None
        assert decision.rule_matched.id == "context-policy:scope-deny"

    def test_require_context_blocks_missing_context(self) -> None:
        guard = ContextPolicyGuard(enabled=True, require_context=True)
        call = ToolCall(tool_type=ToolType.FILE_READ, params={"path": "/tmp/x"})
        decision = guard.check(call)
        assert decision is not None
        assert decision.is_blocked
        assert decision.rule_matched is not None
        assert decision.rule_matched.id == "context-policy:missing-context"


class TestToolCallContextParsing:
    def test_parse_caller_scopes_from_string(self) -> None:
        call = ToolCall.from_dict(
            {
                "tool": "file.read",
                "path": "/tmp/a.txt",
                "caller_role": "operator",
                "caller_scopes": "operator.write,operator.audit",
            }
        )
        assert call.context.caller_role == "operator"
        assert call.context.caller_scopes == ("operator.write", "operator.audit")
