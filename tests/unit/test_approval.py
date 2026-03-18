from __future__ import annotations

import pytest

from skillsecurity import SkillGuard
from skillsecurity.approval.service import ApprovalService, reset_shared_approval_service
from skillsecurity.engine.decision import DecisionEngine
from skillsecurity.models.tool_call import ToolCall, ToolType


@pytest.fixture(autouse=True)
def _reset_shared_approval_state() -> None:
    reset_shared_approval_service()


class TestApprovalService:
    def test_create_ticket_from_ask_decision(self, sample_ask_rule) -> None:
        engine = DecisionEngine()
        call = ToolCall(tool_type=ToolType.SHELL, params={"command": "sudo whoami"})
        decision = engine.make_decision(call, sample_ask_rule)
        service = ApprovalService(default_timeout_seconds=30)

        ticket = service.create_ticket(call, decision, source="unit-test")
        assert ticket.ticket_id.startswith("appr-")
        assert ticket.status.value == "pending"
        assert ticket.decision_type == "hard_ask"
        assert ticket.source == "unit-test"
        assert ticket.to_dict()["tool_call"]["tool"] == "shell"

    def test_resolve_ticket(self, sample_ask_rule) -> None:
        engine = DecisionEngine()
        call = ToolCall(tool_type=ToolType.SHELL, params={"command": "sudo whoami"})
        decision = engine.make_decision(call, sample_ask_rule)
        service = ApprovalService(default_timeout_seconds=30)

        ticket = service.create_ticket(call, decision)
        resolved = service.resolve_ticket(
            ticket.ticket_id, allow=True, approver="alice", scope="session"
        )

        assert resolved is not None
        assert resolved.status.value == "approved"
        assert resolved.resolution == "allow"
        assert resolved.approver == "alice"
        assert resolved.scope == "session"
        assert service.list_pending() == []

    def test_remembered_decision_match(self, sample_ask_rule) -> None:
        engine = DecisionEngine()
        call = ToolCall.from_dict(
            {"tool": "shell", "command": "sudo whoami", "session_id": "sess-1"}
        )
        decision = engine.make_decision(call, sample_ask_rule)
        service = ApprovalService(default_timeout_seconds=30, remember_enabled=True)

        ticket = service.create_ticket(call, decision)
        service.resolve_ticket(ticket.ticket_id, allow=True, scope="session")

        matched = service.match_remembered(
            {"tool": "shell", "command": "sudo whoami", "session_id": "sess-2"},
            rule_id=decision.rule_matched.id if decision.rule_matched else None,
        )
        assert matched is None

        matched_session = service.match_remembered(
            {"tool": "shell", "command": "sudo whoami", "session_id": "sess-1"},
            rule_id=decision.rule_matched.id if decision.rule_matched else None,
        )
        assert matched_session == "allow"


class TestSkillGuardApproval:
    def test_guard_creates_and_resolves_approval_ticket(self) -> None:
        guard = SkillGuard(policy="openclaw-hardened")
        tool_call = {"tool": "shell", "command": "python -V"}
        decision = guard.check(tool_call)
        assert decision.needs_confirmation

        created = guard.create_approval_ticket(tool_call, decision, source="unit-test")
        assert created["status"] == "pending"
        assert created["ticket_id"]

        pending = guard.list_pending_approvals()
        assert len(pending) == 1
        assert pending[0]["ticket_id"] == created["ticket_id"]

        resolved = guard.resolve_approval_ticket(
            created["ticket_id"], allow=False, approver="security-admin"
        )
        assert resolved is not None
        assert resolved["status"] == "denied"
        assert resolved["approver"] == "security-admin"

    def test_guard_skip_ticket_for_non_ask(self) -> None:
        guard = SkillGuard()
        tool_call = {"tool": "shell", "command": "echo hello"}
        decision = guard.check(tool_call)
        assert decision.is_allowed
        assert guard.create_approval_ticket(tool_call, decision) == {}

    def test_guard_applies_remembered_allow(self) -> None:
        guard = SkillGuard(
            config={
                "global": {"default_action": "allow", "fail_behavior": "block"},
                "rules": [
                    {
                        "id": "ask-shell",
                        "tool_type": "shell",
                        "action": "ask",
                        "severity": "high",
                        "message": "Confirm shell command",
                    }
                ],
                "ask": {
                    "remember": {
                        "enabled": True,
                        "scope": "session",
                        "expiry_hours": 24,
                    }
                }
            },
        )
        tool_call = {"tool": "shell", "command": "echo hello", "session_id": "sess-1"}
        first = guard.check(tool_call)
        assert first.needs_confirmation
        ticket = guard.create_approval_ticket(tool_call, first, source="unit-test")
        guard.resolve_approval_ticket(ticket["ticket_id"], allow=True, scope="session")

        second = guard.check(tool_call)
        assert second.is_allowed
        assert second.rule_matched is not None
        assert second.rule_matched.id == "approval-memory:allow"

    def test_guard_soft_confirmation_converts_allow_to_ask(self) -> None:
        guard = SkillGuard(
            config={
                "rules": [],
                "ask": {
                    "soft_confirmation": {
                        "enabled": True,
                        "tool_types": ["shell"],
                        "severity": "medium",
                    }
                },
            }
        )
        result = guard.check({"tool": "shell", "command": "echo hello"})
        assert result.needs_confirmation
        assert result.rule_matched is not None
        assert result.rule_matched.id == "soft-ask:shell"
