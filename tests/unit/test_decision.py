from __future__ import annotations

from skillsecurity.engine.decision import DecisionEngine
from skillsecurity.models.decision import Decision
from skillsecurity.models.rule import Action, Severity


class TestBlockDecision:
    def test_block_decision_from_rule(self, dangerous_shell_call, sample_block_rule):
        engine = DecisionEngine()
        decision = engine.make_decision(dangerous_shell_call, sample_block_rule)
        assert decision.is_blocked
        assert decision.action == Action.BLOCK
        assert decision.severity == Severity.CRITICAL

    def test_block_decision_has_suggestions(self, dangerous_shell_call, sample_block_rule):
        engine = DecisionEngine()
        decision = engine.make_decision(dangerous_shell_call, sample_block_rule)
        assert len(decision.suggestions) > 0
        assert "Use a precise file path instead" in decision.suggestions

    def test_block_decision_has_rule_ref(self, dangerous_shell_call, sample_block_rule):
        engine = DecisionEngine()
        decision = engine.make_decision(dangerous_shell_call, sample_block_rule)
        assert decision.rule_matched is not None
        assert decision.rule_matched.id == "block-recursive-delete"


class TestAllowDecision:
    def test_allow_decision_from_rule(self, safe_shell_call, sample_allow_rule):
        engine = DecisionEngine()
        decision = engine.make_decision(safe_shell_call, sample_allow_rule)
        assert decision.is_allowed
        assert decision.action == Action.ALLOW


class TestAskDecision:
    def test_ask_decision_from_rule(self, sudo_shell_call, sample_ask_rule):
        engine = DecisionEngine()
        decision = engine.make_decision(sudo_shell_call, sample_ask_rule)
        assert decision.needs_confirmation
        assert decision.action == Action.ASK
        assert decision.severity == Severity.HIGH


class TestDefaultDecision:
    def test_no_match_default_allow(self, safe_shell_call):
        engine = DecisionEngine(default_action="allow")
        decision = engine.make_decision(safe_shell_call, None)
        assert decision.is_allowed
        assert "No matching rule" in decision.reason

    def test_no_match_default_block(self, safe_shell_call):
        engine = DecisionEngine(default_action="block")
        decision = engine.make_decision(safe_shell_call, None)
        assert decision.is_blocked


class TestDecisionProperties:
    def test_decision_is_allowed(self):
        d = Decision(action=Action.ALLOW, reason="ok", severity=Severity.LOW)
        assert d.is_allowed
        assert not d.is_blocked
        assert not d.needs_confirmation

    def test_decision_is_blocked(self):
        d = Decision(action=Action.BLOCK, reason="no", severity=Severity.HIGH)
        assert d.is_blocked
        assert not d.is_allowed
        assert not d.needs_confirmation

    def test_decision_needs_confirmation(self):
        d = Decision(action=Action.ASK, reason="?", severity=Severity.MEDIUM)
        assert d.needs_confirmation
        assert not d.is_allowed
        assert not d.is_blocked


class TestDecisionSerialization:
    def test_to_dict(self, dangerous_shell_call, sample_block_rule):
        engine = DecisionEngine()
        decision = engine.make_decision(dangerous_shell_call, sample_block_rule)
        data = decision.to_dict()
        assert data["action"] == "block"
        assert data["severity"] == "critical"
        assert data["rule_matched"]["id"] == "block-recursive-delete"
        assert isinstance(data["suggestions"], list)
        assert isinstance(data["check_duration_ms"], float)

    def test_to_dict_no_rule(self, safe_shell_call):
        engine = DecisionEngine()
        decision = engine.make_decision(safe_shell_call, None)
        data = decision.to_dict()
        assert data["action"] == "allow"
        assert data["rule_matched"] is None
