from __future__ import annotations

import pytest

from skillsecurity.engine.policy import PolicyEngine, PolicyLoadError
from skillsecurity.models.rule import Action, Severity
from skillsecurity.models.tool_call import ToolCall, ToolType


class TestPolicyLoading:
    def test_load_yaml_policy_file(self, tmp_policy_file):
        engine = PolicyEngine()
        engine.load_file(tmp_policy_file)
        assert len(engine.rules) == 3

    def test_load_builtin_default(self, policies_dir):
        engine = PolicyEngine()
        engine.load_builtin("default")
        assert len(engine.rules) > 0

    def test_rules_have_correct_types(self, tmp_policy_file):
        engine = PolicyEngine()
        engine.load_file(tmp_policy_file)
        for rule in engine.rules:
            assert isinstance(rule.action, Action)
            assert isinstance(rule.severity, Severity)

    def test_global_config_loaded(self, tmp_policy_file):
        engine = PolicyEngine()
        engine.load_file(tmp_policy_file)
        assert engine.global_config.default_action == "allow"
        assert engine.global_config.fail_behavior == "block"

    def test_load_nonexistent_file_raises(self):
        engine = PolicyEngine()
        with pytest.raises(PolicyLoadError):
            engine.load_file("/nonexistent/path/policy.yaml")


class TestPolicyEvaluation:
    def test_evaluate_first_match_wins(self, tmp_policy_file):
        engine = PolicyEngine()
        engine.load_file(tmp_policy_file)

        call = ToolCall(
            tool_type=ToolType.SHELL,
            params={"command": "rm -rf /tmp/data"},
        )
        matched = engine.evaluate(call)
        assert matched is not None
        assert matched.id == "block-recursive-delete"
        assert matched.action == Action.BLOCK

    def test_evaluate_no_match_returns_none(self, tmp_policy_file):
        engine = PolicyEngine()
        engine.load_file(tmp_policy_file)

        call = ToolCall(
            tool_type=ToolType.SHELL,
            params={"command": "echo hello"},
        )
        matched = engine.evaluate(call)
        assert matched is None

    def test_evaluate_ask_rule(self, tmp_policy_file):
        engine = PolicyEngine()
        engine.load_file(tmp_policy_file)

        call = ToolCall(
            tool_type=ToolType.SHELL,
            params={"command": "sudo apt install nginx"},
        )
        matched = engine.evaluate(call)
        assert matched is not None
        assert matched.action == Action.ASK

    def test_evaluate_path_rule(self, tmp_policy_file):
        engine = PolicyEngine()
        engine.load_file(tmp_policy_file)

        call = ToolCall(
            tool_type=ToolType.FILE_WRITE,
            params={"path": "/etc/hosts"},
        )
        matched = engine.evaluate(call)
        assert matched is not None
        assert matched.action == Action.BLOCK


class TestConfigValidation:
    """T021: Config loader validation tests for US2."""

    def test_yaml_syntax_error_reports_location(self, tmp_path):
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("version: '1.0'\nrules:\n  - id: 'test'\n    action: block\n  bad_indent")
        engine = PolicyEngine()
        with pytest.raises(PolicyLoadError, match="YAML syntax error"):
            engine.load_file(bad_yaml)

    def test_duplicate_rule_id_raises(self, tmp_path):
        policy = tmp_path / "dup.yaml"
        policy.write_text(
            "version: '1.0'\nname: test\nrules:\n"
            "  - id: same-id\n    action: block\n"
            "  - id: same-id\n    action: allow\n"
        )
        engine = PolicyEngine()
        with pytest.raises(PolicyLoadError, match="Duplicate rule ID"):
            engine.load_file(policy)

    def test_invalid_action_raises(self, tmp_path):
        policy = tmp_path / "badaction.yaml"
        policy.write_text(
            "version: '1.0'\nname: test\nrules:\n"
            "  - id: r1\n    action: deny\n"
        )
        engine = PolicyEngine()
        with pytest.raises(PolicyLoadError, match="Invalid action"):
            engine.load_file(policy)

    def test_missing_rule_id_raises(self, tmp_path):
        policy = tmp_path / "noid.yaml"
        policy.write_text(
            "version: '1.0'\nname: test\nrules:\n"
            "  - action: block\n"
        )
        engine = PolicyEngine()
        with pytest.raises(PolicyLoadError, match="missing required 'id'"):
            engine.load_file(policy)

    def test_negative_rate_limit_raises(self, tmp_path):
        policy = tmp_path / "badrate.yaml"
        policy.write_text(
            "version: '1.0'\nname: test\nrules:\n"
            "  - id: r1\n    action: block\n    rate_limit:\n      max_calls: -1\n      window_seconds: 60\n"
        )
        engine = PolicyEngine()
        with pytest.raises(PolicyLoadError, match="must be positive"):
            engine.load_file(policy)

    def test_empty_rules_uses_default_action(self, tmp_path):
        policy = tmp_path / "empty.yaml"
        policy.write_text("version: '1.0'\nname: test\nglobal:\n  default_action: block\nrules: []\n")
        engine = PolicyEngine()
        engine.load_file(policy)
        assert len(engine.rules) == 0
        assert engine.global_config.default_action == "block"
