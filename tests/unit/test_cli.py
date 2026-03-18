"""Unit tests for CLI commands and formatter."""

from __future__ import annotations

import json

from click.testing import CliRunner

from skillsecurity.cli.formatter import DecisionFormatter
from skillsecurity.cli.main import cli
from skillsecurity.models.decision import Decision
from skillsecurity.models.rule import Action, Severity


class TestCheckCommand:
    def test_check_blocks_dangerous(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--tool", "shell", "--command", "rm -rf /"])
        assert result.exit_code == 1

    def test_check_allows_safe(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--tool", "shell", "--command", "echo hello"])
        assert result.exit_code == 0

    def test_check_json_format(self):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["--format", "json", "check", "--tool", "shell", "--command", "rm -rf /"]
        )
        data = json.loads(result.output)
        assert data["action"] == "block"

    def test_check_requires_tool_or_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["check"])
        assert result.exit_code != 0

    def test_check_json_input(self):
        runner = CliRunner()
        input_data = json.dumps({"tool": "shell", "command": "echo hello"})
        result = runner.invoke(cli, ["check", "--json-input"], input=input_data)
        assert result.exit_code == 0

    def test_check_with_path(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--tool", "file.write", "--path", "/etc/hosts"])
        assert result.exit_code == 1

    def test_check_with_policy(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text(
            "version: '1.0'\nname: test\nglobal:\n  default_action: block\nrules: []\n"
        )
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["--policy", str(policy), "check", "--tool", "shell", "--command", "echo hi"],
        )
        assert result.exit_code == 1

    def test_check_no_color(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["--no-color", "--no-emoji", "check", "--tool", "shell", "--command", "rm -rf /"],
        )
        assert result.exit_code == 1


class TestInitCommand:
    def test_init_creates_file(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "test-policy.yaml"
        result = runner.invoke(cli, ["init", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_init_strict_template(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "strict.yaml"
        result = runner.invoke(cli, ["init", "--template", "strict", "--output", str(out)])
        assert result.exit_code == 0
        assert "strict" in out.read_text(encoding="utf-8")

    def test_init_openclaw_hardened_template(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "openclaw-hardened.yaml"
        result = runner.invoke(
            cli, ["init", "--template", "openclaw-hardened", "--output", str(out)]
        )
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert "openclaw-hardened" in text
        assert "default_action: block" in text

    def test_init_refuses_overwrite(self, tmp_path):
        out = tmp_path / "exists.yaml"
        out.write_text("existing")
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--output", str(out)])
        assert result.exit_code != 0


class TestValidateCommand:
    def test_validate_valid_file(self, tmp_path):
        policy = tmp_path / "valid.yaml"
        policy.write_text("version: '1.0'\nname: test\nrules:\n  - id: r1\n    action: block\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", str(policy)])
        assert "valid" in result.output.lower()

    def test_validate_invalid_file(self, tmp_path):
        policy = tmp_path / "invalid.yaml"
        policy.write_text("not: valid: yaml: [[[")
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", str(policy)])
        assert result.exit_code != 0


class TestDecisionFormatter:
    def test_format_human_block(self):
        decision = Decision(
            action=Action.BLOCK,
            reason="Dangerous",
            severity=Severity.CRITICAL,
        )
        formatter = DecisionFormatter(use_color=False, use_emoji=False)
        output = formatter.format_human(decision)
        assert "BLOCK" in output
        assert "Dangerous" in output

    def test_format_human_with_tool_call(self):
        decision = Decision(
            action=Action.BLOCK,
            reason="Blocked",
            severity=Severity.HIGH,
            suggestions=["Use safer command"],
        )
        formatter = DecisionFormatter(use_color=True, use_emoji=True)
        output = formatter.format_human(
            decision, tool_call={"tool": "shell", "command": "rm -rf /"}
        )
        assert "shell" in output
        assert "rm -rf /" in output
        assert "Use safer command" in output

    def test_format_json(self):
        decision = Decision(
            action=Action.ALLOW,
            reason="OK",
            severity=Severity.LOW,
        )
        formatter = DecisionFormatter()
        output = formatter.format_json(decision)
        data = json.loads(output)
        assert data["action"] == "allow"

    def test_format_allow(self):
        decision = Decision(action=Action.ALLOW, reason="OK", severity=Severity.LOW)
        formatter = DecisionFormatter(use_color=False, use_emoji=False)
        output = formatter.format_human(decision)
        assert "ALLOW" in output

    def test_format_ask(self):
        decision = Decision(action=Action.ASK, reason="Confirm?", severity=Severity.MEDIUM)
        formatter = DecisionFormatter(use_color=False, use_emoji=False)
        output = formatter.format_human(decision)
        assert "ASK" in output
