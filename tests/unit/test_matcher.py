from __future__ import annotations

from unittest.mock import patch

from skillsecurity.engine.matcher import RuleMatcher
from skillsecurity.models.rule import Action, MatchCondition, RateLimit, Rule, Severity
from skillsecurity.models.tool_call import ToolCall, ToolType


class TestCommandPatternMatching:
    def test_match_command_pattern_blocks_dangerous(self, dangerous_shell_call, sample_block_rule):
        matcher = RuleMatcher([sample_block_rule])
        result = matcher.match(dangerous_shell_call)
        assert result is not None
        assert result.id == "block-recursive-delete"
        assert result.action == Action.BLOCK

    def test_match_command_pattern_no_match_returns_none(self, safe_shell_call, sample_block_rule):
        matcher = RuleMatcher([sample_block_rule])
        result = matcher.match(safe_shell_call)
        assert result is None

    def test_match_sudo_command(self, sudo_shell_call, sample_ask_rule):
        matcher = RuleMatcher([sample_ask_rule])
        result = matcher.match(sudo_shell_call)
        assert result is not None
        assert result.action == Action.ASK


class TestPathPatternMatching:
    def test_match_path_pattern_blocks_system_dir(self, file_write_system_call):
        rule = Rule(
            id="block-system-paths",
            action=Action.BLOCK,
            tool_type=["file.write", "file.delete"],
            match=MatchCondition(path_pattern=r"^(/etc|/System|/boot)"),
            severity=Severity.CRITICAL,
        )
        matcher = RuleMatcher([rule])
        result = matcher.match(file_write_system_call)
        assert result is not None
        assert result.id == "block-system-paths"

    def test_match_path_pattern_allows_safe_path(self, file_write_safe_call):
        rule = Rule(
            id="block-system-paths",
            action=Action.BLOCK,
            tool_type=["file.write", "file.delete"],
            match=MatchCondition(path_pattern=r"^(/etc|/System|/boot)"),
            severity=Severity.CRITICAL,
        )
        matcher = RuleMatcher([rule])
        result = matcher.match(file_write_safe_call)
        assert result is None


class TestUrlPatternMatching:
    def test_match_url_pattern(self):
        rule = Rule(
            id="block-evil-url",
            action=Action.BLOCK,
            tool_type="network.request",
            match=MatchCondition(url_pattern=r"evil\.com"),
            severity=Severity.HIGH,
        )
        call = ToolCall(
            tool_type=ToolType.NETWORK_REQUEST,
            params={"url": "https://evil.com/malware"},
        )
        matcher = RuleMatcher([rule])
        result = matcher.match(call)
        assert result is not None
        assert result.id == "block-evil-url"


class TestFirstMatchWins:
    def test_first_match_wins(self):
        allow_rule = Rule(
            id="allow-all-shell",
            action=Action.ALLOW,
            tool_type="shell",
            match=MatchCondition(command_pattern=r".*"),
        )
        block_rule = Rule(
            id="block-all-shell",
            action=Action.BLOCK,
            tool_type="shell",
            match=MatchCondition(command_pattern=r".*"),
        )
        call = ToolCall(tool_type=ToolType.SHELL, params={"command": "anything"})

        matcher = RuleMatcher([allow_rule, block_rule])
        result = matcher.match(call)
        assert result is not None
        assert result.id == "allow-all-shell"
        assert result.action == Action.ALLOW

    def test_no_match_returns_none(self):
        rule = Rule(
            id="block-specific",
            action=Action.BLOCK,
            tool_type="shell",
            match=MatchCondition(command_pattern=r"^very-specific-command$"),
        )
        call = ToolCall(tool_type=ToolType.SHELL, params={"command": "ls"})
        matcher = RuleMatcher([rule])
        assert matcher.match(call) is None


class TestToolTypeFiltering:
    def test_shell_rule_does_not_match_file_write(self):
        rule = Rule(
            id="shell-only",
            action=Action.BLOCK,
            tool_type="shell",
            match=MatchCondition(command_pattern=r".*"),
        )
        call = ToolCall(tool_type=ToolType.FILE_WRITE, params={"path": "/tmp/x"})
        matcher = RuleMatcher([rule])
        assert matcher.match(call) is None

    def test_tool_type_list_matching(self):
        rule = Rule(
            id="block-file-ops",
            action=Action.BLOCK,
            tool_type=["file.write", "file.delete"],
            match=MatchCondition(path_pattern=r"^/etc"),
        )
        call = ToolCall(tool_type=ToolType.FILE_WRITE, params={"path": "/etc/hosts"})
        matcher = RuleMatcher([rule])
        result = matcher.match(call)
        assert result is not None

    def test_no_tool_type_matches_all(self):
        rule = Rule(
            id="block-everything",
            action=Action.BLOCK,
            match=MatchCondition(command_pattern=r"dangerous"),
        )
        call = ToolCall(tool_type=ToolType.SHELL, params={"command": "dangerous cmd"})
        matcher = RuleMatcher([rule])
        assert matcher.match(call) is not None


class TestRateLimit:
    def test_rate_limit_blocks_after_exceeding(self):
        rule = Rule(
            id="rate-limited",
            action=Action.BLOCK,
            tool_type="shell",
            rate_limit=RateLimit(max_calls=2, window_seconds=60),
            severity=Severity.MEDIUM,
        )
        call = ToolCall(tool_type=ToolType.SHELL, params={"command": "echo hi"})
        matcher = RuleMatcher([rule])

        assert matcher.match(call) is None
        assert matcher.match(call) is None
        result = matcher.match(call)
        assert result is not None
        assert result.id == "rate-limited"


class TestOsFiltering:
    @patch("skillsecurity.engine.matcher.platform.system", return_value="Linux")
    def test_unix_rule_matches_on_linux(self, _mock):
        rule = Rule(
            id="unix-only",
            action=Action.BLOCK,
            os="unix",
            tool_type="shell",
            match=MatchCondition(command_pattern=r"rm\s"),
        )
        call = ToolCall(tool_type=ToolType.SHELL, params={"command": "rm file"})
        matcher = RuleMatcher([rule])
        assert matcher.match(call) is not None

    @patch("skillsecurity.engine.matcher.platform.system", return_value="Windows")
    def test_unix_rule_skipped_on_windows(self, _mock):
        rule = Rule(
            id="unix-only",
            action=Action.BLOCK,
            os="unix",
            tool_type="shell",
            match=MatchCondition(command_pattern=r"rm\s"),
        )
        call = ToolCall(tool_type=ToolType.SHELL, params={"command": "rm file"})
        matcher = RuleMatcher([rule])
        assert matcher.match(call) is None

    @patch("skillsecurity.engine.matcher.platform.system", return_value="Windows")
    def test_windows_rule_matches_on_windows(self, _mock):
        rule = Rule(
            id="win-only",
            action=Action.BLOCK,
            os="windows",
            tool_type="shell",
            match=MatchCondition(command_pattern=r"del\s"),
        )
        call = ToolCall(tool_type=ToolType.SHELL, params={"command": "del /s file"})
        matcher = RuleMatcher([rule])
        assert matcher.match(call) is not None
