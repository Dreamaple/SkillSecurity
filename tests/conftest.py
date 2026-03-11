from __future__ import annotations

from pathlib import Path

import pytest

from skillsecurity.models.rule import Action, MatchCondition, Rule, Severity
from skillsecurity.models.tool_call import ToolCall, ToolType


@pytest.fixture
def dangerous_shell_call() -> ToolCall:
    return ToolCall(
        tool_type=ToolType.SHELL,
        params={"command": "rm -rf /"},
    )


@pytest.fixture
def safe_shell_call() -> ToolCall:
    return ToolCall(
        tool_type=ToolType.SHELL,
        params={"command": "ls /tmp"},
    )


@pytest.fixture
def sudo_shell_call() -> ToolCall:
    return ToolCall(
        tool_type=ToolType.SHELL,
        params={"command": "sudo apt install nginx"},
    )


@pytest.fixture
def file_write_system_call() -> ToolCall:
    return ToolCall(
        tool_type=ToolType.FILE_WRITE,
        params={"path": "/etc/passwd"},
    )


@pytest.fixture
def file_write_safe_call() -> ToolCall:
    return ToolCall(
        tool_type=ToolType.FILE_WRITE,
        params={"path": "/home/user/project/data.txt"},
    )


@pytest.fixture
def sample_block_rule() -> Rule:
    return Rule(
        id="block-recursive-delete",
        action=Action.BLOCK,
        tool_type="shell",
        match=MatchCondition(command_pattern=r"rm\s+.*-[a-zA-Z]*r"),
        severity=Severity.CRITICAL,
        message="Recursive deletion detected",
        suggestions=["Use a precise file path instead"],
    )


@pytest.fixture
def sample_allow_rule() -> Rule:
    return Rule(
        id="allow-ls",
        action=Action.ALLOW,
        tool_type="shell",
        match=MatchCondition(command_pattern=r"^ls\s"),
    )


@pytest.fixture
def sample_ask_rule() -> Rule:
    return Rule(
        id="ask-sudo",
        action=Action.ASK,
        tool_type="shell",
        match=MatchCondition(command_pattern=r"^sudo\s"),
        severity=Severity.HIGH,
        message="Privilege escalation operation",
    )


@pytest.fixture
def sample_policy_yaml() -> str:
    return """\
version: "1.0"
name: "test-policy"
description: "Test policy for unit tests"

global:
  default_action: allow
  fail_behavior: block

rules:
  - id: "block-recursive-delete"
    tool_type: shell
    match:
      command_pattern: "rm\\\\s+.*-[a-zA-Z]*r"
    action: block
    severity: critical
    message: "Recursive deletion detected"
    suggestions:
      - "Use a precise file path instead"

  - id: "ask-sudo"
    tool_type: shell
    match:
      command_pattern: "^sudo\\\\s"
    action: ask
    severity: high
    message: "Privilege escalation operation"

  - id: "block-system-paths"
    tool_type:
      - file.write
      - file.delete
    match:
      path_pattern: "^(/etc|/System|/boot)"
    action: block
    severity: critical
    message: "System directory modification blocked"
"""


@pytest.fixture
def tmp_policy_file(sample_policy_yaml: str, tmp_path: Path) -> Path:
    policy_file = tmp_path / "test-policy.yaml"
    policy_file.write_text(sample_policy_yaml)
    return policy_file


@pytest.fixture
def policies_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "policies"
