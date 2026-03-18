"""CLI tests for approval queue commands."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from skillsecurity import SkillGuard
from skillsecurity.approval import reset_shared_approval_service
from skillsecurity.cli.main import cli


@pytest.fixture(autouse=True)
def _reset_approval_state() -> None:
    reset_shared_approval_service()


def _seed_pending_ticket() -> str:
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
            },
        }
    )
    tool_call = {"tool": "shell", "command": "echo approval", "session_id": "sess-cli"}
    decision = guard.check(tool_call)
    ticket = guard.create_approval_ticket(tool_call, decision, source="test-cli")
    return str(ticket["ticket_id"])


class TestApprovalCommands:
    def test_list_pending(self) -> None:
        ticket_id = _seed_pending_ticket()
        runner = CliRunner()
        result = runner.invoke(cli, ["approval", "list"])
        assert result.exit_code == 0
        assert ticket_id[:12] in result.output

    def test_approve_and_revoke_remembered(self) -> None:
        ticket_id = _seed_pending_ticket()
        runner = CliRunner()

        approve = runner.invoke(
            cli,
            ["--format", "json", "approval", "approve", ticket_id, "--scope", "session", "--approver", "alice"],
        )
        assert approve.exit_code == 0
        approved = json.loads(approve.output)
        assert approved["status"] == "approved"

        remembered = runner.invoke(cli, ["--format", "json", "approval", "list", "--remembered"])
        assert remembered.exit_code == 0
        remembered_items = json.loads(remembered.output)
        assert remembered_items
        remember_id = remembered_items[0]["remember_id"]

        revoke = runner.invoke(cli, ["approval", "revoke", remember_id])
        assert revoke.exit_code == 0
        assert "Revoked remembered entry" in revoke.output

    def test_deny_missing_ticket_returns_2(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["approval", "deny", "missing-ticket-id"])
        assert result.exit_code == 2

    def test_list_via_api_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Resp:
            def __init__(self, payload: list[dict]) -> None:
                self._payload = payload

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps(self._payload).encode("utf-8")

        monkeypatch.setattr(
            "skillsecurity.cli.main.urlopen",
            lambda req, timeout=10: _Resp([{"ticket_id": "appr-api-1", "reason": "from api"}]),
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["--format", "json", "approval", "--api-url", "http://127.0.0.1:9099", "list"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data[0]["ticket_id"] == "appr-api-1"
