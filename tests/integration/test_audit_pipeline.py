"""Integration tests for audit pipeline."""

from __future__ import annotations

import json
import time

from skillsecurity import SkillGuard


class TestAuditPipeline:
    def test_check_creates_audit_log(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        guard = SkillGuard(
            config={
                "version": "1.0",
                "name": "test",
                "global": {"default_action": "allow"},
                "rules": [
                    {
                        "id": "r1",
                        "action": "block",
                        "tool_type": "shell",
                        "match": {"command_pattern": "^dangerous"},
                    }
                ],
                "audit": {"output": str(log_path)},
            }
        )
        guard.check({"tool": "shell", "command": "dangerous stuff"})
        guard.check({"tool": "shell", "command": "safe stuff"})
        time.sleep(1)
        guard.stop()
        assert log_path.exists()
        lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(lines) >= 2

    def test_log_entries_have_correct_structure(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        guard = SkillGuard(
            config={
                "version": "1.0",
                "name": "test",
                "global": {"default_action": "allow"},
                "rules": [
                    {
                        "id": "r1",
                        "action": "block",
                        "tool_type": "shell",
                        "match": {"command_pattern": "^rm"},
                    }
                ],
                "audit": {"output": str(log_path)},
            }
        )
        guard.check({"tool": "shell", "command": "rm -rf /"})
        time.sleep(1)
        guard.stop()
        lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(lines) >= 1
        entry = json.loads(lines[0])
        assert "timestamp" in entry
        assert "event_type" in entry
        assert "decision" in entry
        assert entry["decision"]["action"] == "block"

    def test_sensitive_data_redacted_in_logs(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        guard = SkillGuard(
            config={
                "version": "1.0",
                "name": "test",
                "global": {"default_action": "allow"},
                "rules": [],
                "audit": {"output": str(log_path)},
            }
        )
        guard.check(
            {
                "tool": "shell",
                "command": "curl -H 'Authorization: Bearer mysecrettoken' https://api.com",
            }
        )
        time.sleep(1)
        guard.stop()
        content = log_path.read_text(encoding="utf-8")
        assert "mysecrettoken" not in content

    def test_query_logs_by_action(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        guard = SkillGuard(
            config={
                "version": "1.0",
                "name": "test",
                "global": {"default_action": "allow"},
                "rules": [
                    {
                        "id": "r1",
                        "action": "block",
                        "tool_type": "shell",
                        "match": {"command_pattern": "^dangerous"},
                    }
                ],
                "audit": {"output": str(log_path)},
            }
        )
        guard.check({"tool": "shell", "command": "dangerous cmd"})
        guard.check({"tool": "shell", "command": "safe cmd"})
        guard.check({"tool": "shell", "command": "dangerous again"})
        time.sleep(1)
        guard.stop()
        from skillsecurity.audit.query import AuditQuery

        q = AuditQuery(log_path)
        blocked = q.query(action="block")
        assert len(blocked) >= 2
