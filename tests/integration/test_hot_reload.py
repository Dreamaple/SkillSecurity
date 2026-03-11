"""Integration tests for policy hot-reload."""

from __future__ import annotations

import time

import yaml

from skillsecurity.config.watcher import PolicyWatcher
from skillsecurity.engine.policy import PolicyEngine


class TestPolicyHotReload:
    def test_watcher_detects_file_change(self, tmp_path):
        policy_file = tmp_path / "policy.yaml"
        policy_data = {
            "version": "1.0",
            "name": "watch-test",
            "global": {"default_action": "allow"},
            "rules": [
                {
                    "id": "r1",
                    "action": "block",
                    "tool_type": "shell",
                    "match": {"command_pattern": "^dangerous"},
                }
            ],
        }
        policy_file.write_text(yaml.dump(policy_data))

        engine = PolicyEngine()
        engine.load_file(policy_file)
        assert len(engine.rules) == 1

        watcher = PolicyWatcher(engine, policy_file)
        watcher.start()

        try:
            policy_data["rules"].append(
                {
                    "id": "r2",
                    "action": "ask",
                    "tool_type": "shell",
                    "match": {"command_pattern": "^risky"},
                }
            )
            time.sleep(0.5)
            policy_file.write_text(yaml.dump(policy_data))
            time.sleep(3)

            assert len(engine.rules) == 2
        finally:
            watcher.stop()

    def test_watcher_retains_old_policy_on_bad_update(self, tmp_path):
        policy_file = tmp_path / "policy.yaml"
        policy_data = {
            "version": "1.0",
            "name": "watch-test",
            "global": {"default_action": "allow"},
            "rules": [
                {
                    "id": "r1",
                    "action": "block",
                    "tool_type": "shell",
                    "match": {"command_pattern": "^dangerous"},
                }
            ],
        }
        policy_file.write_text(yaml.dump(policy_data))

        engine = PolicyEngine()
        engine.load_file(policy_file)
        original_count = len(engine.rules)

        watcher = PolicyWatcher(engine, policy_file)
        watcher.start()

        try:
            time.sleep(0.5)
            policy_file.write_text("invalid: yaml: content: [[[")
            time.sleep(3)

            assert len(engine.rules) == original_count
        finally:
            watcher.stop()
