"""Unit tests for config loader."""

from __future__ import annotations

import pytest

from skillsecurity.config.loader import load_and_validate_policy, validate_policy_file
from skillsecurity.engine.policy import PolicyLoadError


class TestConfigLoader:
    def test_load_and_validate_valid(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text("version: '1.0'\nname: test\nrules:\n  - id: r1\n    action: block\n")
        engine = load_and_validate_policy(policy)
        assert len(engine.rules) == 1

    def test_load_nonexistent_raises(self):
        with pytest.raises(PolicyLoadError):
            load_and_validate_policy("/nonexistent.yaml")

    def test_validate_valid_file(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text("version: '1.0'\nname: test\nrules:\n  - id: r1\n    action: block\n")
        warnings = validate_policy_file(policy)
        assert isinstance(warnings, list)

    def test_validate_missing_name_warns(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text("version: '1.0'\nrules:\n  - id: r1\n    action: block\n")
        warnings = validate_policy_file(policy)
        assert any("name" in w.lower() for w in warnings)

    def test_validate_empty_rules_warns(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text("version: '1.0'\nname: test\nrules: []\n")
        warnings = validate_policy_file(policy)
        assert any("empty" in w.lower() for w in warnings)

    def test_validate_nonexistent_raises(self):
        with pytest.raises(PolicyLoadError):
            validate_policy_file("/nonexistent.yaml")

    def test_validate_bad_yaml_raises(self, tmp_path):
        policy = tmp_path / "bad.yaml"
        policy.write_text("not: valid: yaml: [[[")
        with pytest.raises(PolicyLoadError, match="YAML syntax"):
            validate_policy_file(policy)

    def test_validate_not_a_dict_raises(self, tmp_path):
        policy = tmp_path / "list.yaml"
        policy.write_text("- item1\n- item2\n")
        with pytest.raises(PolicyLoadError, match="mapping"):
            validate_policy_file(policy)

    def test_validate_missing_version_raises(self, tmp_path):
        policy = tmp_path / "noversion.yaml"
        policy.write_text("name: test\nrules: []\n")
        with pytest.raises(PolicyLoadError, match="version"):
            validate_policy_file(policy)
