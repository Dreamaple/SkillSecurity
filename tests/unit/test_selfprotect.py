"""Unit tests for self-protection guard."""

from __future__ import annotations

from skillsecurity.selfprotect.guard import SelfProtectionGuard


class TestSelfProtectionGuard:
    def test_block_write_to_protected(self, tmp_path):
        guard = SelfProtectionGuard()
        guard.add_protected_path(tmp_path)
        result = guard.check(str(tmp_path / "config.yaml"))
        assert result is not None
        assert result.action.value == "block"
        assert "protected" in result.reason.lower() or "self-protection" in result.reason.lower()

    def test_allow_non_protected(self, tmp_path):
        guard = SelfProtectionGuard()
        guard.add_protected_path(tmp_path / "protected")
        result = guard.check(str(tmp_path / "other" / "file.txt"))
        assert result is None

    def test_block_delete_protected(self, tmp_path):
        guard = SelfProtectionGuard()
        guard.add_protected_path(tmp_path)
        result = guard.check(str(tmp_path / "policy.yaml"))
        assert result is not None
        assert result.action.value == "block"

    def test_block_read_protected(self, tmp_path):
        """Guard blocks all access to protected paths, including reads."""
        guard = SelfProtectionGuard()
        guard.add_protected_path(tmp_path)
        result = guard.check(str(tmp_path / "policy.yaml"))
        assert result is not None
        assert result.action.value == "block"

    def test_block_shell_path_targeting_protected(self, tmp_path):
        """When path would target protected dir, check(path) blocks it."""
        guard = SelfProtectionGuard()
        guard.add_protected_path(tmp_path)
        target = tmp_path / "policy.yaml"
        result = guard.check(str(target))
        assert result is not None
        assert result.action.value == "block"

    def test_check_none_returns_none(self):
        guard = SelfProtectionGuard()
        result = guard.check(None)
        assert result is None
