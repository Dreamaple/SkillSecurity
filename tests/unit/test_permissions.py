"""Unit tests for permission types and constraint matching."""

from __future__ import annotations

from skillsecurity.manifest.permissions import PermissionSpec, PermissionType, SkillManifest


class TestPermissionSpec:
    def test_empty_domains_allows_all(self):
        spec = PermissionSpec()
        assert spec.check_domain("any.example.com") is True

    def test_domain_match(self):
        spec = PermissionSpec(domains=["api.example.com"])
        assert spec.check_domain("api.example.com") is True
        assert spec.check_domain("evil.com") is False

    def test_domain_glob(self):
        spec = PermissionSpec(domains=["*.example.com"])
        assert spec.check_domain("api.example.com") is True
        assert spec.check_domain("evil.com") is False

    def test_empty_paths_allows_all(self):
        spec = PermissionSpec()
        assert spec.check_path("/any/path") is True

    def test_path_match(self):
        spec = PermissionSpec(paths=["/home/user/*"])
        assert spec.check_path("/home/user/doc.txt") is True
        assert spec.check_path("/etc/hosts") is False


class TestSkillManifest:
    def test_has_permission(self):
        manifest = SkillManifest(
            skill_id="acme/test",
            version="1.0",
            name="Test",
            permissions={"network.read": PermissionSpec()},
        )
        assert manifest.has_permission("network.read") is True
        assert manifest.has_permission("shell") is False

    def test_check_operation_allowed(self):
        manifest = SkillManifest(
            skill_id="acme/test",
            version="1.0",
            name="Test",
            permissions={"network.read": PermissionSpec(domains=["api.example.com"])},
        )
        allowed, _ = manifest.check_operation("network.read", domain="api.example.com")
        assert allowed is True

    def test_check_operation_denied_perm(self):
        manifest = SkillManifest(
            skill_id="acme/test",
            version="1.0",
            name="Test",
            permissions={},
            deny_permissions=["shell"],
        )
        allowed, reason = manifest.check_operation("shell")
        assert allowed is False
        assert "denied" in reason.lower()

    def test_check_operation_undeclared(self):
        manifest = SkillManifest(
            skill_id="acme/test",
            version="1.0",
            name="Test",
            permissions={"network.read": PermissionSpec()},
        )
        allowed, reason = manifest.check_operation("file.write")
        assert allowed is False
        assert "not declared" in reason.lower()

    def test_check_operation_wrong_domain(self):
        manifest = SkillManifest(
            skill_id="acme/test",
            version="1.0",
            name="Test",
            permissions={"network.read": PermissionSpec(domains=["api.example.com"])},
        )
        allowed, reason = manifest.check_operation("network.read", domain="evil.com")
        assert allowed is False
        assert "domain" in reason.lower()

    def test_check_operation_wrong_path(self):
        manifest = SkillManifest(
            skill_id="acme/test",
            version="1.0",
            name="Test",
            permissions={"file.read": PermissionSpec(paths=["/home/user/*"])},
        )
        allowed, reason = manifest.check_operation("file.read", path="/etc/shadow")
        assert allowed is False
        assert "path" in reason.lower()


class TestPermissionType:
    def test_all_types_exist(self):
        expected = [
            "file.read",
            "file.write",
            "file.delete",
            "shell",
            "network.read",
            "network.write",
            "message.send",
            "browser",
            "database.read",
            "database.write",
            "env.read",
        ]
        for e in expected:
            assert PermissionType(e)
