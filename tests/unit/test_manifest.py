"""Unit tests for manifest parser."""
from __future__ import annotations

import json

import pytest

from skillsecurity.manifest.parser import ManifestParser, ManifestValidationError


class TestManifestParser:
    def test_parse_valid_manifest(self, tmp_path):
        manifest = {
            "skill_id": "acme/weather-forecast",
            "version": "1.0.0",
            "name": "Weather Forecast",
            "permissions": {
                "network.read": {"description": "Fetch weather", "domains": ["api.openweathermap.org"]}
            },
        }
        path = tmp_path / "skill-manifest.json"
        path.write_text(json.dumps(manifest))
        result = ManifestParser.parse_file(str(path))
        assert result.skill_id == "acme/weather-forecast"
        assert "network.read" in result.permissions

    def test_parse_from_dict(self):
        manifest = {
            "skill_id": "acme/weather",
            "version": "1.0.0",
            "name": "Weather",
            "permissions": {},
        }
        result = ManifestParser.parse_dict(manifest)
        assert result.skill_id == "acme/weather"

    def test_missing_skill_id_raises(self):
        with pytest.raises(ManifestValidationError, match="skill_id"):
            ManifestParser.parse_dict({"version": "1.0.0", "name": "X", "permissions": {}})

    def test_missing_version_raises(self):
        with pytest.raises(ManifestValidationError, match="version"):
            ManifestParser.parse_dict({"skill_id": "acme/test", "name": "X", "permissions": {}})

    def test_invalid_skill_id_format(self):
        with pytest.raises(ManifestValidationError, match="skill_id"):
            ManifestParser.parse_dict({"skill_id": "INVALID", "version": "1.0.0", "name": "X", "permissions": {}})

    def test_permission_with_domains(self, tmp_path):
        manifest = {
            "skill_id": "acme/weather",
            "version": "1.0.0",
            "name": "Weather",
            "permissions": {
                "network.read": {"description": "API", "domains": ["api.example.com", "wttr.in"]}
            },
        }
        result = ManifestParser.parse_dict(manifest)
        assert result.permissions["network.read"].domains == ["api.example.com", "wttr.in"]

    def test_deny_permissions(self):
        manifest = {
            "skill_id": "acme/safe",
            "version": "1.0.0",
            "name": "Safe",
            "permissions": {},
            "deny_permissions": ["shell", "file.delete"],
        }
        result = ManifestParser.parse_dict(manifest)
        assert "shell" in result.deny_permissions
        assert "file.delete" in result.deny_permissions
