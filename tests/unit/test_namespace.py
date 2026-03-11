"""Unit tests for namespace validation."""
from __future__ import annotations

import pytest

from skillsecurity.manifest.namespace import NamespaceError, validate_skill_id


class TestNamespaceValidation:
    def test_valid_skill_id(self):
        assert validate_skill_id("acme/weather-forecast") is True

    def test_valid_simple(self):
        assert validate_skill_id("abc/def") is True

    def test_missing_slash(self):
        with pytest.raises(NamespaceError, match="must contain"):
            validate_skill_id("noslash")

    def test_uppercase_rejected(self):
        with pytest.raises(NamespaceError, match="lowercase"):
            validate_skill_id("Acme/Weather")

    def test_author_too_short(self):
        with pytest.raises(NamespaceError, match="author"):
            validate_skill_id("ab/skill-name")

    def test_skill_name_too_short(self):
        with pytest.raises(NamespaceError, match="skill name"):
            validate_skill_id("author/ab")

    def test_special_chars_rejected(self):
        with pytest.raises(NamespaceError):
            validate_skill_id("auth@r/skill_name")

    def test_author_max_length(self):
        author = "a" * 50
        assert validate_skill_id(f"{author}/skill-name") is True

    def test_author_too_long(self):
        author = "a" * 51
        with pytest.raises(NamespaceError, match="author"):
            validate_skill_id(f"{author}/skill-name")
