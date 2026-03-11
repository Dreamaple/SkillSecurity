"""Unit tests for sensitive data redactor."""

from __future__ import annotations

from skillsecurity.audit.redactor import Redactor


class TestRedactor:
    def test_redact_password(self):
        r = Redactor()
        assert "***" in r.redact("password=secret123")
        assert "secret123" not in r.redact("password=secret123")

    def test_redact_token(self):
        r = Redactor()
        assert "mytoken" not in r.redact("token=mytoken")

    def test_redact_api_key(self):
        r = Redactor()
        assert "abc123" not in r.redact("api_key=abc123")

    def test_redact_bearer_token(self):
        r = Redactor()
        result = r.redact("Authorization: Bearer eyJhbGciOiJ...")
        assert "eyJhbGciOiJ" not in result
        assert "Bearer" in result

    def test_redact_sk_token_preserves_prefix(self):
        r = Redactor()
        result = r.redact("key: sk-abcdefghij1234567890end")
        assert "sk-" in result
        assert "abcdefghij1234567890end" not in result

    def test_safe_text_unchanged(self):
        r = Redactor()
        safe = "Hello world, this is normal text"
        assert r.redact(safe) == safe

    def test_redact_multiple_patterns(self):
        r = Redactor()
        text = "password=secret token=abc123 api_key=xyz"
        result = r.redact(text)
        assert "secret" not in result
        assert "abc123" not in result
        assert "xyz" not in result

    def test_redact_dict(self):
        r = Redactor()
        data = {
            "command": "curl -H 'Authorization: Bearer sk-abc123' https://api.com",
            "path": "/tmp/safe",
        }
        result = r.redact_dict(data)
        assert "sk-abc123" not in str(result)
        assert "/tmp/safe" in str(result)
