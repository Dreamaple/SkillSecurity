"""Tests for known secret/API key detection."""

from __future__ import annotations

import pytest

from skillsecurity.privacy.secrets import SecretDetector


@pytest.fixture
def detector() -> SecretDetector:
    return SecretDetector()


class TestSecretDetector:
    def test_openai_api_key(self, detector: SecretDetector) -> None:
        text = "my key is sk-abc123def456ghi789jklmnop"
        matches = detector.scan(text)
        assert len(matches) >= 1
        assert any(m.pattern_id == "openai-api-key" for m in matches)
        assert all(m.severity == "critical" for m in matches)

    def test_anthropic_api_key(self, detector: SecretDetector) -> None:
        text = "token: sk-ant-abcdefghijklmnopqrstuvwx"
        matches = detector.scan(text)
        assert any(m.pattern_id == "anthropic-api-key" for m in matches)

    def test_github_pat(self, detector: SecretDetector) -> None:
        text = "gh token ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        matches = detector.scan(text)
        assert any(m.pattern_id == "github-pat" for m in matches)

    def test_aws_access_key(self, detector: SecretDetector) -> None:
        text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
        matches = detector.scan(text)
        assert any(m.pattern_id == "aws-access-key" for m in matches)

    def test_stripe_secret_key(self, detector: SecretDetector) -> None:
        text = "sk_test_4eC39HqLyjWDarjtT1zdp7dc00000000"
        matches = detector.scan(text)
        assert any(m.pattern_id == "stripe-secret-key" for m in matches)

    def test_stripe_publishable_key(self, detector: SecretDetector) -> None:
        text = "pk_test_abcdefghijklmnopqrstuvwxyz"
        matches = detector.scan(text)
        assert any(m.pattern_id == "stripe-publishable-key" for m in matches)

    def test_jwt_token(self, detector: SecretDetector) -> None:
        text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi"
        matches = detector.scan(text)
        assert any(m.pattern_id == "jwt-token" for m in matches)

    def test_bearer_token(self, detector: SecretDetector) -> None:
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        matches = detector.scan(text)
        assert any(m.pattern_id == "bearer-token" for m in matches)

    def test_private_key_pem(self, detector: SecretDetector) -> None:
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        matches = detector.scan(text)
        assert any(m.pattern_id == "private-key-pem" for m in matches)

    def test_no_false_positive_on_normal_text(self, detector: SecretDetector) -> None:
        text = "This is a normal paragraph about API design and security best practices."
        matches = detector.scan(text)
        assert len(matches) == 0

    def test_redacted_value(self, detector: SecretDetector) -> None:
        text = "sk-abc123def456ghi789jklmnop"
        matches = detector.scan(text)
        assert len(matches) >= 1
        for m in matches:
            assert "****" in m.redacted_value
            assert m.matched_value not in m.redacted_value or len(m.matched_value) <= 8

    def test_google_ai_key(self, detector: SecretDetector) -> None:
        text = "key=AIzaSyA-fake-key-for-testing-purposes12"
        matches = detector.scan(text)
        assert any(m.pattern_id == "google-ai-key" for m in matches)

    def test_gitlab_pat(self, detector: SecretDetector) -> None:
        text = "token: glpat-abcdefghijklmnopqrst"
        matches = detector.scan(text)
        assert any(m.pattern_id == "gitlab-pat" for m in matches)
