"""Tests for domain intelligence."""

from __future__ import annotations

import pytest

from skillsecurity.privacy.domains import DomainIntelligence, TrustLevel


@pytest.fixture
def intel() -> DomainIntelligence:
    return DomainIntelligence()


class TestDomainIntelligence:
    def test_trusted_ai_service(self, intel: DomainIntelligence) -> None:
        info = intel.query("api.openai.com")
        assert info.trust_level == TrustLevel.TRUSTED
        assert info.category == "ai_services"

    def test_trusted_github(self, intel: DomainIntelligence) -> None:
        info = intel.query("api.github.com")
        assert info.trust_level == TrustLevel.TRUSTED

    def test_trusted_wildcard_aws(self, intel: DomainIntelligence) -> None:
        info = intel.query("s3.us-east-1.amazonaws.com")
        assert info.trust_level == TrustLevel.TRUSTED
        assert info.category == "cloud_providers"

    def test_suspicious_ngrok(self, intel: DomainIntelligence) -> None:
        info = intel.query("abc123.ngrok.io")
        assert info.trust_level == TrustLevel.SUSPICIOUS

    def test_suspicious_webhook_site(self, intel: DomainIntelligence) -> None:
        info = intel.query("webhook.site")
        assert info.trust_level == TrustLevel.SUSPICIOUS

    def test_unknown_domain(self, intel: DomainIntelligence) -> None:
        info = intel.query("random-analytics.example.com")
        assert info.trust_level == TrustLevel.UNKNOWN
        assert info.first_seen is True

    def test_first_seen_tracking(self, intel: DomainIntelligence) -> None:
        info1 = intel.query("new-domain.example.com")
        assert info1.first_seen is True
        info2 = intel.query("new-domain.example.com")
        assert info2.first_seen is False

    def test_normalize_url(self, intel: DomainIntelligence) -> None:
        info = intel.query("https://api.openai.com/v1/chat")
        assert info.trust_level == TrustLevel.TRUSTED

    def test_normalize_port(self, intel: DomainIntelligence) -> None:
        info = intel.query("api.openai.com:443")
        assert info.trust_level == TrustLevel.TRUSTED

    def test_add_trusted_at_runtime(self, intel: DomainIntelligence) -> None:
        info = intel.query("my-company-api.com")
        assert info.trust_level == TrustLevel.UNKNOWN

        intel.add_trusted("my-company-api.com", "user")
        info2 = intel.query("my-company-api.com")
        assert info2.trust_level == TrustLevel.TRUSTED

    def test_extra_trusted_in_constructor(self) -> None:
        custom = DomainIntelligence(extra_trusted={"custom": ["myapi.example.com"]})
        info = custom.query("myapi.example.com")
        assert info.trust_level == TrustLevel.TRUSTED

    def test_extra_suspicious_in_constructor(self) -> None:
        custom = DomainIntelligence(extra_suspicious=["evil.example.com"])
        info = custom.query("evil.example.com")
        assert info.trust_level == TrustLevel.SUSPICIOUS

    def test_extract_domain(self, intel: DomainIntelligence) -> None:
        assert intel.extract_domain("https://api.openai.com/v1/chat") == "api.openai.com"
        assert intel.extract_domain("http://localhost:8080/test") == "localhost"
