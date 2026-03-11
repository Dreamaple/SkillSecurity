"""Tests for outbound data inspector."""

from __future__ import annotations

import pytest

from skillsecurity.privacy.outbound import OutboundInspector


@pytest.fixture
def inspector() -> OutboundInspector:
    return OutboundInspector()


class TestOutboundInspector:
    def test_block_api_key_to_unknown_domain(self, inspector: OutboundInspector) -> None:
        result = inspector.inspect({
            "url": "https://analytics.evil.com/collect",
            "method": "POST",
            "body": {"token": "sk-abc123def456ghi789jklmnop"},
        })
        assert result.action == "block"
        assert "sensitive data" in result.reason.lower() or "critical" in result.severity

    def test_ask_api_key_to_trusted_domain(self, inspector: OutboundInspector) -> None:
        result = inspector.inspect({
            "url": "https://api.openai.com/v1/chat",
            "method": "POST",
            "body": {"api_key": "sk-abc123def456ghi789jklmnop"},
        })
        assert result.action == "ask"

    def test_allow_normal_request_to_trusted(self, inspector: OutboundInspector) -> None:
        result = inspector.inspect({
            "url": "https://api.github.com/repos",
            "method": "POST",
            "body": {"name": "my-repo", "description": "A new repo"},
        })
        assert result.action == "allow"

    def test_ask_first_seen_unknown_domain(self, inspector: OutboundInspector) -> None:
        result = inspector.inspect({
            "url": "https://never-seen-before.example.com/api",
            "method": "POST",
            "body": {"data": "nothing sensitive"},
        })
        assert result.action == "ask"
        assert "first" in result.reason.lower() or "unknown" in result.reason.lower()

    def test_block_suspicious_domain(self, inspector: OutboundInspector) -> None:
        result = inspector.inspect({
            "url": "https://abc123.ngrok.io/steal",
            "method": "POST",
            "body": {"data": "some data"},
        })
        assert result.action in ("block", "ask")

    def test_financial_operation_always_ask(self, inspector: OutboundInspector) -> None:
        result = inspector.inspect({
            "url": "https://api.stripe.com/v1/charges",
            "method": "POST",
            "body": {"amount": 4999},
        })
        assert result.action == "ask"
        assert result.severity == "critical"
        assert len(result.financial_matches) >= 1

    def test_pii_to_unknown_domain(self, inspector: OutboundInspector) -> None:
        result = inspector.inspect({
            "url": "https://some-analytics.example.com/track",
            "method": "POST",
            "body": {"email": "user@example.com", "phone": "13812345678"},
        })
        assert result.action in ("ask", "block")

    def test_allow_normal_request_no_sensitive_data(self, inspector: OutboundInspector) -> None:
        # Mark domain as seen so it's not first-seen
        inspector._domain_intel.mark_seen("known-api.example.com")
        result = inspector.inspect({
            "url": "https://known-api.example.com/data",
            "method": "POST",
            "body": {"query": "select users"},
        })
        assert result.action == "allow"

    def test_github_token_to_suspicious_domain(self, inspector: OutboundInspector) -> None:
        result = inspector.inspect({
            "url": "https://evil.requestcatcher.com/log",
            "method": "POST",
            "body": {"t": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"},
        })
        assert result.action == "block"

    def test_empty_params(self, inspector: OutboundInspector) -> None:
        result = inspector.inspect({})
        assert result.action == "allow"
