"""Tests for the unified DataClassifier."""

from __future__ import annotations

import pytest

from skillsecurity.privacy.classifier import DataClassifier


@pytest.fixture
def classifier() -> DataClassifier:
    return DataClassifier()


class TestDataClassifier:
    def test_classify_openai_key(self, classifier: DataClassifier) -> None:
        result = classifier.classify("my key is sk-abc123def456ghi789jklmnop")
        assert result.has_critical()
        assert any(m.type == "openai-api-key" for m in result.matches)

    def test_classify_email(self, classifier: DataClassifier) -> None:
        result = classifier.classify("email: user@example.com")
        assert result.has_any()
        assert any(m.type == "email" for m in result.matches)

    def test_classify_combined(self, classifier: DataClassifier) -> None:
        text = "key=sk-abc123def456ghi789jklmnop email=user@example.com"
        result = classifier.classify(text)
        types = {m.type for m in result.matches}
        assert "openai-api-key" in types
        assert "email" in types

    def test_classify_normal_text(self, classifier: DataClassifier) -> None:
        result = classifier.classify("Hello world, nothing sensitive here.")
        assert not result.has_any()

    def test_classify_dict_nested(self, classifier: DataClassifier) -> None:
        data = {
            "headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
            "body": {"api_key": "sk-abc123def456ghi789jklmnop"},
        }
        result = classifier.classify_dict(data)
        assert result.has_critical()
        paths = {m.field_path for m in result.matches}
        assert any("body.api_key" in p for p in paths)

    def test_classify_dict_with_list(self, classifier: DataClassifier) -> None:
        data = {
            "items": ["normal text", "ghp_abcdefghijklmnopqrstuvwxyz1234567890"],
        }
        result = classifier.classify_dict(data)
        assert result.has_any()
        assert any(m.type == "github-pat" for m in result.matches)

    def test_max_severity_critical(self, classifier: DataClassifier) -> None:
        result = classifier.classify("sk-abc123def456ghi789jklmnop")
        assert result.max_severity == "critical"

    def test_max_severity_none(self, classifier: DataClassifier) -> None:
        result = classifier.classify("nothing here")
        assert result.max_severity == "low"

    def test_field_path_propagated(self, classifier: DataClassifier) -> None:
        result = classifier.classify("sk-abc123def456ghi789jklmnop", field_path="body.token")
        assert result.matches[0].field_path == "body.token"

    def test_disabled_secret_detection(self) -> None:
        c = DataClassifier(secret_detection=False)
        result = c.classify("sk-abc123def456ghi789jklmnop")
        assert not any(m.type == "openai-api-key" for m in result.matches)

    def test_disabled_pii_detection(self) -> None:
        c = DataClassifier(pii_detection=False)
        result = c.classify("user@example.com")
        assert not any(m.type == "email" for m in result.matches)

    def test_disabled_entropy_detection(self) -> None:
        c = DataClassifier(secret_detection=False, pii_detection=False, entropy_detection=False)
        result = c.classify("aB3xQ9mKpL7wR2nT5vJ8hY4gF6cE1dUzX")
        assert not result.has_any()

    def test_classify_chat_messages(self, classifier: DataClassifier) -> None:
        text = '{"messages": [{"role": "user", "content": "Hello"}, {"role": "assistant", "content": "Hi"}]}'
        result = classifier.classify(text)
        assert result.has_any()
        assert any("chat" in m.type for m in result.matches)

    def test_classify_chat_in_dict(self, classifier: DataClassifier) -> None:
        data = {
            "payload": '{"messages": [{"role": "user", "content": "secret plan"}]}',
        }
        result = classifier.classify_dict(data)
        assert any("chat" in m.type for m in result.matches)

    def test_classify_bulk_chat_is_critical(self, classifier: DataClassifier) -> None:
        msgs = ", ".join(f'{{"role": "user", "content": "message {i}"}}' for i in range(10))
        text = f'{{"messages": [{msgs}]}}'
        result = classifier.classify(text)
        assert result.has_critical()

    def test_disabled_chat_detection(self) -> None:
        c = DataClassifier(chat_detection=False)
        text = '{"messages": [{"role": "user", "content": "Hello"}]}'
        result = c.classify(text)
        assert not any("chat" in m.type for m in result.matches)
