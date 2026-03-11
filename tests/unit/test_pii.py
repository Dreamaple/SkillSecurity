"""Tests for PII detection."""

from __future__ import annotations

import pytest

from skillsecurity.privacy.pii import PIIDetector, _luhn_check


@pytest.fixture
def detector() -> PIIDetector:
    return PIIDetector()


class TestLuhnCheck:
    def test_valid_visa(self) -> None:
        assert _luhn_check("4111111111111111")

    def test_valid_mastercard(self) -> None:
        assert _luhn_check("5500000000000004")

    def test_invalid_number(self) -> None:
        assert not _luhn_check("1234567890123456")

    def test_too_short(self) -> None:
        assert not _luhn_check("12345")


class TestPIIDetector:
    def test_email_detection(self, detector: PIIDetector) -> None:
        text = "Contact us at user@example.com for info"
        matches = detector.scan(text)
        assert any(m.pattern_id == "email" for m in matches)

    def test_chinese_phone(self, detector: PIIDetector) -> None:
        text = "电话: 13812345678"
        matches = detector.scan(text)
        assert any(m.pattern_id == "phone-cn" for m in matches)

    def test_us_phone(self, detector: PIIDetector) -> None:
        text = "Call 212-555-1234"
        matches = detector.scan(text)
        assert any(m.pattern_id == "phone-us" for m in matches)

    def test_chinese_id_card(self, detector: PIIDetector) -> None:
        text = "身份证号: 110101199003074513"
        matches = detector.scan(text)
        assert any(m.pattern_id == "id-card-cn" for m in matches)

    def test_us_ssn(self, detector: PIIDetector) -> None:
        text = "SSN: 123-45-6789"
        matches = detector.scan(text)
        assert any(m.pattern_id == "ssn-us" for m in matches)

    def test_credit_card_visa(self, detector: PIIDetector) -> None:
        text = "card: 4111111111111111"
        matches = detector.scan(text)
        assert any(m.pattern_id == "credit-card" for m in matches)

    def test_credit_card_invalid_luhn(self, detector: PIIDetector) -> None:
        text = "card: 4111111111111112"
        matches = detector.scan(text)
        assert not any(m.pattern_id == "credit-card" for m in matches)

    def test_no_false_positive_on_normal_text(self, detector: PIIDetector) -> None:
        text = "This is a normal paragraph about privacy."
        matches = detector.scan(text)
        assert len(matches) == 0

    def test_redacted_value(self, detector: PIIDetector) -> None:
        text = "user@example.com"
        matches = detector.scan(text)
        assert len(matches) >= 1
        for m in matches:
            assert "****" in m.redacted_value
