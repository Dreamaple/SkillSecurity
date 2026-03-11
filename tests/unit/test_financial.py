"""Tests for financial operation detection."""

from __future__ import annotations

import pytest

from skillsecurity.privacy.financial import FinancialDetector


@pytest.fixture
def detector() -> FinancialDetector:
    return FinancialDetector()


class TestFinancialDetector:
    def test_stripe_payment(self, detector: FinancialDetector) -> None:
        matches = detector.detect(
            url="https://api.stripe.com/v1/charges",
            method="POST",
        )
        assert len(matches) >= 1
        assert matches[0].pattern_id == "stripe"
        assert matches[0].category == "payment_api"

    def test_stripe_subscription(self, detector: FinancialDetector) -> None:
        matches = detector.detect(
            url="https://api.stripe.com/v1/subscriptions",
            method="POST",
        )
        assert len(matches) >= 1

    def test_paypal_payment(self, detector: FinancialDetector) -> None:
        matches = detector.detect(
            url="https://api.paypal.com/v2/orders",
            method="POST",
        )
        assert len(matches) >= 1
        assert matches[0].pattern_id == "paypal"

    def test_wechat_pay(self, detector: FinancialDetector) -> None:
        matches = detector.detect(
            url="https://api.mch.weixin.qq.com/v3/pay/transactions",
            method="POST",
        )
        assert len(matches) >= 1
        assert matches[0].pattern_id == "wechat-pay"

    def test_aws_ec2_creation(self, detector: FinancialDetector) -> None:
        matches = detector.detect(
            url="https://ec2.us-east-1.amazonaws.com",
            params_text="Action=RunInstances&ImageId=ami-12345",
        )
        assert len(matches) >= 1
        assert matches[0].category == "cloud_resource"

    def test_gcp_compute_creation(self, detector: FinancialDetector) -> None:
        matches = detector.detect(
            url="https://compute.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/instances",
            method="POST",
        )
        assert len(matches) >= 1

    def test_ethereum_transaction(self, detector: FinancialDetector) -> None:
        matches = detector.detect(
            params_text='{"method": "eth_sendTransaction", "params": [...]}',
        )
        assert len(matches) >= 1
        assert matches[0].category == "crypto"

    def test_browser_purchase_button(self, detector: FinancialDetector) -> None:
        matches = detector.detect(
            params_text="click button 'Buy Now'",
        )
        assert len(matches) >= 1
        assert matches[0].category == "browser_purchase"

    def test_browser_checkout(self, detector: FinancialDetector) -> None:
        matches = detector.detect(
            params_text="navigate to checkout page and confirm payment",
        )
        assert len(matches) >= 1

    def test_normal_api_not_detected(self, detector: FinancialDetector) -> None:
        matches = detector.detect(
            url="https://api.example.com/v1/users",
            method="POST",
        )
        assert len(matches) == 0

    def test_normal_get_request_not_detected(self, detector: FinancialDetector) -> None:
        matches = detector.detect(
            url="https://api.stripe.com/v1/charges",
            method="GET",
        )
        assert len(matches) == 0

    def test_from_tool_call_params(self, detector: FinancialDetector) -> None:
        params = {
            "url": "https://api.stripe.com/v1/payment_intents",
            "method": "POST",
            "body": '{"amount": 4999, "currency": "usd"}',
        }
        matches = detector.detect_from_tool_call_params(params)
        assert len(matches) >= 1
