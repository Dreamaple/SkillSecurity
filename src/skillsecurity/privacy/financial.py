"""Financial operation detector — identifies payment, purchase, and subscription actions."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class FinancialPattern:
    id: str
    name: str
    category: str  # "payment_api", "cloud_resource", "browser_purchase", "crypto"
    url_pattern: re.Pattern[str] | None = None
    param_pattern: re.Pattern[str] | None = None
    method: str | None = None  # HTTP method filter (e.g. "POST")
    severity: str = "critical"


@dataclass(frozen=True)
class FinancialMatch:
    pattern_id: str
    name: str
    category: str
    severity: str
    detail: str  # human-readable explanation


_PAYMENT_PATTERNS: list[FinancialPattern] = [
    FinancialPattern("stripe", "Stripe Payment API", "payment_api",
                     url_pattern=re.compile(
                         r"api\.stripe\.com/v1/"
                         r"(charges|payment_intents|subscriptions|invoices|checkout)"
                     ),
                     method="POST"),
    FinancialPattern("paypal", "PayPal Payment API", "payment_api",
                     url_pattern=re.compile(
                         r"api\.paypal\.com/(v1|v2)/(payments|orders|billing)"
                     ),
                     method="POST"),
    FinancialPattern("alipay", "Alipay API", "payment_api",
                     url_pattern=re.compile(r"openapi\.alipay\.com"),
                     param_pattern=re.compile(r"alipay\.trade\.(pay|create|precreate)")),
    FinancialPattern("wechat-pay", "WeChat Pay API", "payment_api",
                     url_pattern=re.compile(
                         r"api\.mch\.weixin\.qq\.com/(v3/)?(pay|transactions)"
                     ),
                     method="POST"),
]

_CLOUD_PATTERNS: list[FinancialPattern] = [
    FinancialPattern("aws-ec2-create", "AWS EC2 Instance Creation", "cloud_resource",
                     url_pattern=re.compile(r"ec2\..*\.amazonaws\.com"),
                     param_pattern=re.compile(r"Action=RunInstances"),
                     severity="high"),
    FinancialPattern("aws-resource-create", "AWS Resource Creation", "cloud_resource",
                     url_pattern=re.compile(r".*\.amazonaws\.com"),
                     param_pattern=re.compile(
                         r"Action=(Create|Launch|Purchase|Subscribe)"
                     ),
                     severity="high"),
    FinancialPattern("gcp-compute-create", "GCP Compute Instance", "cloud_resource",
                     url_pattern=re.compile(r"compute\.googleapis\.com/.*/instances"),
                     method="POST", severity="high"),
    FinancialPattern("azure-vm-create", "Azure VM Creation", "cloud_resource",
                     url_pattern=re.compile(
                         r"management\.azure\.com/.*/virtualMachines"
                     ),
                     method="PUT", severity="high"),
]

_CRYPTO_PATTERNS: list[FinancialPattern] = [
    FinancialPattern("ethereum-tx", "Ethereum Transaction", "crypto",
                     param_pattern=re.compile(r"eth_sendTransaction|eth_signTransaction")),
    FinancialPattern("bitcoin-tx", "Bitcoin Transaction", "crypto",
                     param_pattern=re.compile(r"sendtoaddress|sendmany|sendrawtransaction")),
]

_BROWSER_PATTERNS: list[FinancialPattern] = [
    FinancialPattern("browser-purchase", "Browser Purchase Action", "browser_purchase",
                     param_pattern=re.compile(
                         r"(?i)(buy\s+now|place\s+order|checkout|purchase|subscribe|"
                         r"confirm\s+payment|add\s+to\s+cart.*checkout|pay\s+now)"
                     )),
    FinancialPattern("browser-payment-form", "Browser Payment Form", "browser_purchase",
                     param_pattern=re.compile(
                         r"(?i)(card[\s._-]?number|cvv|cvc|expir(y|ation)|billing[\s._-]?address)"
                     )),
]


class FinancialDetector:
    """Detects financial operations in tool calls."""

    def __init__(self) -> None:
        self._patterns = (
            _PAYMENT_PATTERNS + _CLOUD_PATTERNS + _CRYPTO_PATTERNS + _BROWSER_PATTERNS
        )

    def detect(
        self,
        url: str = "",
        method: str = "",
        params_text: str = "",
        body_text: str = "",
    ) -> list[FinancialMatch]:
        """Check if a tool call involves financial operations."""
        matches: list[FinancialMatch] = []
        combined_text = f"{params_text} {body_text}"

        for fp in self._patterns:
            if fp.url_pattern and (not url or not fp.url_pattern.search(url)):
                continue
            if fp.method and method and method.upper() != fp.method.upper():
                continue
            if fp.param_pattern and not fp.param_pattern.search(combined_text):
                continue

            matches.append(FinancialMatch(
                pattern_id=fp.id,
                name=fp.name,
                category=fp.category,
                severity=fp.severity,
                detail=f"Detected {fp.name} operation targeting {url or 'browser action'}",
            ))

        return matches

    def detect_from_tool_call_params(self, params: dict) -> list[FinancialMatch]:
        """Convenience: extract fields from a tool call params dict."""
        url = str(params.get("url", ""))
        method = str(params.get("method", ""))
        body = str(params.get("body", ""))
        # Flatten all param values for text matching
        param_texts = " ".join(str(v) for v in params.values())
        return self.detect(url=url, method=method, params_text=param_texts, body_text=body)
