"""Outbound data inspector — checks outgoing network requests for sensitive data leakage."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from skillsecurity.privacy.classifier import ClassificationResult, DataClassifier
from skillsecurity.privacy.domains import DomainInfo, DomainIntelligence, TrustLevel
from skillsecurity.privacy.financial import FinancialDetector, FinancialMatch


@dataclass(frozen=True)
class InspectionResult:
    """Result of inspecting an outbound request."""

    action: str  # "allow", "block", "ask"
    reason: str = ""
    severity: str = "low"
    classification: ClassificationResult | None = None
    domain_info: DomainInfo | None = None
    financial_matches: list[FinancialMatch] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


# Decision matrix: (data_sensitivity, domain_trust) → action
# Rows: critical, high, medium, low
# Cols: trusted, known, unknown, suspicious
_DECISION_MATRIX: dict[tuple[str, str], str] = {
    ("critical", "trusted"): "ask",
    ("critical", "known"): "block",
    ("critical", "unknown"): "block",
    ("critical", "suspicious"): "block",
    ("high", "trusted"): "allow",
    ("high", "known"): "ask",
    ("high", "unknown"): "ask",
    ("high", "suspicious"): "block",
    ("medium", "trusted"): "allow",
    ("medium", "known"): "allow",
    ("medium", "unknown"): "ask",
    ("medium", "suspicious"): "block",
    ("low", "trusted"): "allow",
    ("low", "known"): "allow",
    ("low", "unknown"): "allow",
    ("low", "suspicious"): "ask",
}


class OutboundInspector:
    """Inspects outbound network requests for sensitive data, suspicious domains,
    and financial operations."""

    def __init__(
        self,
        classifier: DataClassifier | None = None,
        domain_intel: DomainIntelligence | None = None,
        financial_detector: FinancialDetector | None = None,
    ) -> None:
        self._classifier = classifier or DataClassifier()
        self._domain_intel = domain_intel or DomainIntelligence()
        self._financial = financial_detector or FinancialDetector()

    def inspect(self, params: dict[str, Any]) -> InspectionResult:
        """Full inspection of an outbound request's parameters."""

        # 1. Financial check (highest priority — always Ask, never skip)
        fin_matches = self._financial.detect_from_tool_call_params(params)
        if fin_matches:
            top = fin_matches[0]
            return InspectionResult(
                action="ask",
                reason=f"Financial operation detected: {top.name}",
                severity="critical",
                financial_matches=fin_matches,
                suggestions=[
                    "This operation involves financial transactions.",
                    "Review carefully before confirming.",
                ],
            )

        # 2. Domain analysis
        url = str(params.get("url", ""))
        domain_info: DomainInfo | None = None
        if url:
            domain_info = self._domain_intel.query(url)

        # 3. Data classification on payload
        payload = self._extract_payload(params)
        classification = self._classifier.classify_dict(payload) if payload else None

        # 4. Combine domain trust + data sensitivity → decision
        if classification and classification.has_any() and domain_info:
            data_severity = classification.max_severity
            trust = domain_info.trust_level.value
            action = _DECISION_MATRIX.get((data_severity, trust), "ask")

            match_desc = ", ".join(m.name for m in classification.matches[:3])
            reason = (
                f"Outbound request contains sensitive data ({match_desc}) "
                f"targeting {domain_info.trust_level.value} domain '{domain_info.domain}'"
            )
            suggestions = self._build_suggestions(classification, domain_info)

            return InspectionResult(
                action=action,
                reason=reason,
                severity=data_severity,
                classification=classification,
                domain_info=domain_info,
                suggestions=suggestions,
            )

        # 5. First-seen unknown domain (no sensitive data detected)
        if domain_info and domain_info.first_seen and domain_info.trust_level == TrustLevel.UNKNOWN:
            return InspectionResult(
                action="ask",
                reason=f"First outbound request to unknown domain '{domain_info.domain}'",
                severity="medium",
                domain_info=domain_info,
                suggestions=[
                    "This domain has not been seen before.",
                    "Add it to trusted domains if this is expected.",
                ],
            )

        # 6. Suspicious domain (no sensitive data detected)
        if domain_info and domain_info.trust_level == TrustLevel.SUSPICIOUS:
            return InspectionResult(
                action="block",
                reason=f"Request targets suspicious domain '{domain_info.domain}'",
                severity="high",
                domain_info=domain_info,
                suggestions=["This domain is flagged as suspicious."],
            )

        return InspectionResult(action="allow")

    def _extract_payload(self, params: dict[str, Any]) -> dict[str, Any]:
        """Extract the fields likely to carry user data."""
        payload: dict[str, Any] = {}
        for key in ("body", "data", "payload", "json", "content"):
            if key in params:
                val = params[key]
                if isinstance(val, dict):
                    payload.update(val)
                elif isinstance(val, str):
                    payload[key] = val

        for key in ("headers",):
            if key in params and isinstance(params[key], dict):
                payload[key] = params[key]

        if "url" in params:
            payload["_url"] = str(params["url"])

        return payload

    @staticmethod
    def _build_suggestions(
        classification: ClassificationResult, domain_info: DomainInfo
    ) -> list[str]:
        suggestions: list[str] = []
        if classification.has_critical():
            suggestions.append(
                "Critical sensitive data (API keys/tokens) detected in the outbound payload."
            )
        if domain_info.trust_level == TrustLevel.UNKNOWN:
            suggestions.append(
                f"Domain '{domain_info.domain}' is not in the trusted list. "
                "Add it via configuration if this is expected."
            )
        elif domain_info.trust_level == TrustLevel.SUSPICIOUS:
            suggestions.append(
                f"Domain '{domain_info.domain}' is flagged as suspicious."
            )
        return suggestions
