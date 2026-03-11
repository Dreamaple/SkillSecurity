"""Data Classification Engine — unified entry point for sensitive data detection."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from skillsecurity.privacy.chat import ChatDetector
from skillsecurity.privacy.entropy import extract_high_entropy_tokens
from skillsecurity.privacy.pii import PIIDetector
from skillsecurity.privacy.secrets import SecretDetector


class SensitivityLevel(enum.StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class SensitiveMatch:
    """A single sensitive data detection result."""

    type: str  # pattern id, e.g. "openai-api-key", "email", "high-entropy"
    name: str
    severity: str
    value_preview: str  # redacted preview
    field_path: str = ""  # where in the data structure it was found
    confidence: float = 1.0
    start: int = 0
    end: int = 0


@dataclass
class ClassificationResult:
    """Aggregated classification output."""

    matches: list[SensitiveMatch] = field(default_factory=list)

    def has_critical(self) -> bool:
        return any(m.severity == "critical" for m in self.matches)

    def has_high(self) -> bool:
        return any(m.severity in ("critical", "high") for m in self.matches)

    def has_any(self) -> bool:
        return len(self.matches) > 0

    @property
    def max_severity(self) -> str:
        if not self.matches:
            return "low"
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return min(self.matches, key=lambda m: order.get(m.severity, 99)).severity


class DataClassifier:
    """Unified sensitive data classifier combining secrets, PII, chat history, and entropy analysis."""

    def __init__(
        self,
        secret_detection: bool = True,
        pii_detection: bool = True,
        entropy_detection: bool = True,
        chat_detection: bool = True,
    ) -> None:
        self._secret_detector = SecretDetector() if secret_detection else None
        self._pii_detector = PIIDetector() if pii_detection else None
        self._entropy_detection = entropy_detection
        self._chat_detector = ChatDetector() if chat_detection else None

    def classify(self, text: str, field_path: str = "") -> ClassificationResult:
        """Classify a single text string for sensitive data."""
        result = ClassificationResult()

        if self._secret_detector:
            for sm in self._secret_detector.scan(text):
                result.matches.append(
                    SensitiveMatch(
                        type=sm.pattern_id,
                        name=sm.name,
                        severity=sm.severity,
                        value_preview=sm.redacted_value,
                        field_path=field_path,
                        confidence=0.99,
                        start=sm.start,
                        end=sm.end,
                    )
                )

        if self._pii_detector:
            seen_ranges: set[tuple[int, int]] = {(m.start, m.end) for m in result.matches}
            for pm in self._pii_detector.scan(text):
                if (pm.start, pm.end) not in seen_ranges:
                    result.matches.append(
                        SensitiveMatch(
                            type=pm.pattern_id,
                            name=pm.name,
                            severity=pm.severity,
                            value_preview=pm.redacted_value,
                            field_path=field_path,
                            confidence=0.95,
                            start=pm.start,
                            end=pm.end,
                        )
                    )
                    seen_ranges.add((pm.start, pm.end))

        if self._entropy_detection:
            secret_ranges = {(m.start, m.end) for m in result.matches}
            for token in extract_high_entropy_tokens(text):
                idx = text.find(token)
                if idx >= 0 and not any(s <= idx < e for s, e in secret_ranges):
                    preview = token[:4] + "****" + token[-4:] if len(token) > 8 else "****"
                    result.matches.append(
                        SensitiveMatch(
                            type="high-entropy",
                            name="High-entropy string (possible secret)",
                            severity="high",
                            value_preview=preview,
                            field_path=field_path,
                            confidence=0.7,
                            start=idx,
                            end=idx + len(token),
                        )
                    )

        if self._chat_detector:
            for cm in self._chat_detector.scan(text):
                result.matches.append(
                    SensitiveMatch(
                        type=cm.pattern_id,
                        name=cm.name,
                        severity=cm.severity,
                        value_preview=cm.redacted_value,
                        field_path=field_path,
                        confidence=0.9,
                        start=cm.start,
                        end=cm.end,
                    )
                )

        return result

    def classify_dict(self, data: dict[str, Any], prefix: str = "") -> ClassificationResult:
        """Recursively classify all string values in a dictionary."""
        combined = ClassificationResult()
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, str):
                r = self.classify(value, field_path=path)
                combined.matches.extend(r.matches)
            elif isinstance(value, dict):
                r = self.classify_dict(value, prefix=path)
                combined.matches.extend(r.matches)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    item_path = f"{path}[{i}]"
                    if isinstance(item, str):
                        r = self.classify(item, field_path=item_path)
                        combined.matches.extend(r.matches)
                    elif isinstance(item, dict):
                        r = self.classify_dict(item, prefix=item_path)
                        combined.matches.extend(r.matches)
        return combined
