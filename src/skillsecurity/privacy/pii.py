"""PII (Personally Identifiable Information) detection."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PIIPattern:
    id: str
    name: str
    pattern: re.Pattern[str]
    severity: str
    region: str  # "global", "cn", "us", etc.
    validation: str | None = None  # optional extra validation, e.g. "luhn"


@dataclass(frozen=True)
class PIIMatch:
    pattern_id: str
    name: str
    severity: str
    region: str
    matched_value: str
    start: int
    end: int

    @property
    def redacted_value(self) -> str:
        v = self.matched_value
        if len(v) <= 6:
            return "****"
        return v[:3] + "****" + v[-2:]


def _luhn_check(number: str) -> bool:
    """Validate a number string using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 12:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


_PATTERNS: list[PIIPattern] = [
    PIIPattern("email", "Email Address",
               re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
               "high", "global"),
    PIIPattern("phone-cn", "Chinese Phone Number",
               re.compile(r"(?<!\d)(?:\+86)?1[3-9]\d{9}(?!\d)"),
               "high", "cn"),
    PIIPattern("phone-us", "US Phone Number",
               re.compile(r"(?<!\d)(?:\+1)?[2-9]\d{2}[\-.]?\d{3}[\-.]?\d{4}(?!\d)"),
               "high", "us"),
    PIIPattern("id-card-cn", "Chinese ID Card Number",
               re.compile(
                   r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}"
                   r"(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?!\d)"
               ),
               "critical", "cn"),
    PIIPattern("ssn-us", "US Social Security Number",
               re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
               "critical", "us"),
    PIIPattern("credit-card", "Credit Card Number",
               re.compile(
                   r"(?<!\d)(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}"
                   r"|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})(?!\d)"
               ),
               "critical", "global", validation="luhn"),
]


class PIIDetector:
    """Detects personally identifiable information in text."""

    def __init__(self, extra_patterns: list[PIIPattern] | None = None) -> None:
        self._patterns = list(_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    def scan(self, text: str) -> list[PIIMatch]:
        """Scan text for PII patterns. Returns all matches."""
        matches: list[PIIMatch] = []
        for pp in self._patterns:
            for m in pp.pattern.finditer(text):
                value = m.group()
                if pp.validation == "luhn" and not _luhn_check(value):
                    continue
                matches.append(PIIMatch(
                    pattern_id=pp.id,
                    name=pp.name,
                    severity=pp.severity,
                    region=pp.region,
                    matched_value=value,
                    start=m.start(),
                    end=m.end(),
                ))
        return matches
