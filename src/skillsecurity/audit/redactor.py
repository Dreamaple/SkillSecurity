"""Sensitive data redaction with precompiled regex patterns."""

from __future__ import annotations

import re
from typing import Any

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(password|passwd)\s*[=:]\s*\S+"), r"\1=***"),
    (re.compile(r"(?i)(token|api_key|api-key|apikey|secret|secret_key)\s*[=:]\s*\S+"), r"\1=***"),
    (
        re.compile(r"(?i)(Bearer)\s+\S+"),
        r"\1 ***",
    ),  # Before authorization to preserve Bearer prefix
    (re.compile(r"(sk-|pk-)[a-zA-Z0-9]{4}[a-zA-Z0-9]+([a-zA-Z0-9]{4})"), r"\g<1>****\2"),
    (
        re.compile(r"(?i)(authorization)\s*[=:]\s*(?!Bearer\s)\S+"),
        r"\1=***",
    ),  # Skip Bearer (handled above)
]


class Redactor:
    def __init__(self, extra_patterns: list[tuple[str, str]] | None = None) -> None:
        self._patterns = list(_PATTERNS)
        if extra_patterns:
            for pat, repl in extra_patterns:
                self._patterns.append((re.compile(pat), repl))

    def redact(self, text: str) -> str:
        for pattern, replacement in self._patterns:
            text = pattern.sub(replacement, text)
        return text

    def redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.redact(value)
            elif isinstance(value, dict):
                result[key] = self.redact_dict(value)
            elif isinstance(value, list):
                result[key] = [self.redact(str(v)) if isinstance(v, str) else v for v in value]
            else:
                result[key] = value
        return result
