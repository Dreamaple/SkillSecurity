"""Shannon entropy analysis for detecting high-randomness strings (likely secrets)."""

from __future__ import annotations

import re
from collections import Counter
from math import log2

_MIN_TOKEN_LENGTH = 16
_HIGH_ENTROPY_SHORT = 4.5  # threshold for tokens 16-31 chars
_HIGH_ENTROPY_LONG = 4.0  # threshold for tokens ≥ 32 chars

_EXCLUDED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),  # UUID
    re.compile(r"^[0-9a-f]{32,64}$", re.I),  # hex hash (MD5/SHA)
    re.compile(r"^/|^[A-Z]:\\", re.I),  # file paths
    re.compile(r"^https?://"),  # URLs
]


def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((count / length) * log2(count / length) for count in freq.values())


def is_likely_secret(token: str) -> bool:
    """Heuristic check: is this string likely a secret/key based on entropy?"""
    if len(token) < _MIN_TOKEN_LENGTH:
        return False

    for pat in _EXCLUDED_PATTERNS:
        if pat.search(token):
            return False

    entropy = shannon_entropy(token)

    if len(token) >= 32 and entropy > _HIGH_ENTROPY_LONG:
        return True
    return len(token) >= _MIN_TOKEN_LENGTH and entropy > _HIGH_ENTROPY_SHORT


def extract_high_entropy_tokens(text: str, min_length: int = _MIN_TOKEN_LENGTH) -> list[str]:
    """Extract tokens from text that have suspiciously high entropy."""
    tokens = re.findall(rf"[A-Za-z0-9+/=_\-]{{{min_length},}}", text)
    return [t for t in tokens if is_likely_secret(t)]
