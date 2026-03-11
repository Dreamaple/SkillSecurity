"""Known secret/API key format detection via pattern matching."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    id: str
    name: str
    pattern: re.Pattern[str]
    severity: str  # "critical" or "high"
    service: str


@dataclass(frozen=True)
class SecretMatch:
    pattern_id: str
    name: str
    service: str
    severity: str
    matched_value: str
    start: int
    end: int

    @property
    def redacted_value(self) -> str:
        v = self.matched_value
        if len(v) <= 8:
            return "****"
        return v[:4] + "****" + v[-4:]


_PATTERNS: list[SecretPattern] = [
    # AI services
    SecretPattern("openai-api-key", "OpenAI API Key",
                  re.compile(r"sk-[a-zA-Z0-9]{20,}"), "critical", "OpenAI"),
    SecretPattern("openai-proj-key", "OpenAI Project Key",
                  re.compile(r"sk-proj-[a-zA-Z0-9\-_]{20,}"), "critical", "OpenAI"),
    SecretPattern("anthropic-api-key", "Anthropic API Key",
                  re.compile(r"sk-ant-[a-zA-Z0-9\-]{20,}"), "critical", "Anthropic"),
    SecretPattern("google-ai-key", "Google AI API Key",
                  re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "critical", "Google AI"),

    # Cloud platforms
    SecretPattern("aws-access-key", "AWS Access Key",
                  re.compile(r"AKIA[0-9A-Z]{16}"), "critical", "AWS"),
    SecretPattern("gcp-service-account", "GCP Service Account",
                  re.compile(r'"type"\s*:\s*"service_account"'), "critical", "GCP"),

    # Code hosting
    SecretPattern("github-pat", "GitHub Personal Access Token",
                  re.compile(r"ghp_[a-zA-Z0-9]{36}"), "critical", "GitHub"),
    SecretPattern("github-fine-grained", "GitHub Fine-Grained Token",
                  re.compile(r"github_pat_[a-zA-Z0-9_]{22,}"), "critical", "GitHub"),
    SecretPattern("gitlab-pat", "GitLab Personal Access Token",
                  re.compile(r"glpat-[a-zA-Z0-9\-]{20,}"), "critical", "GitLab"),

    # Payment
    SecretPattern("stripe-secret-key", "Stripe Secret Key",
                  re.compile(r"sk_(live|test)_[a-zA-Z0-9]{24,}"), "critical", "Stripe"),
    SecretPattern("stripe-publishable-key", "Stripe Publishable Key",
                  re.compile(r"pk_(live|test)_[a-zA-Z0-9]{24,}"), "high", "Stripe"),

    # Auth tokens
    SecretPattern("jwt-token", "JWT Token",
                  re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
                  "high", "JWT"),
    SecretPattern("bearer-token", "Bearer Token",
                  re.compile(r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*"),
                  "high", "HTTP Auth"),
    SecretPattern("basic-auth", "Basic Auth Credentials",
                  re.compile(r"Basic\s+[A-Za-z0-9+/]+=*"),
                  "high", "HTTP Auth"),

    # Crypto keys
    SecretPattern("private-key-pem", "Private Key (PEM)",
                  re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
                  "critical", "Crypto"),
]


class SecretDetector:
    """Detects known API key and secret formats in text."""

    def __init__(self, extra_patterns: list[SecretPattern] | None = None) -> None:
        self._patterns = list(_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    def scan(self, text: str) -> list[SecretMatch]:
        """Scan text for known secret patterns. Returns all matches."""
        matches: list[SecretMatch] = []
        for sp in self._patterns:
            for m in sp.pattern.finditer(text):
                matches.append(SecretMatch(
                    pattern_id=sp.id,
                    name=sp.name,
                    service=sp.service,
                    severity=sp.severity,
                    matched_value=m.group(),
                    start=m.start(),
                    end=m.end(),
                ))
        return matches
