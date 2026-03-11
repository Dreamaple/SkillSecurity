"""Domain intelligence — trust classification for outbound request targets."""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass


class TrustLevel(enum.StrEnum):
    TRUSTED = "trusted"
    KNOWN = "known"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"


@dataclass(frozen=True)
class DomainInfo:
    domain: str
    trust_level: TrustLevel
    category: str = ""
    first_seen: bool = False


_BUILTIN_TRUSTED: dict[str, list[str]] = {
    "ai_services": [
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "api.mistral.ai",
        "api.cohere.ai",
        "api.deepseek.com",
    ],
    "code_hosting": [
        "api.github.com",
        "github.com",
        "gitlab.com",
        "bitbucket.org",
    ],
    "package_registries": [
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "crates.io",
    ],
    "cloud_providers": [
        "*.amazonaws.com",
        "*.googleapis.com",
        "*.azure.com",
        "*.cloudflare.com",
    ],
    "search": [
        "api.bing.com",
        "serpapi.com",
        "www.google.com",
    ],
}

_BUILTIN_SUSPICIOUS: list[str] = [
    "*.ngrok.io",
    "*.serveo.net",
    "*.localtunnel.me",
    "requestbin.com",
    "webhook.site",
    "pipedream.net",
    "*.requestcatcher.com",
]


class DomainIntelligence:
    """Maintains domain trust levels and classifies outbound targets."""

    def __init__(
        self,
        extra_trusted: dict[str, list[str]] | None = None,
        extra_suspicious: list[str] | None = None,
    ) -> None:
        self._trusted: dict[str, list[str]] = dict(_BUILTIN_TRUSTED)
        if extra_trusted:
            for cat, domains in extra_trusted.items():
                self._trusted.setdefault(cat, []).extend(domains)

        self._suspicious = list(_BUILTIN_SUSPICIOUS)
        if extra_suspicious:
            self._suspicious.extend(extra_suspicious)

        self._seen_domains: set[str] = set()

    def query(self, domain: str) -> DomainInfo:
        """Look up trust level for a domain."""
        domain = self._normalize(domain)
        first_seen = domain not in self._seen_domains
        self._seen_domains.add(domain)

        for cat, patterns in self._trusted.items():
            if self._matches_any(domain, patterns):
                return DomainInfo(
                    domain=domain,
                    trust_level=TrustLevel.TRUSTED,
                    category=cat,
                    first_seen=first_seen,
                )

        if self._matches_any(domain, self._suspicious):
            return DomainInfo(
                domain=domain, trust_level=TrustLevel.SUSPICIOUS, first_seen=first_seen
            )

        return DomainInfo(domain=domain, trust_level=TrustLevel.UNKNOWN, first_seen=first_seen)

    def add_trusted(self, domain: str, category: str = "user") -> None:
        """Add a domain to the trusted list at runtime."""
        self._trusted.setdefault(category, []).append(domain)

    def mark_seen(self, domain: str) -> None:
        self._seen_domains.add(self._normalize(domain))

    @staticmethod
    def _normalize(domain: str) -> str:
        domain = domain.lower().strip()
        if domain.startswith("http"):
            domain = re.sub(r"^https?://", "", domain)
        domain = domain.split("/")[0]
        domain = domain.split(":")[0]
        return domain

    @staticmethod
    def _matches_any(domain: str, patterns: list[str]) -> bool:
        for pat in patterns:
            if pat.startswith("*."):
                suffix = pat[1:]  # ".amazonaws.com"
                if domain.endswith(suffix) or domain == pat[2:]:
                    return True
            elif domain == pat.lower():
                return True
        return False

    def extract_domain(self, url: str) -> str:
        """Extract domain from a URL string."""
        return self._normalize(url)
