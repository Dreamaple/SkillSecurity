from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Action(enum.StrEnum):
    """Decision action types."""

    ALLOW = "allow"
    BLOCK = "block"
    ASK = "ask"


class Severity(enum.StrEnum):
    """Risk severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class MatchCondition:
    """Conditions for matching a tool call against a rule."""

    command_pattern: str | None = None
    path_pattern: str | None = None
    url_pattern: str | None = None
    param_pattern: str | None = None

    def has_any(self) -> bool:
        return any([self.command_pattern, self.path_pattern, self.url_pattern, self.param_pattern])


@dataclass(frozen=True)
class RateLimit:
    """Rate limiting configuration for a rule."""

    max_calls: int = 0
    window_seconds: int = 60


@dataclass(frozen=True)
class Rule:
    """A single policy rule entry."""

    id: str
    action: Action
    description: str = ""
    tool_type: str | list[str] | None = None
    os: str = "all"
    match: MatchCondition | None = None
    rate_limit: RateLimit | None = None
    severity: Severity = Severity.MEDIUM
    message: str = ""
    suggestions: list[str] = field(default_factory=list)
