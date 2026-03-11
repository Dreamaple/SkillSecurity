from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from skillsecurity.models.rule import Action, Severity


@dataclass(frozen=True)
class RuleRef:
    """Reference to a matched rule."""

    id: str
    description: str = ""


@dataclass(frozen=True)
class Decision:
    """The outcome of evaluating a tool call against security policies."""

    action: Action
    reason: str
    severity: Severity
    rule_matched: RuleRef | None = None
    suggestions: list[str] = field(default_factory=list)
    check_duration_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_allowed(self) -> bool:
        return self.action == Action.ALLOW

    @property
    def is_blocked(self) -> bool:
        return self.action == Action.BLOCK

    @property
    def needs_confirmation(self) -> bool:
        return self.action == Action.ASK

    def to_dict(self) -> dict:
        """Serialize to a dictionary for JSON output."""
        result = {
            "action": self.action.value,
            "reason": self.reason,
            "severity": self.severity.value,
            "rule_matched": (
                {"id": self.rule_matched.id, "description": self.rule_matched.description}
                if self.rule_matched
                else None
            ),
            "suggestions": self.suggestions,
            "check_duration_ms": round(self.check_duration_ms, 2),
        }
        return result
