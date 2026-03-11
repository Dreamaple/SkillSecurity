"""Behavior chain detection — identifies multi-step attack patterns across tool calls."""

from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ChainStep:
    """One step in a multi-step attack chain rule."""

    tool_type: str | list[str] | None = None
    match: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ChainRule:
    """Defines a multi-step attack pattern.

    When all steps are observed in order within `window_seconds`,
    the chain is considered triggered.
    """

    id: str
    steps: list[ChainStep]
    action: str = "block"
    severity: str = "critical"
    window_seconds: int = 300
    description: str = ""
    message: str = ""
    suggestions: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChainRule:
        steps = []
        for s in data.get("steps", []):
            steps.append(
                ChainStep(
                    tool_type=s.get("tool_type"),
                    match=s.get("match", {}),
                )
            )
        return cls(
            id=data["id"],
            steps=steps,
            action=data.get("action", "block"),
            severity=data.get("severity", "critical"),
            window_seconds=data.get("window_seconds", 300),
            description=data.get("description", ""),
            message=data.get("message", ""),
            suggestions=data.get("suggestions", []),
        )


@dataclass
class ChainEvent:
    """A recorded tool call event for chain tracking."""

    tool_type: str
    params: dict[str, Any]
    timestamp: float
    action: str  # the decision action ("allow", "block", "ask")


@dataclass(frozen=True)
class ChainMatch:
    """Result when a chain rule is triggered."""

    rule: ChainRule
    matched_events: list[ChainEvent]


# ──────────────── Built-in chain rules ────────────────

BUILTIN_CHAIN_RULES = [
    ChainRule(
        id="chain:read-sensitive-then-exfil",
        description="Read sensitive file then POST to external domain",
        steps=[
            ChainStep(
                tool_type="file.read",
                match={"path_pattern": r"\.(ssh|gpg|pem|key|env|credentials|secret)"},
            ),
            ChainStep(
                tool_type="network.request",
                match={"param_pattern": r"method.*(POST|PUT)"},
            ),
        ],
        action="block",
        severity="critical",
        window_seconds=300,
        message="Behavior chain detected: sensitive file read followed by outbound network write",
        suggestions=[
            "A sensitive file was read and then data was sent externally.",
            "This pattern resembles a data exfiltration attack.",
            "Review the sequence of operations carefully.",
        ],
    ),
    ChainRule(
        id="chain:multi-secret-read",
        description="Read multiple secret/credential files in sequence",
        steps=[
            ChainStep(
                tool_type="file.read",
                match={"path_pattern": r"(\.ssh|\.aws|\.gnupg|\.config|credentials|\.env|id_rsa)"},
            ),
            ChainStep(
                tool_type="file.read",
                match={"path_pattern": r"(\.ssh|\.aws|\.gnupg|\.config|credentials|\.env|id_rsa)"},
            ),
            ChainStep(
                tool_type="network.request",
                match={"param_pattern": r"method.*(POST|PUT)"},
            ),
        ],
        action="block",
        severity="critical",
        window_seconds=300,
        message="Behavior chain detected: multiple credential files read then outbound network write",
        suggestions=[
            "Multiple credential/secret files were read before a network write.",
            "This is a strong indicator of credential harvesting + exfiltration.",
        ],
    ),
    ChainRule(
        id="chain:db-dump-then-exfil",
        description="Database query followed by network exfiltration",
        steps=[
            ChainStep(
                tool_type="database",
                match={"param_pattern": r"(?i)(SELECT|DUMP|EXPORT|COPY)"},
            ),
            ChainStep(
                tool_type="network.request",
                match={"param_pattern": r"method.*(POST|PUT)"},
            ),
        ],
        action="block",
        severity="critical",
        window_seconds=300,
        message="Behavior chain detected: database query followed by outbound network write",
        suggestions=[
            "Data was read from a database and then sent externally.",
            "Verify this is an authorized data export operation.",
        ],
    ),
    ChainRule(
        id="chain:chat-read-then-exfil",
        description="Read chat history then send to external",
        steps=[
            ChainStep(
                tool_type="file.read",
                match={
                    "path_pattern": r"(?i)(chat|conversation|message|dialog|hist)"
                    r"|(\.(telegram|whatsapp|signal|wechat|slack))"
                },
            ),
            ChainStep(
                tool_type="network.request",
                match={"param_pattern": r"method.*(POST|PUT)"},
            ),
        ],
        action="block",
        severity="critical",
        window_seconds=300,
        message="Behavior chain detected: chat history read followed by outbound network write",
        suggestions=[
            "Chat/conversation data was read and then sent externally.",
            "This pattern resembles chat history exfiltration.",
        ],
    ),
    ChainRule(
        id="chain:env-recon-then-exfil",
        description="Environment reconnaissance followed by data exfiltration",
        steps=[
            ChainStep(
                tool_type="shell",
                match={"command_pattern": r"(whoami|hostname|uname|ifconfig|ipconfig|env\b|set\b)"},
            ),
            ChainStep(
                tool_type="network.request",
                match={"param_pattern": r"method.*(POST|PUT)"},
            ),
        ],
        action="ask",
        severity="high",
        window_seconds=120,
        message="Behavior chain detected: system reconnaissance followed by outbound network write",
        suggestions=[
            "System information was gathered and then sent externally.",
            "Verify this is not a reconnaissance + exfiltration attack.",
        ],
    ),
]

_MAX_HISTORY = 200
_DEFAULT_SESSION = "__default__"


class ChainTracker:
    """Tracks tool call sequences per session and detects multi-step attack patterns.

    Thread-safety: basic — assumes single-threaded call pattern per session.
    For multi-threaded use, external synchronization is required.
    """

    def __init__(
        self,
        chain_rules: list[ChainRule] | None = None,
        max_history: int = _MAX_HISTORY,
        builtin_rules: bool = True,
    ) -> None:
        self._rules: list[ChainRule] = []
        if builtin_rules:
            self._rules.extend(BUILTIN_CHAIN_RULES)
        if chain_rules:
            self._rules.extend(chain_rules)
        self._max_history = max_history
        self._sessions: dict[str, deque[ChainEvent]] = {}

    @property
    def rules(self) -> list[ChainRule]:
        return list(self._rules)

    def add_rule(self, rule: ChainRule) -> None:
        self._rules.append(rule)

    def record_and_check(
        self,
        tool_type: str,
        params: dict[str, Any],
        action: str,
        session_id: str | None = None,
    ) -> ChainMatch | None:
        """Record a tool call event and check if any chain rule is now triggered.

        Returns a ChainMatch if a chain is detected, None otherwise.
        Only checks chains if the current call was allowed (attackers need
        allowed steps to form a chain).
        """
        sid = session_id or _DEFAULT_SESSION
        now = time.time()
        event = ChainEvent(
            tool_type=tool_type,
            params=params,
            timestamp=now,
            action=action,
        )

        if sid not in self._sessions:
            self._sessions[sid] = deque(maxlen=self._max_history)
        history = self._sessions[sid]
        history.append(event)

        if action != "allow":
            return None

        for rule in self._rules:
            match = self._check_rule(rule, history, now)
            if match is not None:
                return match

        return None

    def clear_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def clear_all(self) -> None:
        self._sessions.clear()

    def _check_rule(
        self, rule: ChainRule, history: deque[ChainEvent], now: float
    ) -> ChainMatch | None:
        """Check if events in history match all steps of a chain rule in order."""
        if not rule.steps:
            return None

        window_start = now - rule.window_seconds
        recent = [e for e in history if e.timestamp >= window_start]

        matched_events: list[ChainEvent] = []
        step_idx = 0

        for event in recent:
            if step_idx >= len(rule.steps):
                break
            step = rule.steps[step_idx]
            if self._event_matches_step(event, step):
                matched_events.append(event)
                step_idx += 1

        if step_idx >= len(rule.steps):
            return ChainMatch(rule=rule, matched_events=matched_events)

        return None

    @staticmethod
    def _event_matches_step(event: ChainEvent, step: ChainStep) -> bool:
        """Check if a single event matches a chain step's conditions."""
        if step.tool_type:
            expected_types = (
                step.tool_type if isinstance(step.tool_type, list) else [step.tool_type]
            )
            if event.tool_type not in expected_types:
                return False

        for key, pattern in step.match.items():
            if key == "command_pattern":
                val = event.params.get("command", "")
                if not re.search(pattern, str(val)):
                    return False
            elif key == "path_pattern":
                val = event.params.get("path", "")
                if not re.search(pattern, str(val)):
                    return False
            elif key == "url_pattern":
                val = event.params.get("url", "")
                if not re.search(pattern, str(val)):
                    return False
            elif key == "param_pattern":
                params_str = " ".join(f"{k}={v}" for k, v in event.params.items())
                if not re.search(pattern, params_str):
                    return False

        return True
