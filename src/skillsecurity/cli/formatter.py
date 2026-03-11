"""Terminal output formatter with colored decision rendering."""

from __future__ import annotations

import json
from typing import Any

from skillsecurity.models.decision import Decision
from skillsecurity.models.rule import Action, Severity

_SEVERITY_COLORS = {
    Severity.LOW: "\033[32m",  # green
    Severity.MEDIUM: "\033[33m",  # yellow
    Severity.HIGH: "\033[91m",  # light red
    Severity.CRITICAL: "\033[31m",  # red
}

_ACTION_ICONS = {
    Action.ALLOW: "\u2705",  # ✅
    Action.BLOCK: "\U0001f6d1",  # 🛑
    Action.ASK: "\u26a0\ufe0f",  # ⚠️
}

_ACTION_LABELS = {
    Action.ALLOW: "ALLOW",
    Action.BLOCK: "BLOCK",
    Action.ASK: "ASK",
}

_RESET = "\033[0m"
_BOLD = "\033[1m"


class DecisionFormatter:
    """Formats Decision objects for terminal output."""

    def __init__(self, use_color: bool = True, use_emoji: bool = True, lang: str = "en") -> None:
        self._color = use_color
        self._emoji = use_emoji
        self._lang = lang

    def format_human(self, decision: Decision, tool_call: dict[str, Any] | None = None) -> str:
        lines: list[str] = []
        icon = _ACTION_ICONS.get(decision.action, "") if self._emoji else ""
        label = _ACTION_LABELS.get(decision.action, str(decision.action.value).upper())

        header = f"{icon} [{label}]" if icon else f"[{label}]"
        if decision.action == Action.BLOCK:
            header += " Operation blocked"
        elif decision.action == Action.ASK:
            header += " Confirmation required"
        else:
            header += " Operation allowed"

        lines.append(self._styled(header, bold=True))

        if tool_call:
            tool_type = tool_call.get("tool", "unknown")
            lines.append(f"   Tool: {tool_type}")
            for key in ("command", "path", "url"):
                if key in tool_call:
                    lines.append(f"   {key.capitalize()}: {tool_call[key]}")

        lines.append(f"   Reason: {decision.reason}")

        if decision.rule_matched:
            lines.append(f"   Rule: {decision.rule_matched.id}")

        sev_color = _SEVERITY_COLORS.get(decision.severity, "") if self._color else ""
        sev_reset = _RESET if self._color and sev_color else ""
        lines.append(f"   Severity: {sev_color}{decision.severity.value}{sev_reset}")

        if decision.suggestions:
            lines.append("   Suggestions:")
            for s in decision.suggestions:
                lines.append(f"     - {s}")

        if decision.check_duration_ms > 0:
            lines.append(f"   Check time: {decision.check_duration_ms:.1f}ms")

        return "\n".join(lines)

    def format_json(self, decision: Decision) -> str:
        return json.dumps(decision.to_dict(), ensure_ascii=False)

    def _styled(self, text: str, bold: bool = False) -> str:
        if not self._color:
            return text
        prefix = _BOLD if bold else ""
        return f"{prefix}{text}{_RESET}"
