"""Rule matching engine — evaluates ToolCalls against Rules using regex patterns."""

from __future__ import annotations

import platform
import re
import time
from collections import defaultdict

from skillsecurity.models.rule import Rule
from skillsecurity.models.tool_call import ToolCall

_OS_MAP = {"Linux": "unix", "Darwin": "unix", "Windows": "windows"}


class RuleMatcher:
    """Matches tool calls against an ordered list of rules (first-match-wins)."""

    def __init__(self, rules: list[Rule]) -> None:
        self._rules = rules
        self._compiled: dict[str, re.Pattern[str]] = {}
        self._rate_counters: dict[str, list[float]] = defaultdict(list)
        self._current_os = _OS_MAP.get(platform.system(), "unix")

        for rule in rules:
            if rule.match:
                for field in ("command_pattern", "path_pattern", "url_pattern", "param_pattern"):
                    pattern = getattr(rule.match, field, None)
                    if pattern:
                        key = f"{rule.id}:{field}"
                        self._compiled[key] = re.compile(pattern)

    def match(self, tool_call: ToolCall) -> Rule | None:
        """Return the first matching rule, or None."""
        for rule in self._rules:
            if not self._os_applies(rule):
                continue
            if not self._tool_type_applies(rule, tool_call):
                continue

            if rule.rate_limit and not rule.match:
                if self._rate_exceeded(rule):
                    return rule
                continue

            if rule.match and self._conditions_match(rule, tool_call):
                return rule

        return None

    def _os_applies(self, rule: Rule) -> bool:
        if rule.os == "all" or not rule.os:
            return True
        return rule.os == self._current_os

    def _tool_type_applies(self, rule: Rule, tool_call: ToolCall) -> bool:
        if rule.tool_type is None:
            return True
        tool_value = tool_call.tool_type.value
        if isinstance(rule.tool_type, list):
            return tool_value in rule.tool_type
        return tool_value == rule.tool_type

    def _conditions_match(self, rule: Rule, tool_call: ToolCall) -> bool:
        mc = rule.match
        if not mc:
            return False

        matched_any = False

        if mc.command_pattern:
            command = tool_call.params.get("command", "")
            key = f"{rule.id}:command_pattern"
            if key in self._compiled and self._compiled[key].search(command):
                matched_any = True
            elif mc.command_pattern:
                return False

        if mc.path_pattern:
            path = tool_call.params.get("path", "")
            key = f"{rule.id}:path_pattern"
            if key in self._compiled and self._compiled[key].search(path):
                matched_any = True
            elif mc.path_pattern:
                return False

        if mc.url_pattern:
            url = tool_call.params.get("url", "")
            key = f"{rule.id}:url_pattern"
            if key in self._compiled and self._compiled[key].search(url):
                matched_any = True
            elif mc.url_pattern:
                return False

        if mc.param_pattern:
            param_str = " ".join(str(v) for v in tool_call.params.values())
            key = f"{rule.id}:param_pattern"
            if key in self._compiled and self._compiled[key].search(param_str):
                matched_any = True
            elif mc.param_pattern:
                return False

        return matched_any

    def _rate_exceeded(self, rule: Rule) -> bool:
        if not rule.rate_limit:
            return False

        now = time.monotonic()
        window = rule.rate_limit.window_seconds
        counter = self._rate_counters[rule.id]

        counter[:] = [t for t in counter if now - t < window]
        counter.append(now)

        return len(counter) > rule.rate_limit.max_calls
