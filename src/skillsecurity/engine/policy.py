"""Policy engine — loads YAML policies and provides first-match-wins evaluation."""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Any

import yaml

from skillsecurity.config.defaults import BUILTIN_POLICIES_DIR, GlobalConfig
from skillsecurity.engine.matcher import RuleMatcher
from skillsecurity.models.rule import Action, MatchCondition, RateLimit, Rule, Severity

_OS_MAP = {"Linux": "unix", "Darwin": "unix", "Windows": "windows"}


class PolicyLoadError(Exception):
    """Raised when a policy file cannot be loaded or parsed."""


class PolicyEngine:
    """Loads YAML security policies and evaluates tool calls against them."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._global_config = GlobalConfig()
        self._matcher: RuleMatcher | None = None
        self._source_path: str | None = None

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    @property
    def global_config(self) -> GlobalConfig:
        return self._global_config

    def load_file(self, path: str | Path) -> None:
        """Load and parse a YAML policy file."""
        path = Path(path)
        if not path.exists():
            raise PolicyLoadError(f"Policy file not found: {path}")

        try:
            text = path.read_text(encoding="utf-8")
            data = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise PolicyLoadError(f"YAML syntax error in {path}: {e}") from e

        if not isinstance(data, dict):
            raise PolicyLoadError(f"Policy file must contain a YAML mapping: {path}")

        self._parse_policy(data)
        self._source_path = str(path)
        self._rebuild_matcher()

    def load_builtin(self, name: str = "default") -> None:
        """Load a built-in policy template by name."""
        policy_file = BUILTIN_POLICIES_DIR / f"{name}.yaml"
        if not policy_file.exists():
            raise PolicyLoadError(f"Built-in policy '{name}' not found at {policy_file}")
        self.load_file(policy_file)

    def load_dict(self, data: dict[str, Any]) -> None:
        """Load policy from a dictionary (for programmatic use)."""
        self._parse_policy(data)
        self._rebuild_matcher()

    def evaluate(self, tool_call: Any) -> Rule | None:
        """Evaluate a tool call against loaded rules. Returns first matching rule or None."""
        if self._matcher is None:
            self._rebuild_matcher()
        return self._matcher.match(tool_call)  # type: ignore[union-attr]

    def _parse_policy(self, data: dict[str, Any]) -> None:
        if "global" in data:
            self._global_config = GlobalConfig.from_dict(data["global"])

        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise PolicyLoadError("'rules' must be a list")

        current_os = _OS_MAP.get(platform.system(), "unix")
        parsed: list[Rule] = []
        seen_ids: set[str] = set()

        for i, raw in enumerate(raw_rules):
            if not isinstance(raw, dict):
                raise PolicyLoadError(f"Rule at index {i} must be a mapping")

            rule_id = raw.get("id")
            if not rule_id:
                raise PolicyLoadError(f"Rule at index {i} is missing required 'id' field")
            if rule_id in seen_ids:
                raise PolicyLoadError(f"Duplicate rule ID: '{rule_id}'")
            seen_ids.add(rule_id)

            rule_os = raw.get("os", "all")
            if rule_os not in ("all", current_os):
                continue

            try:
                action = Action(raw.get("action", "block"))
            except ValueError as e:
                raise PolicyLoadError(
                    f"Invalid action '{raw.get('action')}' at rule '{rule_id}', "
                    f"valid: allow, block, ask"
                ) from e

            try:
                severity = Severity(raw.get("severity", "medium"))
            except ValueError:
                severity = Severity.MEDIUM

            match_data = raw.get("match")
            match_cond = None
            if match_data and isinstance(match_data, dict):
                match_cond = MatchCondition(
                    command_pattern=match_data.get("command_pattern"),
                    path_pattern=match_data.get("path_pattern"),
                    url_pattern=match_data.get("url_pattern"),
                    param_pattern=match_data.get("param_pattern"),
                )

            rate_data = raw.get("rate_limit")
            rate_limit = None
            if rate_data and isinstance(rate_data, dict):
                max_calls = rate_data.get("max_calls", 0)
                if max_calls <= 0:
                    raise PolicyLoadError(
                        f"rate_limit.max_calls must be positive in rule '{rule_id}'"
                    )
                rate_limit = RateLimit(
                    max_calls=max_calls,
                    window_seconds=rate_data.get("window_seconds", 60),
                )

            tool_type = raw.get("tool_type")
            suggestions = raw.get("suggestions", [])
            if not isinstance(suggestions, list):
                suggestions = [suggestions]

            parsed.append(
                Rule(
                    id=rule_id,
                    action=action,
                    description=raw.get("description", ""),
                    tool_type=tool_type,
                    os=rule_os,
                    match=match_cond,
                    rate_limit=rate_limit,
                    severity=severity,
                    message=raw.get("message", ""),
                    suggestions=suggestions,
                )
            )

        self._rules = parsed

    def _rebuild_matcher(self) -> None:
        self._matcher = RuleMatcher(self._rules)
