"""Decision engine — produces Decision objects from matched rules or defaults."""

from __future__ import annotations

from skillsecurity.models.decision import Decision, RuleRef
from skillsecurity.models.rule import Action, Rule, Severity
from skillsecurity.models.tool_call import ToolCall


class DecisionEngine:
    """Creates Decision results based on rule match outcomes."""

    def __init__(
        self,
        default_action: str = "allow",
        fail_behavior: str = "block",
    ) -> None:
        self._default_action = default_action
        self._fail_behavior = fail_behavior

    def make_decision(self, tool_call: ToolCall, matched_rule: Rule | None) -> Decision:
        if matched_rule is None:
            return self._default_decision(tool_call)
        return self._rule_decision(tool_call, matched_rule)

    def _rule_decision(self, tool_call: ToolCall, rule: Rule) -> Decision:
        reason = rule.message or self._generate_reason(tool_call, rule)

        suggestions = list(rule.suggestions)
        if rule.action == Action.BLOCK and not suggestions:
            suggestions = [self._generate_suggestion(tool_call, rule)]

        return Decision(
            action=rule.action,
            reason=reason,
            severity=rule.severity,
            rule_matched=RuleRef(id=rule.id, description=rule.description),
            suggestions=suggestions,
        )

    def _default_decision(self, tool_call: ToolCall) -> Decision:
        try:
            action = Action(self._default_action)
        except ValueError:
            action = Action.ALLOW

        return Decision(
            action=action,
            reason="No matching rule found — applying default policy",
            severity=Severity.LOW,
        )

    @staticmethod
    def _generate_reason(tool_call: ToolCall, rule: Rule) -> str:
        parts = [f"Matched rule '{rule.id}'"]
        if rule.description:
            parts.append(f": {rule.description}")
        return "".join(parts)

    @staticmethod
    def _generate_suggestion(tool_call: ToolCall, rule: Rule) -> str:
        if rule.severity == Severity.CRITICAL:
            return "This operation is highly dangerous. Consider a safer alternative."
        return "Review the operation and retry with appropriate parameters."
