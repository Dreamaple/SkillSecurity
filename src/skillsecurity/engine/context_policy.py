"""Context-based authorization guard (role/scope constraints)."""

from __future__ import annotations

import fnmatch

from skillsecurity.models.decision import Decision, RuleRef
from skillsecurity.models.rule import Action, Severity
from skillsecurity.models.tool_call import ToolCall


class ContextPolicyGuard:
    """Applies caller role/scope constraints before policy evaluation."""

    def __init__(
        self,
        enabled: bool = False,
        require_context: bool = False,
        role_permissions: dict[str, list[str]] | None = None,
        scope_permissions: dict[str, list[str]] | None = None,
    ) -> None:
        self._enabled = enabled
        self._require_context = require_context
        self._role_permissions = {
            str(k).lower(): [str(p) for p in v]
            for k, v in (role_permissions or {}).items()
        }
        self._scope_permissions = {
            str(k): [str(p) for p in v]
            for k, v in (scope_permissions or {}).items()
        }

    def check(self, tool_call: ToolCall) -> Decision | None:
        if not self._enabled:
            return None

        role = (tool_call.context.caller_role or "").strip().lower()
        scopes = tuple(s.strip() for s in tool_call.context.caller_scopes if s.strip())
        tool_value = tool_call.tool_type.value

        if not role and not scopes and self._require_context:
            return Decision(
                action=Action.BLOCK,
                reason="Caller context is required but missing (role/scopes)",
                severity=Severity.HIGH,
                rule_matched=RuleRef(id="context-policy:missing-context", description="Context policy"),
                suggestions=["Provide caller_role and/or caller_scopes in tool call context."],
            )

        if role and role in self._role_permissions:
            if not self._matches_permissions(tool_value, self._role_permissions[role]):
                return Decision(
                    action=Action.BLOCK,
                    reason=f"Role '{role}' is not allowed to invoke '{tool_value}'",
                    severity=Severity.HIGH,
                    rule_matched=RuleRef(
                        id=f"context-policy:role:{role}",
                        description="Context role policy",
                    ),
                    suggestions=[
                        "Use a role with required privileges.",
                        "Adjust context_policy.role_permissions if this action is expected.",
                    ],
                )

        if scopes and self._scope_permissions:
            matched_any_scope = False
            allowed_by_scope = False
            for scope in scopes:
                perms = self._scope_permissions.get(scope)
                if perms is None:
                    continue
                matched_any_scope = True
                if self._matches_permissions(tool_value, perms):
                    allowed_by_scope = True
                    break
            if matched_any_scope and not allowed_by_scope:
                joined = ", ".join(scopes[:3])
                return Decision(
                    action=Action.BLOCK,
                    reason=f"Scopes '{joined}' do not allow '{tool_value}'",
                    severity=Severity.HIGH,
                    rule_matched=RuleRef(
                        id="context-policy:scope-deny",
                        description="Context scope policy",
                    ),
                    suggestions=[
                        "Use a scope that includes this tool capability.",
                        "Adjust context_policy.scope_permissions if this action is expected.",
                    ],
                )

        return None

    @staticmethod
    def _matches_permissions(tool_type: str, patterns: list[str]) -> bool:
        for pat in patterns:
            if pat == "*":
                return True
            if fnmatch.fnmatch(tool_type, pat):
                return True
        return False
