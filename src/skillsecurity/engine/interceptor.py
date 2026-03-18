"""Tool call interception entry point — orchestrates the full check pipeline."""

from __future__ import annotations

import contextlib
import time
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from skillsecurity.audit.logger import AuditLogger
from skillsecurity.config.defaults import MAX_COMMAND_LENGTH
from skillsecurity.engine.chain import ChainTracker
from skillsecurity.engine.decision import DecisionEngine
from skillsecurity.engine.policy import PolicyEngine
from skillsecurity.models.decision import Decision, RuleRef
from skillsecurity.models.rule import Action, Severity
from skillsecurity.models.tool_call import ToolCall, ToolType
from skillsecurity.selfprotect.guard import SelfProtectionGuard

if TYPE_CHECKING:
    from skillsecurity.engine.command_semantics import CommandSemanticsGuard
    from skillsecurity.engine.context_policy import ContextPolicyGuard
    from skillsecurity.engine.path_boundary import PathBoundaryGuard
    from skillsecurity.manifest.permissions import SkillManifest
    from skillsecurity.privacy.outbound import OutboundInspector

_NETWORK_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class Interceptor:
    """Orchestrates: self-protection → policy matching → privacy check → chain check → decision."""

    def __init__(
        self,
        policy_engine: PolicyEngine,
        decision_engine: DecisionEngine,
        self_protection: SelfProtectionGuard,
        audit_logger: AuditLogger | None = None,
        outbound_inspector: OutboundInspector | None = None,
        chain_tracker: ChainTracker | None = None,
        path_boundary_guard: PathBoundaryGuard | None = None,
        command_semantics_guard: CommandSemanticsGuard | None = None,
        context_policy_guard: ContextPolicyGuard | None = None,
    ) -> None:
        self._policy = policy_engine
        self._decision = decision_engine
        self._self_protection = self_protection
        self._audit_logger = audit_logger
        self._outbound_inspector = outbound_inspector
        self._chain_tracker = chain_tracker
        self._path_boundary_guard = path_boundary_guard
        self._command_semantics_guard = command_semantics_guard
        self._context_policy_guard = context_policy_guard
        self._skill_manifests: dict[str, SkillManifest] = {}

    def register_skill(self, skill_id: str, manifest: SkillManifest) -> None:
        """Register a Skill manifest for permission checking."""
        self._skill_manifests[skill_id] = manifest

    def check(self, tool_call: ToolCall) -> Decision:
        start = time.perf_counter()

        try:
            tool_call = self._truncate_long_params(tool_call)

            sp_decision = self._check_self_protection(tool_call)
            if sp_decision is not None:
                final = self._finalize(sp_decision, start)
                self._log_check(tool_call, final)
                return final

            context_decision = self._check_context_policy(tool_call)
            if context_decision is not None:
                final = self._finalize(context_decision, start)
                self._log_check(tool_call, final)
                return final

            perm_decision = self._check_skill_permission(tool_call)
            if perm_decision is not None:
                final = self._finalize(perm_decision, start)
                self._log_check(tool_call, final)
                return final

            sem_decision = self._check_command_semantics(tool_call)
            if sem_decision is not None:
                final = self._finalize(sem_decision, start)
                self._log_check(tool_call, final)
                return final

            path_boundary_decision = self._check_path_boundary(tool_call)
            if path_boundary_decision is not None:
                final = self._finalize(path_boundary_decision, start)
                self._log_check(tool_call, final)
                return final

            matched_rule = self._policy.evaluate(tool_call)
            if matched_rule and matched_rule.action == Action.BLOCK:
                decision = self._decision.make_decision(tool_call, matched_rule)
                final = self._finalize(decision, start)
                self._log_check(tool_call, final)
                return final

            privacy_decision = self._check_privacy(tool_call)
            if privacy_decision is not None:
                final = self._finalize(privacy_decision, start)
                self._log_check(tool_call, final)
                self._record_chain(tool_call, final)
                return final

            decision = self._decision.make_decision(tool_call, matched_rule)
            final = self._finalize(decision, start)

            chain_decision = self._check_chain(tool_call, final)
            if chain_decision is not None:
                self._log_check(tool_call, chain_decision)
                return chain_decision

            self._log_check(tool_call, final)
            self._record_chain(tool_call, final)
            return final

        except Exception:
            return self._fail_close(start)

    def _log_check(self, tool_call: ToolCall, decision: Decision) -> None:
        if not self._audit_logger:
            return
        with contextlib.suppress(Exception):
            self._audit_logger.log(
                event_type="tool_call_check",
                request={"tool_type": tool_call.tool_type.value, **tool_call.params},
                decision=decision.to_dict(),
                agent_id=tool_call.context.agent_id,
                session_id=tool_call.context.session_id,
                skill_id=tool_call.context.skill_id,
            )

    def _check_skill_permission(self, tool_call: ToolCall) -> Decision | None:
        """Check Skill-scoped permissions when skill_id and manifest are registered."""
        from skillsecurity.manifest.permissions import TOOL_TYPE_TO_PERMISSION

        skill_id = tool_call.context.skill_id
        if not skill_id or skill_id not in self._skill_manifests:
            return None
        manifest = self._skill_manifests[skill_id]
        perm_type = TOOL_TYPE_TO_PERMISSION.get(tool_call.tool_type.value)
        if not perm_type:
            return None
        domain = (
            tool_call.params.get("url", "").split("//")[-1].split("/")[0]
            if "url" in tool_call.params
            else None
        )
        path = tool_call.params.get("path")
        allowed, reason = manifest.check_operation(perm_type, domain=domain, path=path)
        if not allowed:
            return Decision(
                action=Action.BLOCK,
                reason=reason,
                severity=Severity.HIGH,
                rule_matched=RuleRef(
                    id=f"skill-permission:{skill_id}",
                    description="Skill permission boundary",
                ),
                suggestions=[
                    f"The Skill '{skill_id}' has not declared this permission",
                    "Update the Skill manifest to include the required permission",
                ],
            )
        return None

    def _check_path_boundary(self, tool_call: ToolCall) -> Decision | None:
        if self._path_boundary_guard is None:
            return None
        return self._path_boundary_guard.check(tool_call)

    def _check_command_semantics(self, tool_call: ToolCall) -> Decision | None:
        if self._command_semantics_guard is None:
            return None
        return self._command_semantics_guard.check(tool_call)

    def _check_context_policy(self, tool_call: ToolCall) -> Decision | None:
        if self._context_policy_guard is None:
            return None
        return self._context_policy_guard.check(tool_call)

    def _check_privacy(self, tool_call: ToolCall) -> Decision | None:
        """Run outbound data inspection for network requests, browser actions, and message sends."""
        if self._outbound_inspector is None:
            return None

        is_outbound = (
            tool_call.tool_type == ToolType.NETWORK_REQUEST
            and str(tool_call.params.get("method", "GET")).upper() in _NETWORK_WRITE_METHODS
        )
        if tool_call.tool_type in (ToolType.BROWSER, ToolType.MESSAGE_SEND):
            is_outbound = True

        if not is_outbound:
            return None

        result = self._outbound_inspector.inspect(tool_call.params)

        if result.action == "allow":
            return None

        action = Action.BLOCK if result.action == "block" else Action.ASK
        try:
            severity = Severity(result.severity)
        except ValueError:
            severity = Severity.HIGH

        rule_id = "privacy-check"
        rule_desc = "Privacy protection layer"
        if result.financial_matches:
            rule_id = f"financial:{result.financial_matches[0].pattern_id}"
            rule_desc = "Financial operation detection"
        elif result.domain_info and result.domain_info.first_seen:
            rule_id = "domain:first-seen"
            rule_desc = "First outbound request to unknown domain"

        return Decision(
            action=action,
            reason=result.reason,
            severity=severity,
            rule_matched=RuleRef(id=rule_id, description=rule_desc),
            suggestions=result.suggestions,
        )

    def _record_chain(self, tool_call: ToolCall, decision: Decision) -> None:
        """Record an event in the chain tracker (non-blocking)."""
        if self._chain_tracker is None:
            return
        with contextlib.suppress(Exception):
            self._chain_tracker.record_and_check(
                tool_type=tool_call.tool_type.value,
                params=tool_call.params,
                action=decision.action.value,
                session_id=tool_call.context.session_id,
            )

    def _check_chain(self, tool_call: ToolCall, decision: Decision) -> Decision | None:
        """Check whether the current (allowed) call completes an attack chain."""
        if self._chain_tracker is None:
            return None
        if decision.action != Action.ALLOW:
            return None

        match = self._chain_tracker.record_and_check(
            tool_type=tool_call.tool_type.value,
            params=tool_call.params,
            action=decision.action.value,
            session_id=tool_call.context.session_id,
        )
        if match is None:
            return None

        rule = match.rule
        action = Action.BLOCK if rule.action == "block" else Action.ASK
        try:
            severity = Severity(rule.severity)
        except ValueError:
            severity = Severity.CRITICAL

        chain_steps_desc = " → ".join(e.tool_type for e in match.matched_events)
        reason = rule.message or (f"Behavior chain detected ({rule.id}): {chain_steps_desc}")

        return self._finalize(
            Decision(
                action=action,
                reason=reason,
                severity=severity,
                rule_matched=RuleRef(id=rule.id, description=rule.description),
                suggestions=rule.suggestions
                or ["Review the sequence of operations for this session."],
            ),
            time.perf_counter() - 0.001,
        )

    def _check_self_protection(self, tool_call: ToolCall) -> Decision | None:
        target = tool_call.params.get("path") or tool_call.params.get("command")
        return self._self_protection.check(target)

    def _truncate_long_params(self, tool_call: ToolCall) -> ToolCall:
        """Truncate extremely long parameter values for analysis."""
        truncated = False
        new_params: dict[str, Any] = {}
        for k, v in tool_call.params.items():
            if isinstance(v, str) and len(v) > MAX_COMMAND_LENGTH:
                new_params[k] = v[:MAX_COMMAND_LENGTH]
                truncated = True
            else:
                new_params[k] = v

        if truncated:
            return ToolCall(
                tool_type=tool_call.tool_type,
                params=new_params,
                operation=tool_call.operation,
                context=tool_call.context,
            )
        return tool_call

    def _fail_close(self, start: float) -> Decision:
        """Fail-close: return a block decision on internal error."""
        fail_behavior = self._policy.global_config.fail_behavior
        action = Action.ALLOW if fail_behavior == "allow" else Action.BLOCK

        return self._finalize(
            Decision(
                action=action,
                reason="Internal security check error — applying fail-close policy",
                severity=Severity.HIGH,
            ),
            start,
        )

    @staticmethod
    def _finalize(decision: Decision, start: float) -> Decision:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return replace(decision, check_duration_ms=elapsed_ms)
