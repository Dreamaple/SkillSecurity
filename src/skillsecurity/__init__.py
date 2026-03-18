"""SkillSecurity — AI Agent Skill/Tool call security protection layer."""

from __future__ import annotations

import contextlib
import functools
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from skillsecurity.approval.service import ApprovalService, get_shared_approval_service
from skillsecurity.config.defaults import BUILTIN_POLICIES_DIR
from skillsecurity.engine.chain import ChainRule, ChainTracker
from skillsecurity.engine.command_semantics import CommandSemanticsGuard
from skillsecurity.engine.context_policy import ContextPolicyGuard
from skillsecurity.engine.decision import DecisionEngine
from skillsecurity.engine.interceptor import Interceptor
from skillsecurity.engine.path_boundary import PathBoundaryGuard
from skillsecurity.engine.policy import PolicyEngine, PolicyLoadError
from skillsecurity.manifest.parser import ManifestParser, ManifestValidationError
from skillsecurity.models.decision import Decision, RuleRef
from skillsecurity.models.rule import Action, Severity
from skillsecurity.models.tool_call import ToolCall
from skillsecurity.security.startup_audit import OpenClawDeploymentAuditor, StartupAuditFinding
from skillsecurity.selfprotect.guard import SelfProtectionGuard

if TYPE_CHECKING:
    from skillsecurity.config.watcher import PolicyWatcher


class SkillSecurityError(Exception):
    """Base exception for SkillSecurity errors."""


def protect(framework: str, **kwargs: Any) -> None:
    """One-liner: install SkillSecurity into a framework.

    Usage:
        import skillsecurity
        skillsecurity.protect("langchain")
        skillsecurity.protect("mcp", policy_file="strict.yaml")
    """
    from skillsecurity.integrations import install

    install(framework, **kwargs)


def unprotect(framework: str) -> None:
    """Remove SkillSecurity protection from a framework.

    Usage:
        import skillsecurity
        skillsecurity.unprotect("langchain")
    """
    from skillsecurity.integrations import uninstall

    uninstall(framework)


__all__ = [
    "ChainRule",
    "ChainTracker",
    "Decision",
    "ManifestParser",
    "ManifestValidationError",
    "PolicyLoadError",
    "SkillGuard",
    "SkillSecurityError",
    "protect",
    "unprotect",
]


class SkillGuard:
    """Main entry point for SkillSecurity — checks tool calls against security policies.

    Usage:
        guard = SkillGuard()
        result = guard.check({"tool": "shell", "command": "rm -rf /"})
        if result.is_blocked:
            print(f"Blocked: {result.reason}")
    """

    def __init__(
        self,
        policy: str | None = None,
        policy_file: str | None = None,
        config: dict | None = None,
    ) -> None:
        self._policy_engine = PolicyEngine()
        self._self_protection = SelfProtectionGuard()
        self._startup_audit_findings: list[StartupAuditFinding] = []
        self._ask_config = (config or {}).get("ask", {})
        self._soft_confirmation_config = self._ask_config.get("soft_confirmation", {})
        self._approval_service = self._setup_approval(config)

        self._load_policy(policy, policy_file, config)

        gc = self._policy_engine.global_config
        self._decision_engine = DecisionEngine(
            default_action=gc.default_action,
            fail_behavior=gc.fail_behavior,
        )

        audit_logger, audit_log_path = self._setup_audit(config, policy_file)
        self._audit_log_path = audit_log_path
        self._audit_logger = audit_logger

        outbound_inspector = self._setup_privacy(config)
        chain_tracker = self._setup_chain_detection(config)
        path_boundary_guard = self._setup_path_boundary(config)
        command_semantics_guard = self._setup_command_semantics(config)
        context_policy_guard = self._setup_context_policy(config)

        self._interceptor = Interceptor(
            policy_engine=self._policy_engine,
            decision_engine=self._decision_engine,
            self_protection=self._self_protection,
            audit_logger=audit_logger,
            outbound_inspector=outbound_inspector,
            chain_tracker=chain_tracker,
            path_boundary_guard=path_boundary_guard,
            command_semantics_guard=command_semantics_guard,
            context_policy_guard=context_policy_guard,
        )

        self._setup_self_protection()

        self._watcher: PolicyWatcher | None = None
        if policy_file:
            self._start_watcher(policy_file)

        self._run_startup_audit(config)

    def register_skill(self, skill_id: str, manifest: str | dict) -> None:
        """Register a Skill permission manifest for tool-call authorization."""
        if isinstance(manifest, str):
            parsed = ManifestParser.parse_file(manifest)
        elif isinstance(manifest, dict):
            parsed = ManifestParser.parse_dict(manifest)
        else:
            raise ManifestValidationError("manifest must be a file path string or dict")
        self._interceptor.register_skill(skill_id, parsed)

    def scan_skill(self, skill_path: str, manifest: str | dict | None = None) -> dict:
        """Scan a Skill directory for dangerous code patterns."""
        from skillsecurity.scanner.analyzer import Analyzer
        from skillsecurity.scanner.report import generate_report

        analyzer = Analyzer()
        issues, file_count = analyzer.scan_directory(skill_path)
        skill_manifest = None
        if manifest:
            from skillsecurity.manifest.parser import ManifestParser

            if isinstance(manifest, str):
                skill_manifest = ManifestParser.parse_file(manifest)
            elif isinstance(manifest, dict):
                skill_manifest = ManifestParser.parse_dict(manifest)
        report = generate_report(skill_path, issues, file_count, skill_manifest)
        return report.to_dict()

    def query_logs(
        self,
        action: str | None = None,
        severity: str | None = None,
        agent_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query audit logs with optional filters."""
        from skillsecurity.audit.query import AuditQuery

        query = AuditQuery(self._audit_log_path)
        return query.query(
            action=action,
            severity=severity,
            agent_id=agent_id,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
        )

    def check(self, tool_call: dict[str, Any]) -> Decision:
        """Check a tool call against security policies.

        Args:
            tool_call: Dict with at least a "tool" key. Other keys depend on tool type.

        Returns:
            Decision with action (allow/block/ask), reason, severity, and suggestions.
        """
        tc = ToolCall.from_dict(tool_call)
        decision = self._interceptor.check(tc)
        decision = self._apply_soft_confirmation(tc, decision)
        decision = self._apply_approval_memory(tc, decision)
        return decision

    def create_approval_ticket(
        self,
        tool_call: dict[str, Any],
        decision: Decision,
        *,
        source: str = "runtime",
        decision_type: str = "hard_ask",
    ) -> dict[str, Any]:
        """Create a pending approval ticket for an ASK decision."""
        if self._approval_service is None:
            return {}
        if not decision.needs_confirmation:
            return {}

        ticket = self._approval_service.create_ticket(
            tool_call=tool_call,
            decision=decision,
            decision_type=decision_type,
            source=source,
        )

        if self._audit_logger:
            self._audit_logger.log(
                event_type="approval_ticket_created",
                request=ticket.tool_call,
                decision=decision.to_dict(),
                ticket_id=ticket.ticket_id,
                source=source,
                decision_type=decision_type,
                expires_at=ticket.expires_at.isoformat(),
            )

        return ticket.to_dict()

    def list_pending_approvals(self, limit: int = 100) -> list[dict[str, Any]]:
        """List pending approval tickets."""
        if self._approval_service is None:
            return []
        return [t.to_dict() for t in self._approval_service.list_pending(limit=limit)]

    def list_remembered_approvals(self, limit: int = 100) -> list[dict[str, Any]]:
        """List remembered approval decisions."""
        if self._approval_service is None:
            return []
        return [e.to_dict() for e in self._approval_service.list_remembered(limit=limit)]

    def revoke_remembered_approval(self, remember_id: str) -> bool:
        """Remove a remembered approval decision by id."""
        if self._approval_service is None:
            return False
        return self._approval_service.revoke_remembered(remember_id)

    def resolve_approval_ticket(
        self,
        ticket_id: str,
        *,
        allow: bool,
        approver: str | None = None,
        scope: str = "once",
    ) -> dict[str, Any] | None:
        """Resolve an approval ticket."""
        if self._approval_service is None:
            return None

        ticket = self._approval_service.resolve_ticket(
            ticket_id,
            allow=allow,
            approver=approver,
            scope=scope,
        )
        if ticket is None:
            return None

        if self._audit_logger:
            self._audit_logger.log(
                event_type="approval_ticket_resolved",
                request=ticket.tool_call,
                decision={
                    "action": "allow" if allow else "block",
                    "reason": f"Approval ticket {ticket_id} resolved",
                    "severity": ticket.severity,
                },
                ticket_id=ticket.ticket_id,
                status=ticket.status.value,
                approver=approver,
                scope=scope,
            )
        return ticket.to_dict()

    @property
    def startup_audit_findings(self) -> list[StartupAuditFinding]:
        """Latest startup deployment audit findings."""
        return list(self._startup_audit_findings)

    def protect(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator that automatically checks tool calls before execution."""

        @functools.wraps(func)
        def wrapper(tool_type: str, **params: Any) -> Any:
            call_dict = {"tool": tool_type, **params}
            decision = self.check(call_dict)
            if decision.is_blocked:
                raise SkillSecurityError(f"Operation blocked: {decision.reason}")
            return func(tool_type, **params)

        return wrapper

    def _apply_soft_confirmation(self, tool_call: ToolCall, decision: Decision) -> Decision:
        cfg = self._soft_confirmation_config
        if not cfg:
            return decision
        if not cfg.get("enabled", False):
            return decision
        if decision.action != Action.ALLOW:
            return decision

        tool_types = cfg.get("tool_types", [])
        if isinstance(tool_types, list) and tool_types and "*" not in tool_types:
            if tool_call.tool_type.value not in tool_types:
                return decision

        severity_raw = str(cfg.get("severity", "medium")).strip().lower()
        try:
            severity = Severity(severity_raw)
        except ValueError:
            severity = Severity.MEDIUM

        suggestions = cfg.get("suggestions")
        if not isinstance(suggestions, list) or not suggestions:
            suggestions = [
                "This operation is allowed by policy but configured for user confirmation.",
                "Use remember scope to reduce repeated prompts for trusted operations.",
            ]

        soft_decision = replace(
            decision,
            action=Action.ASK,
            reason=str(
                cfg.get("message")
                or "Operation is allowed but requires user confirmation in soft mode"
            ),
            severity=severity,
            rule_matched=RuleRef(
                id=f"soft-ask:{tool_call.tool_type.value}",
                description="Soft confirmation before allow",
            ),
            suggestions=list(suggestions),
        )

        if self._audit_logger:
            self._audit_logger.log(
                event_type="soft_confirmation_triggered",
                request={"tool_type": tool_call.tool_type.value, **tool_call.params},
                decision=soft_decision.to_dict(),
            )
        return soft_decision

    def _apply_approval_memory(self, tool_call: ToolCall, decision: Decision) -> Decision:
        if self._approval_service is None:
            return decision
        if not decision.needs_confirmation:
            return decision

        rule_id = decision.rule_matched.id if decision.rule_matched else None
        remembered = self._approval_service.match_remembered(tool_call, rule_id=rule_id)
        if remembered not in {"allow", "deny"}:
            return decision

        action = Action.ALLOW if remembered == "allow" else Action.BLOCK
        reason = f"Applied remembered {remembered} decision for this operation fingerprint"
        updated = replace(
            decision,
            action=action,
            reason=reason,
            rule_matched=RuleRef(
                id=f"approval-memory:{remembered}",
                description="Remembered user confirmation result",
            ),
            suggestions=[
                "Manage remembered entries in Dashboard approval center if this is unexpected."
            ],
        )

        if self._audit_logger:
            self._audit_logger.log(
                event_type="approval_memory_applied",
                request={"tool_type": tool_call.tool_type.value, **tool_call.params},
                decision=updated.to_dict(),
                memory_action=remembered,
            )
        return updated

    def _load_policy(
        self,
        policy: str | None,
        policy_file: str | None,
        config: dict | None,
    ) -> None:
        if config:
            self._policy_engine.load_dict(config)
        elif policy_file:
            self._policy_engine.load_file(policy_file)
        elif policy:
            self._policy_engine.load_builtin(policy)
        else:
            with contextlib.suppress(PolicyLoadError):
                self._policy_engine.load_builtin("default")

    def _setup_self_protection(self) -> None:
        self._self_protection.add_protected_path(BUILTIN_POLICIES_DIR)

    def _setup_approval(self, config: dict | None) -> ApprovalService | None:
        ask_cfg = self._ask_config
        if ask_cfg.get("enabled", True) is False:
            return None

        remember_cfg = ask_cfg.get("remember", {})
        use_shared = ask_cfg.get("shared_service", True)
        max_entries = ask_cfg.get("max_entries", 1000)
        timeout_seconds = ask_cfg.get("timeout_seconds", 60)
        params = {
            "default_timeout_seconds": timeout_seconds,
            "max_entries": max_entries,
            "remember_enabled": remember_cfg.get("enabled", False),
            "remember_default_scope": remember_cfg.get("scope", "session"),
            "remember_expiry_hours": remember_cfg.get("expiry_hours", 24),
            "remember_max_entries": remember_cfg.get("max_entries", 500),
        }
        if use_shared:
            return get_shared_approval_service(**params)
        return ApprovalService(**params)

    def _start_watcher(self, policy_file: str) -> None:
        try:
            from skillsecurity.config.watcher import PolicyWatcher

            self._watcher = PolicyWatcher(self._policy_engine, policy_file)
            self._watcher.start()
        except ImportError:
            pass  # watchdog not installed

    def stop(self) -> None:
        """Stop the policy watcher and flush audit logs."""
        if self._audit_logger:
            self._audit_logger.flush()
            self._audit_logger = None
        if self._watcher:
            self._watcher.stop()
            self._watcher = None

    def _setup_audit(self, config: dict | None, policy_file: str | None) -> tuple[Any | None, str]:
        """Create audit logger if enabled. Returns (logger, path)."""
        audit_config = self._get_audit_config(config, policy_file)
        audit_enabled = audit_config.get("enabled", True)
        path = audit_config.get("output", "./logs/skillsecurity-audit.jsonl")
        path_str = str(path)
        if audit_enabled:
            from skillsecurity.audit.logger import AuditLogger

            return AuditLogger(path_str), path_str
        return None, path_str

    def _setup_privacy(self, config: dict | None) -> Any:
        """Create OutboundInspector (privacy protection layer), enabled by default."""
        from skillsecurity.privacy.classifier import DataClassifier
        from skillsecurity.privacy.domains import DomainIntelligence
        from skillsecurity.privacy.financial import FinancialDetector
        from skillsecurity.privacy.outbound import OutboundInspector

        privacy_cfg = (config or {}).get("privacy", {})
        enabled = privacy_cfg.get("enabled", True)
        if not enabled:
            return None

        classifier_cfg = privacy_cfg.get("classifier", {})
        classifier = DataClassifier(
            secret_detection=classifier_cfg.get("secret_detection", True),
            pii_detection=classifier_cfg.get("pii_detection", True),
            entropy_detection=classifier_cfg.get("entropy_detection", True),
        )

        domain_cfg = privacy_cfg.get("domain_intelligence", {})
        extra_trusted = domain_cfg.get("trusted_domains", {})
        domain_intel = DomainIntelligence(
            extra_trusted=extra_trusted if isinstance(extra_trusted, dict) else None,
        )

        financial = FinancialDetector()

        return OutboundInspector(
            classifier=classifier,
            domain_intel=domain_intel,
            financial_detector=financial,
        )

    def _setup_chain_detection(self, config: dict | None) -> ChainTracker | None:
        """Create ChainTracker for behavior chain detection, enabled by default."""
        chain_cfg = (config or {}).get("chain_detection", {})
        enabled = chain_cfg.get("enabled", True)
        if not enabled:
            return None

        extra_rules: list[ChainRule] = []
        for rule_dict in chain_cfg.get("rules", []):
            extra_rules.append(ChainRule.from_dict(rule_dict))

        return ChainTracker(
            chain_rules=extra_rules,
            builtin_rules=chain_cfg.get("builtin_rules", True),
            max_history=chain_cfg.get("max_history", 200),
        )

    def _setup_path_boundary(self, config: dict | None) -> PathBoundaryGuard | None:
        pb_cfg = (config or {}).get("path_boundary", {})
        if not pb_cfg:
            return None
        return PathBoundaryGuard(
            enabled=pb_cfg.get("enabled", False),
            allowed_roots=pb_cfg.get("allowed_roots", []),
        )

    def _setup_command_semantics(self, config: dict | None) -> CommandSemanticsGuard | None:
        cs_cfg = (config or {}).get("command_semantics", {})
        if cs_cfg.get("enabled", True):
            return CommandSemanticsGuard(enabled=True)
        return None

    def _setup_context_policy(self, config: dict | None) -> ContextPolicyGuard | None:
        cp_cfg = (config or {}).get("context_policy", {})
        if not cp_cfg:
            return None
        return ContextPolicyGuard(
            enabled=cp_cfg.get("enabled", False),
            require_context=cp_cfg.get("require_context", False),
            role_permissions=cp_cfg.get("role_permissions"),
            scope_permissions=cp_cfg.get("scope_permissions"),
        )

    def _run_startup_audit(self, config: dict | None) -> None:
        sa_cfg = (config or {}).get("startup_audit", {})
        if not sa_cfg:
            return
        if not sa_cfg.get("enabled", True):
            return

        auditor = OpenClawDeploymentAuditor()
        findings = auditor.audit(
            config_file=sa_cfg.get("openclaw_config_file"),
            openclaw_config=sa_cfg.get("openclaw_config"),
            require_loopback_bind=sa_cfg.get("require_loopback_bind", True),
            require_auth=sa_cfg.get("require_auth", True),
            require_sandbox=sa_cfg.get("require_sandbox", True),
            blocked_public_ports=sa_cfg.get("blocked_public_ports", [18789, 3000]),
        )
        self._startup_audit_findings = findings
        if self._audit_logger and findings:
            for f in findings:
                self._audit_logger.log(
                    event_type="startup_audit",
                    request={"finding_id": f.id},
                    decision={
                        "action": "block" if f.severity in ("critical", "high") else "ask",
                        "reason": f.message,
                        "severity": f.severity,
                    },
                    recommendation=f.recommendation,
                )

    def _get_audit_config(self, config: dict | None, policy_file: str | None) -> dict:
        """Extract audit config from config dict or policy file."""
        if config:
            return (config or {}).get("audit", {})
        if policy_file:
            try:
                data = yaml.safe_load(Path(policy_file).read_text(encoding="utf-8"))
                return (data or {}).get("audit", {}) if isinstance(data, dict) else {}
            except Exception:
                return {}
        return {}
