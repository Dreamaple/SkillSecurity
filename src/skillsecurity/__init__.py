"""SkillSecurity — AI Agent Skill/Tool call security protection layer."""

from __future__ import annotations

import contextlib
import functools
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from skillsecurity.config.defaults import BUILTIN_POLICIES_DIR
from skillsecurity.engine.chain import ChainRule, ChainTracker
from skillsecurity.engine.decision import DecisionEngine
from skillsecurity.engine.interceptor import Interceptor
from skillsecurity.engine.policy import PolicyEngine, PolicyLoadError
from skillsecurity.manifest.parser import ManifestParser, ManifestValidationError
from skillsecurity.models.decision import Decision
from skillsecurity.models.tool_call import ToolCall
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

        self._interceptor = Interceptor(
            policy_engine=self._policy_engine,
            decision_engine=self._decision_engine,
            self_protection=self._self_protection,
            audit_logger=audit_logger,
            outbound_inspector=outbound_inspector,
            chain_tracker=chain_tracker,
        )

        self._setup_self_protection()

        self._watcher: PolicyWatcher | None = None
        if policy_file:
            self._start_watcher(policy_file)

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
        return self._interceptor.check(tc)

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
