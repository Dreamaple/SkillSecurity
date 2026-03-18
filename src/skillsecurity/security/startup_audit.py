"""Startup deployment audit focused on OpenClaw hardening baselines."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class StartupAuditFinding:
    id: str
    severity: str
    message: str
    recommendation: str


class OpenClawDeploymentAuditor:
    """Audits OpenClaw deployment config for risky defaults and weak settings."""

    def audit(
        self,
        config_file: str | None = None,
        openclaw_config: dict[str, Any] | None = None,
        require_loopback_bind: bool = True,
        require_auth: bool = True,
        require_sandbox: bool = True,
        blocked_public_ports: list[int] | None = None,
    ) -> list[StartupAuditFinding]:
        cfg = openclaw_config or self._load_config(config_file)
        if not cfg:
            return []

        findings: list[StartupAuditFinding] = []
        blocked_ports = set(blocked_public_ports or [])

        bind = self._pick(cfg, ["gateway.bind", "bind"])
        port = self._to_int(self._pick(cfg, ["gateway.port", "port"]))
        auth = self._pick(
            cfg,
            [
                "gateway.auth.enabled",
                "auth.enabled",
                "security.auth.enabled",
            ],
        )
        token = self._pick(cfg, ["gateway.auth.token", "auth.token", "security.auth.token"])
        password = self._pick(
            cfg,
            ["gateway.auth.password", "auth.password", "security.auth.password"],
        )
        sandbox_mode = self._pick(
            cfg,
            [
                "agents.defaults.sandbox.mode",
                "sandbox.mode",
                "tools.exec.host",
            ],
        )
        plugin_autodiscovery = self._pick(
            cfg,
            [
                "plugins.autoDiscover",
                "plugins.autodiscovery",
                "extensions.autoDiscover",
            ],
        )

        if require_loopback_bind and isinstance(bind, str):
            normalized = bind.strip().lower()
            if normalized in {"0.0.0.0", "::", "all", "public"}:
                findings.append(
                    StartupAuditFinding(
                        id="openclaw-bind-public",
                        severity="critical",
                        message=f"Gateway bind is public: {bind}",
                        recommendation=(
                            "Bind to loopback/internal address only (e.g. 127.0.0.1) and use reverse proxy auth."
                        ),
                    )
                )

        if port and port in blocked_ports and isinstance(bind, str):
            normalized = bind.strip().lower()
            if normalized not in {"127.0.0.1", "::1", "localhost", "loopback"}:
                findings.append(
                    StartupAuditFinding(
                        id="openclaw-risky-public-port",
                        severity="high",
                        message=f"Risky management port {port} exposed on non-loopback bind '{bind}'",
                        recommendation="Restrict port exposure with firewall and loopback binding.",
                    )
                )

        if require_auth:
            auth_enabled = bool(auth) if auth is not None else False
            has_secret = bool(token) or bool(password)
            if not auth_enabled or not has_secret:
                findings.append(
                    StartupAuditFinding(
                        id="openclaw-auth-weak",
                        severity="critical",
                        message="Authentication appears disabled or missing token/password",
                        recommendation="Enable auth and set strong token/password credentials.",
                    )
                )

        if require_sandbox and isinstance(sandbox_mode, str):
            if sandbox_mode.strip().lower() in {"off", "none", "host", "gateway"}:
                findings.append(
                    StartupAuditFinding(
                        id="openclaw-sandbox-off",
                        severity="high",
                        message=f"Sandbox mode appears weak or disabled: {sandbox_mode}",
                        recommendation="Enable sandbox for tool execution where feasible.",
                    )
                )

        if plugin_autodiscovery is True:
            findings.append(
                StartupAuditFinding(
                    id="openclaw-plugin-autodiscovery",
                    severity="high",
                    message="Plugin auto-discovery is enabled",
                    recommendation="Disable auto-discovery or enforce explicit trusted plugin allowlist.",
                )
            )

        return findings

    @staticmethod
    def _load_config(config_file: str | None) -> dict[str, Any]:
        candidates: list[Path] = []
        if config_file:
            candidates.append(Path(config_file))
        candidates.extend(
            [
                Path("openclaw.json"),
                Path("openclaw.yaml"),
                Path.home() / ".openclaw" / "openclaw.json",
                Path.home() / ".openclaw" / "openclaw.yaml",
            ]
        )

        for p in candidates:
            if not p.exists() or not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except OSError:
                continue
            if p.suffix.lower() == ".json":
                try:
                    data = json.loads(text)
                    if isinstance(data, dict):
                        return data
                except json.JSONDecodeError:
                    continue
            else:
                try:
                    data = yaml.safe_load(text)
                    if isinstance(data, dict):
                        return data
                except yaml.YAMLError:
                    continue
        return {}

    @staticmethod
    def _pick(data: dict[str, Any], dotted_keys: list[str]) -> Any:
        for key in dotted_keys:
            cursor: Any = data
            ok = True
            for part in key.split("."):
                if not isinstance(cursor, dict) or part not in cursor:
                    ok = False
                    break
                cursor = cursor[part]
            if ok:
                return cursor
        return None

    @staticmethod
    def _to_int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
