from __future__ import annotations

from pathlib import Path

from skillsecurity import SkillGuard
from skillsecurity.security.startup_audit import OpenClawDeploymentAuditor


class TestOpenClawDeploymentAuditor:
    def test_detects_risky_defaults(self) -> None:
        auditor = OpenClawDeploymentAuditor()
        findings = auditor.audit(
            openclaw_config={
                "gateway": {"bind": "0.0.0.0", "port": 18789, "auth": {"enabled": False}},
                "agents": {"defaults": {"sandbox": {"mode": "off"}}},
                "plugins": {"autoDiscover": True},
            },
            blocked_public_ports=[18789],
        )
        ids = {f.id for f in findings}
        assert "openclaw-bind-public" in ids
        assert "openclaw-risky-public-port" in ids
        assert "openclaw-auth-weak" in ids
        assert "openclaw-sandbox-off" in ids
        assert "openclaw-plugin-autodiscovery" in ids

    def test_hardened_config_no_findings(self) -> None:
        auditor = OpenClawDeploymentAuditor()
        findings = auditor.audit(
            openclaw_config={
                "gateway": {
                    "bind": "127.0.0.1",
                    "port": 18789,
                    "auth": {"enabled": True, "token": "token-value"},
                },
                "agents": {"defaults": {"sandbox": {"mode": "all"}}},
                "plugins": {"autoDiscover": False},
            },
            blocked_public_ports=[18789],
        )
        assert findings == []

    def test_loads_config_file(self, tmp_path: Path) -> None:
        p = tmp_path / "openclaw.json"
        p.write_text(
            '{"gateway":{"bind":"0.0.0.0","port":18789,"auth":{"enabled":false}}}',
            encoding="utf-8",
        )
        auditor = OpenClawDeploymentAuditor()
        findings = auditor.audit(config_file=str(p), blocked_public_ports=[18789])
        assert findings


class TestSkillGuardStartupAuditIntegration:
    def test_skill_guard_exposes_startup_findings(self) -> None:
        guard = SkillGuard(
            config={
                "rules": [],
                "startup_audit": {
                    "enabled": True,
                    "openclaw_config": {
                        "gateway": {"bind": "0.0.0.0", "port": 18789, "auth": {"enabled": False}},
                    },
                    "blocked_public_ports": [18789],
                },
            }
        )
        assert len(guard.startup_audit_findings) > 0
