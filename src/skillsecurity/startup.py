"""Auto-protect hook — loaded automatically via .pth file on Python startup.

This module reads .skillsecurity.yaml from the working directory (or the path
specified by SKILLSECURITY_CONFIG env var) and auto-protects configured frameworks.
Silently no-ops if config is missing or frameworks are not installed.
"""

from __future__ import annotations

import contextlib
import os
import warnings


def _auto_protect() -> None:
    config_path = os.environ.get("SKILLSECURITY_CONFIG", ".skillsecurity.yaml")
    if not os.path.isfile(config_path):
        return

    try:
        import yaml

        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return
    except Exception:
        return

    _run_startup_audit(data)

    frameworks = data.get("auto_protect", [])
    if not frameworks:
        return

    policy_file = data.get("policy_file")
    policy = data.get("policy")
    config = data.get("config")

    kwargs: dict = {}
    if policy_file:
        kwargs["policy_file"] = policy_file
    elif policy:
        kwargs["policy"] = policy
    elif config:
        kwargs["config"] = config

    from skillsecurity.integrations import install

    for fw in frameworks:
        with contextlib.suppress(Exception):
            install(fw, **kwargs)


def _run_startup_audit(data: dict) -> None:
    audit_cfg = data.get("startup_audit", {})
    if not isinstance(audit_cfg, dict):
        return
    if not audit_cfg.get("enabled", False):
        return
    try:
        from skillsecurity.security.startup_audit import OpenClawDeploymentAuditor

        findings = OpenClawDeploymentAuditor().audit(
            config_file=audit_cfg.get("openclaw_config_file"),
            openclaw_config=audit_cfg.get("openclaw_config"),
            require_loopback_bind=audit_cfg.get("require_loopback_bind", True),
            require_auth=audit_cfg.get("require_auth", True),
            require_sandbox=audit_cfg.get("require_sandbox", True),
            blocked_public_ports=audit_cfg.get("blocked_public_ports", [18789, 3000]),
        )
        if findings:
            warnings.warn(
                f"[SkillSecurity] startup_audit found {len(findings)} risk findings. "
                "Review deployment hardening settings.",
                RuntimeWarning,
                stacklevel=2,
            )
    except Exception:
        return


with contextlib.suppress(Exception):
    _auto_protect()
