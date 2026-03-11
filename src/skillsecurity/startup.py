"""Auto-protect hook — loaded automatically via .pth file on Python startup.

This module reads .skillsecurity.yaml from the working directory (or the path
specified by SKILLSECURITY_CONFIG env var) and auto-protects configured frameworks.
Silently no-ops if config is missing or frameworks are not installed.
"""

from __future__ import annotations

import contextlib
import os


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


with contextlib.suppress(Exception):
    _auto_protect()
