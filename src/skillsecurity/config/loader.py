"""YAML config loader with validation and clear error reporting."""

from __future__ import annotations

from pathlib import Path

import yaml

from skillsecurity.engine.policy import PolicyEngine, PolicyLoadError


def load_and_validate_policy(path: str | Path) -> PolicyEngine:
    """Load a YAML policy file with full validation.

    Returns a configured PolicyEngine, or raises PolicyLoadError with
    detailed error messages including line and field information.
    """
    engine = PolicyEngine()
    engine.load_file(path)
    return engine


def validate_policy_file(path: str | Path) -> list[str]:
    """Validate a policy file and return a list of warnings (empty if valid).

    Raises PolicyLoadError for fatal errors.
    """
    path = Path(path)
    if not path.exists():
        raise PolicyLoadError(f"Policy file not found: {path}")

    try:
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PolicyLoadError(f"YAML syntax error in {path}: {e}") from e

    warnings: list[str] = []

    if not isinstance(data, dict):
        raise PolicyLoadError(f"Policy file must contain a YAML mapping: {path}")

    if "version" not in data:
        raise PolicyLoadError("Missing required field: version")

    if "name" not in data:
        warnings.append("Missing recommended field: name")

    rules = data.get("rules", [])
    if not rules:
        warnings.append("Empty rules list — all actions will use default_action")

    engine = PolicyEngine()
    engine.load_file(path)

    return warnings
