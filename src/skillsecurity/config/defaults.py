from __future__ import annotations

from pathlib import Path

# Default global configuration values
DEFAULT_ACTION = "allow"
DEFAULT_FAIL_BEHAVIOR = "block"
DEFAULT_LOG_LEVEL = "info"

# Policy schema version
POLICY_SCHEMA_VERSION = "1.0"

# Default policy template name
DEFAULT_POLICY_NAME = "default"

# Ask prompt defaults
DEFAULT_ASK_TIMEOUT_SECONDS = 60
DEFAULT_ASK_DEFAULT_ACTION = "block"

# Built-in policy file location (relative to package)
BUILTIN_POLICIES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "policies"

# Maximum command length for analysis (truncate beyond this)
MAX_COMMAND_LENGTH = 102_400  # 100KB

# Rate limit defaults
DEFAULT_RATE_LIMIT_WINDOW = 60  # seconds


class GlobalConfig:
    """Global policy configuration with fail-close defaults."""

    __slots__ = ("default_action", "fail_behavior", "log_level")

    def __init__(
        self,
        default_action: str = DEFAULT_ACTION,
        log_level: str = DEFAULT_LOG_LEVEL,
        fail_behavior: str = DEFAULT_FAIL_BEHAVIOR,
    ) -> None:
        self.default_action = default_action
        self.log_level = log_level
        self.fail_behavior = fail_behavior

    @classmethod
    def from_dict(cls, data: dict) -> GlobalConfig:
        return cls(
            default_action=data.get("default_action", DEFAULT_ACTION),
            log_level=data.get("log_level", DEFAULT_LOG_LEVEL),
            fail_behavior=data.get("fail_behavior", DEFAULT_FAIL_BEHAVIOR),
        )
