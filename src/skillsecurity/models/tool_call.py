from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


class ToolType(enum.StrEnum):
    """Supported tool types for interception."""

    SHELL = "shell"
    FILE_READ = "file.read"
    FILE_WRITE = "file.write"
    FILE_DELETE = "file.delete"
    NETWORK_REQUEST = "network.request"
    MESSAGE_SEND = "message.send"
    BROWSER = "browser"
    DATABASE = "database"


@dataclass(frozen=True)
class CallContext:
    """Context information for a tool call."""

    agent_id: str | None = None
    session_id: str | None = None
    skill_id: str | None = None
    user_id: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class ToolCall:
    """Represents an AI Agent's tool call request."""

    tool_type: ToolType
    params: dict[str, Any] = field(default_factory=dict)
    operation: str | None = None
    context: CallContext = field(default_factory=CallContext)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolCall:
        """Create a ToolCall from a raw dictionary (as received from the public API).

        The dict must contain a "tool" key. Other keys are mapped to params.
        Optional keys: skill_id, agent_id, session_id, user_id are extracted into context.
        """
        tool_raw = data.get("tool", "")
        try:
            tool_type = ToolType(tool_raw)
        except ValueError:
            tool_type = (
                ToolType(tool_raw) if tool_raw in ToolType._value2member_map_ else ToolType.SHELL
            )

        context_keys = {"skill_id", "agent_id", "session_id", "user_id"}
        context_data = {k: v for k, v in data.items() if k in context_keys}
        context = CallContext(**context_data)

        param_keys = set(data.keys()) - {"tool"} - context_keys
        params = {k: data[k] for k in param_keys}

        return cls(tool_type=tool_type, params=params, context=context)
