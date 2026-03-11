"""Chat/conversation history detection — identifies conversation data structures in payloads."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ChatPattern:
    id: str
    name: str
    pattern: re.Pattern[str]
    severity: str  # "high" or "medium"
    category: str  # "structure", "file_path", "bulk"


@dataclass(frozen=True)
class ChatMatch:
    pattern_id: str
    name: str
    severity: str
    category: str
    matched_value: str
    start: int
    end: int
    message_count: int = 0

    @property
    def redacted_value(self) -> str:
        v = self.matched_value
        if len(v) <= 20:
            return v[:6] + "****"
        return v[:10] + "...****..." + v[-10:]


# Structural patterns that indicate conversation/chat data
_STRUCTURE_PATTERNS: list[ChatPattern] = [
    # OpenAI / Anthropic message array format: {"role": "...", "content": "..."}
    ChatPattern(
        "chat-messages-role-content",
        "Chat messages (role/content format)",
        re.compile(
            r'["\']role["\']\s*:\s*["\'](?:user|assistant|system|human|ai|bot|tool)["\']\s*[,}]'
            r'.*?["\']content["\']\s*:\s*["\']',
            re.DOTALL | re.IGNORECASE,
        ),
        "high",
        "structure",
    ),
    # Multiple messages array: "messages": [...]
    ChatPattern(
        "chat-messages-array",
        "Chat messages array",
        re.compile(
            r'["\']messages["\']\s*:\s*\[',
            re.IGNORECASE,
        ),
        "high",
        "structure",
    ),
    # Conversation history with sender/text or author/text
    ChatPattern(
        "chat-sender-text",
        "Chat history (sender/text format)",
        re.compile(
            r'["\'](?:sender|author|from|speaker)["\']\s*:\s*["\'].*?["\']\s*[,}]'
            r'.*?["\'](?:text|message|body|content)["\']\s*:\s*["\']',
            re.DOTALL | re.IGNORECASE,
        ),
        "high",
        "structure",
    ),
    # Chat log timestamp patterns: "[2026-03-11 10:00:00] User: ..."
    ChatPattern(
        "chat-log-timestamped",
        "Timestamped chat log",
        re.compile(
            r"\[\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?\]"
            r"\s*(?:User|Assistant|System|Human|AI|Bot)\s*:",
            re.IGNORECASE,
        ),
        "medium",
        "structure",
    ),
    # Conversation export format: "conversation_id" or "chat_id" with history
    ChatPattern(
        "chat-conversation-export",
        "Conversation export data",
        re.compile(
            r'["\'](?:conversation_id|chat_id|thread_id|dialog_id)["\']\s*:'
            r'.*?["\'](?:messages|history|turns|exchanges)["\']\s*:\s*\[',
            re.DOTALL | re.IGNORECASE,
        ),
        "high",
        "structure",
    ),
]

# File path patterns for chat history storage
_FILE_PATH_PATTERNS: list[ChatPattern] = [
    ChatPattern(
        "chat-history-file",
        "Chat history file path",
        re.compile(
            r"(?:chat[_\-]?history|conversations?|chat[_\-]?log|message[_\-]?log"
            r"|dialog(?:ue)?s?|chat[_\-]?export|chat[_\-]?backup"
            r"|thread[_\-]?history|chat[_\-]?archive"
            r"|\.chathistory|\.chat_sessions)"
            r"(?:\.(?:json|jsonl|db|sqlite|csv|txt|log|yaml|yml|xml|md|html|parquet))?",
            re.IGNORECASE,
        ),
        "high",
        "file_path",
    ),
    # Common chat app data directories
    ChatPattern(
        "chat-app-data-dir",
        "Chat application data directory",
        re.compile(
            r"(?:\.(?:telegram|signal|whatsapp|wechat|slack|discord|teams)|"
            r"(?:Library/Messages|AppData.*?(?:Telegram|Signal|WhatsApp|WeChat|Slack|Discord)))",
            re.IGNORECASE,
        ),
        "high",
        "file_path",
    ),
]


def _count_messages(text: str) -> int:
    """Estimate the number of chat messages in the text."""
    role_hits = len(
        re.findall(
            r'["\']role["\']\s*:\s*["\'](?:user|assistant|system|human|ai|bot|tool)["\']',
            text,
            re.IGNORECASE,
        )
    )
    if role_hits > 0:
        return role_hits
    sender_hits = len(
        re.findall(
            r'["\'](?:sender|author|from|speaker)["\']\s*:\s*["\']',
            text,
            re.IGNORECASE,
        )
    )
    if sender_hits > 0:
        return sender_hits
    timestamp_hits = len(
        re.findall(
            r"\[\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}",
            text,
        )
    )
    return timestamp_hits


class ChatDetector:
    """Detects chat/conversation history data in text payloads and file paths."""

    BULK_THRESHOLD = 5

    def __init__(
        self,
        extra_patterns: list[ChatPattern] | None = None,
        bulk_threshold: int = BULK_THRESHOLD,
    ) -> None:
        self._structure_patterns = list(_STRUCTURE_PATTERNS)
        self._file_patterns = list(_FILE_PATH_PATTERNS)
        self._bulk_threshold = bulk_threshold
        if extra_patterns:
            for p in extra_patterns:
                if p.category == "file_path":
                    self._file_patterns.append(p)
                else:
                    self._structure_patterns.append(p)

    def scan(self, text: str) -> list[ChatMatch]:
        """Scan text for chat/conversation data patterns. Returns all matches."""
        matches: list[ChatMatch] = []
        seen_ids: set[str] = set()

        for cp in self._structure_patterns:
            m = cp.pattern.search(text)
            if m and cp.id not in seen_ids:
                msg_count = _count_messages(text)
                severity = cp.severity
                if msg_count >= self._bulk_threshold:
                    severity = "critical"
                matches.append(
                    ChatMatch(
                        pattern_id=cp.id,
                        name=cp.name,
                        severity=severity,
                        category=cp.category,
                        matched_value=m.group()[:100],
                        start=m.start(),
                        end=m.end(),
                        message_count=msg_count,
                    )
                )
                seen_ids.add(cp.id)

        return matches

    def scan_path(self, path: str) -> list[ChatMatch]:
        """Scan a file path string for chat-related file patterns."""
        matches: list[ChatMatch] = []
        for cp in self._file_patterns:
            m = cp.pattern.search(path)
            if m:
                matches.append(
                    ChatMatch(
                        pattern_id=cp.id,
                        name=cp.name,
                        severity=cp.severity,
                        category=cp.category,
                        matched_value=m.group(),
                        start=m.start(),
                        end=m.end(),
                    )
                )
        return matches
