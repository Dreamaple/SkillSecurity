"""In-memory approval ticket service for ASK decisions."""

from __future__ import annotations

import enum
import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from skillsecurity.config.defaults import DEFAULT_ASK_TIMEOUT_SECONDS
from skillsecurity.models.decision import Decision
from skillsecurity.models.tool_call import ToolCall


class ApprovalStatus(enum.StrEnum):
    """Approval lifecycle states."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"


@dataclass
class ApprovalTicket:
    """A single user confirmation request."""

    ticket_id: str
    status: ApprovalStatus
    decision_type: str
    reason: str
    severity: str
    rule_id: str | None
    suggestions: list[str]
    tool_call: dict[str, Any]
    source: str
    created_at: datetime
    expires_at: datetime
    resolved_at: datetime | None = None
    resolution: str | None = None
    approver: str | None = None
    scope: str = "once"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the ticket for transport/logging."""
        return {
            "ticket_id": self.ticket_id,
            "status": self.status.value,
            "decision_type": self.decision_type,
            "reason": self.reason,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "suggestions": list(self.suggestions),
            "tool_call": dict(self.tool_call),
            "source": self.source,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolution": self.resolution,
            "approver": self.approver,
            "scope": self.scope,
            "metadata": dict(self.metadata),
        }


@dataclass
class RememberEntry:
    """Remembered approval decision for reducing repetitive prompts."""

    remember_id: str
    fingerprint: str
    action: str
    scope: str
    rule_id: str | None
    tool_type: str
    created_at: datetime
    expires_at: datetime
    session_id: str | None = None
    agent_id: str | None = None
    approver: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "remember_id": self.remember_id,
            "fingerprint": self.fingerprint,
            "action": self.action,
            "scope": self.scope,
            "rule_id": self.rule_id,
            "tool_type": self.tool_type,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "approver": self.approver,
        }


class ApprovalService:
    """Thread-safe in-memory approval queue."""

    def __init__(
        self,
        default_timeout_seconds: int = DEFAULT_ASK_TIMEOUT_SECONDS,
        max_entries: int = 1000,
        remember_enabled: bool = False,
        remember_default_scope: str = "session",
        remember_expiry_hours: int = 24,
        remember_max_entries: int = 500,
    ) -> None:
        self._default_timeout_seconds = max(1, int(default_timeout_seconds))
        self._max_entries = max(1, int(max_entries))
        self._remember_enabled = bool(remember_enabled)
        self._remember_default_scope = remember_default_scope
        self._remember_expiry_hours = max(1, int(remember_expiry_hours))
        self._remember_max_entries = max(1, int(remember_max_entries))
        self._lock = threading.RLock()
        self._tickets: dict[str, ApprovalTicket] = {}
        self._order: list[str] = []
        self._remembered: dict[str, RememberEntry] = {}
        self._remember_order: list[str] = []

    def create_ticket(
        self,
        tool_call: ToolCall | dict[str, Any],
        decision: Decision,
        *,
        decision_type: str = "hard_ask",
        source: str = "runtime",
        timeout_seconds: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ApprovalTicket:
        """Create a pending approval ticket from an ASK decision."""
        if not decision.needs_confirmation:
            raise ValueError("Approval tickets can only be created for ASK decisions")

        now = datetime.now(UTC)
        ttl = max(1, int(timeout_seconds or self._default_timeout_seconds))
        ticket = ApprovalTicket(
            ticket_id=f"appr-{uuid4().hex[:16]}",
            status=ApprovalStatus.PENDING,
            decision_type=decision_type,
            reason=decision.reason,
            severity=decision.severity.value,
            rule_id=decision.rule_matched.id if decision.rule_matched else None,
            suggestions=list(decision.suggestions),
            tool_call=self._serialize_tool_call(tool_call),
            source=source,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            metadata=dict(metadata or {}),
        )

        with self._lock:
            self._expire_locked(now)
            self._tickets[ticket.ticket_id] = ticket
            self._order.append(ticket.ticket_id)
            self._trim_locked()
        return ticket

    def get_ticket(self, ticket_id: str) -> ApprovalTicket | None:
        """Fetch a ticket by id."""
        with self._lock:
            self._expire_locked(datetime.now(UTC))
            return self._tickets.get(ticket_id)

    def list_pending(self, limit: int = 100) -> list[ApprovalTicket]:
        """List pending tickets ordered by creation time (oldest first)."""
        with self._lock:
            self._expire_locked(datetime.now(UTC))
            pending: list[ApprovalTicket] = []
            for tid in self._order:
                ticket = self._tickets.get(tid)
                if ticket is None:
                    continue
                if ticket.status == ApprovalStatus.PENDING:
                    pending.append(ticket)
                    if len(pending) >= limit:
                        break
            return pending

    def resolve_ticket(
        self,
        ticket_id: str,
        *,
        allow: bool,
        approver: str | None = None,
        scope: str = "once",
    ) -> ApprovalTicket | None:
        """Resolve a pending approval ticket."""
        with self._lock:
            now = datetime.now(UTC)
            self._expire_locked(now)
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                return None
            if ticket.status != ApprovalStatus.PENDING:
                return ticket

            normalized_scope = scope.lower().strip() if scope else self._remember_default_scope
            if normalized_scope not in {"once", "session", "agent", "global"}:
                normalized_scope = "once"
            ticket.status = ApprovalStatus.APPROVED if allow else ApprovalStatus.DENIED
            ticket.resolution = "allow" if allow else "deny"
            ticket.resolved_at = now
            ticket.approver = approver
            ticket.scope = normalized_scope
            self._remember_decision_locked(ticket, allow=allow, approver=approver)
            return ticket

    def match_remembered(self, tool_call: ToolCall | dict[str, Any], rule_id: str | None) -> str | None:
        """Return remembered action for a matching fingerprint, if any."""
        if not self._remember_enabled:
            return None

        call = self._serialize_tool_call(tool_call)
        fingerprint = self._make_fingerprint(call, rule_id)
        now = datetime.now(UTC)

        with self._lock:
            self._expire_locked(now)
            self._expire_remembered_locked(now)

            for remember_id in reversed(self._remember_order):
                entry = self._remembered.get(remember_id)
                if entry is None:
                    continue
                if entry.fingerprint != fingerprint:
                    continue
                if not self._scope_matches(call, entry):
                    continue
                return entry.action
        return None

    def list_remembered(self, limit: int = 100) -> list[RememberEntry]:
        """List remembered decisions ordered by creation time (newest first)."""
        with self._lock:
            self._expire_remembered_locked(datetime.now(UTC))
            entries: list[RememberEntry] = []
            for remember_id in reversed(self._remember_order):
                entry = self._remembered.get(remember_id)
                if entry is None:
                    continue
                entries.append(entry)
                if len(entries) >= limit:
                    break
            return entries

    def revoke_remembered(self, remember_id: str) -> bool:
        """Delete a remembered decision by id."""
        with self._lock:
            if remember_id not in self._remembered:
                return False
            self._remembered.pop(remember_id, None)
            self._remember_order = [rid for rid in self._remember_order if rid != remember_id]
            return True

    def _expire_locked(self, now: datetime) -> None:
        for ticket in self._tickets.values():
            if ticket.status != ApprovalStatus.PENDING:
                continue
            if now >= ticket.expires_at:
                ticket.status = ApprovalStatus.TIMEOUT
                ticket.resolution = "timeout"
                ticket.resolved_at = now

    def _trim_locked(self) -> None:
        while len(self._order) > self._max_entries:
            tid = self._order.pop(0)
            self._tickets.pop(tid, None)

    def _remember_decision_locked(
        self,
        ticket: ApprovalTicket,
        *,
        allow: bool,
        approver: str | None,
    ) -> None:
        if not self._remember_enabled:
            return
        if ticket.scope not in {"session", "agent", "global"}:
            return

        tool_call = dict(ticket.tool_call)
        remember = RememberEntry(
            remember_id=f"mem-{uuid4().hex[:16]}",
            fingerprint=self._make_fingerprint(tool_call, ticket.rule_id),
            action="allow" if allow else "deny",
            scope=ticket.scope,
            rule_id=ticket.rule_id,
            tool_type=str(tool_call.get("tool", "unknown")),
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(hours=self._remember_expiry_hours),
            session_id=str(tool_call.get("session_id") or "") or None,
            agent_id=str(tool_call.get("agent_id") or "") or None,
            approver=approver,
        )
        self._remembered[remember.remember_id] = remember
        self._remember_order.append(remember.remember_id)
        self._trim_remembered_locked()

    def _expire_remembered_locked(self, now: datetime) -> None:
        keep_ids: list[str] = []
        for remember_id in self._remember_order:
            entry = self._remembered.get(remember_id)
            if entry is None:
                continue
            if now >= entry.expires_at:
                self._remembered.pop(remember_id, None)
                continue
            keep_ids.append(remember_id)
        self._remember_order = keep_ids

    def _trim_remembered_locked(self) -> None:
        while len(self._remember_order) > self._remember_max_entries:
            rid = self._remember_order.pop(0)
            self._remembered.pop(rid, None)

    @staticmethod
    def _scope_matches(tool_call: dict[str, Any], entry: RememberEntry) -> bool:
        if entry.scope == "global":
            return True
        if entry.scope == "agent":
            return (tool_call.get("agent_id") or None) == entry.agent_id
        if entry.scope == "session":
            return (tool_call.get("session_id") or None) == entry.session_id
        return False

    @staticmethod
    def _make_fingerprint(tool_call: dict[str, Any], rule_id: str | None) -> str:
        base = {
            "tool": tool_call.get("tool"),
            "command": tool_call.get("command"),
            "path": tool_call.get("path"),
            "url": tool_call.get("url"),
            "tool_name": tool_call.get("tool_name"),
            "rule_id": rule_id or "",
        }
        raw = json.dumps(base, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def _serialize_tool_call(tool_call: ToolCall | dict[str, Any]) -> dict[str, Any]:
        if isinstance(tool_call, ToolCall):
            payload: dict[str, Any] = {"tool": tool_call.tool_type.value, **tool_call.params}
            if tool_call.context.agent_id:
                payload["agent_id"] = tool_call.context.agent_id
            if tool_call.context.session_id:
                payload["session_id"] = tool_call.context.session_id
            if tool_call.context.skill_id:
                payload["skill_id"] = tool_call.context.skill_id
            if tool_call.context.user_id:
                payload["user_id"] = tool_call.context.user_id
            if tool_call.context.caller_role:
                payload["caller_role"] = tool_call.context.caller_role
            if tool_call.context.caller_scopes:
                payload["caller_scopes"] = list(tool_call.context.caller_scopes)
            return payload
        return dict(tool_call)


_SHARED_SERVICE: ApprovalService | None = None
_SHARED_LOCK = threading.Lock()


def get_shared_approval_service(
    default_timeout_seconds: int = DEFAULT_ASK_TIMEOUT_SECONDS,
    max_entries: int = 1000,
    remember_enabled: bool = False,
    remember_default_scope: str = "session",
    remember_expiry_hours: int = 24,
    remember_max_entries: int = 500,
) -> ApprovalService:
    """Return a process-wide shared approval service instance."""
    global _SHARED_SERVICE
    with _SHARED_LOCK:
        if _SHARED_SERVICE is None:
            _SHARED_SERVICE = ApprovalService(
                default_timeout_seconds=default_timeout_seconds,
                max_entries=max_entries,
                remember_enabled=remember_enabled,
                remember_default_scope=remember_default_scope,
                remember_expiry_hours=remember_expiry_hours,
                remember_max_entries=remember_max_entries,
            )
        else:
            # Merge runtime config upgrades into the existing shared instance.
            _SHARED_SERVICE._default_timeout_seconds = max(  # noqa: SLF001
                1, int(default_timeout_seconds)
            )
            _SHARED_SERVICE._max_entries = max(1, int(max_entries))  # noqa: SLF001
            _SHARED_SERVICE._remember_enabled = (  # noqa: SLF001
                _SHARED_SERVICE._remember_enabled or bool(remember_enabled)
            )
            _SHARED_SERVICE._remember_default_scope = remember_default_scope  # noqa: SLF001
            _SHARED_SERVICE._remember_expiry_hours = max(  # noqa: SLF001
                _SHARED_SERVICE._remember_expiry_hours,
                int(remember_expiry_hours),
            )
            _SHARED_SERVICE._remember_max_entries = max(  # noqa: SLF001
                _SHARED_SERVICE._remember_max_entries,
                int(remember_max_entries),
            )
        return _SHARED_SERVICE


def reset_shared_approval_service() -> None:
    """Reset the shared service (test helper)."""
    global _SHARED_SERVICE
    with _SHARED_LOCK:
        _SHARED_SERVICE = None
