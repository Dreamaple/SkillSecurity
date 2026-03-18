"""Shared utilities for framework adapters."""

from __future__ import annotations

import contextlib
import json
from typing import Any

from skillsecurity.models.decision import Decision

_APPROVAL_PROTOCOL = "skillsecurity.approval.v1"


def _get_or_create_guard(**kwargs: Any) -> Any:
    """Return the user-supplied guard or create a default one."""
    guard = kwargs.get("guard")
    if guard is not None:
        return guard
    from skillsecurity import SkillGuard

    init_kwargs: dict[str, Any] = {}
    if "policy_file" in kwargs:
        init_kwargs["policy_file"] = kwargs["policy_file"]
    if "policy" in kwargs:
        init_kwargs["policy"] = kwargs["policy"]
    if "config" in kwargs:
        init_kwargs["config"] = kwargs["config"]
    return SkillGuard(**init_kwargs)


def _build_pending_approval_payload(
    guard: Any,
    tool_call: dict[str, Any],
    decision: Decision,
    *,
    source: str,
) -> dict[str, Any]:
    """Build a unified pending-approval payload for ASK responses."""
    rule_id = decision.rule_matched.id if decision.rule_matched else None
    decision_type = "soft_ask" if (rule_id or "").startswith("soft-ask:") else "hard_ask"
    default_resolution = "allow" if decision_type == "soft_ask" else "deny"
    ticket: dict[str, Any] | None = None

    create_ticket = getattr(guard, "create_approval_ticket", None)
    if callable(create_ticket):
        with contextlib.suppress(Exception):
            created = create_ticket(
                tool_call,
                decision,
                source=source,
                decision_type=decision_type,
            )
            if isinstance(created, dict) and created.get("ticket_id"):
                ticket = created

    payload: dict[str, Any] = {
        "protocol": _APPROVAL_PROTOCOL,
        "status": "pending_approval",
        "source": source,
        "action": decision.action.value,
        "decision_type": decision_type,
        "default_resolution": default_resolution,
        "reason": decision.reason,
        "severity": decision.severity.value,
        "rule_id": rule_id,
        "suggestions": list(decision.suggestions),
        "ticket_id": None,
        "expires_at": None,
    }
    if ticket:
        payload["ticket_id"] = ticket.get("ticket_id")
        payload["expires_at"] = ticket.get("expires_at")
        payload["decision_type"] = ticket.get("decision_type", decision_type)

    return payload


def _format_pending_approval_message(payload: dict[str, Any]) -> str:
    """Render a backward-compatible confirmation message plus machine payload."""
    reason = str(payload.get("reason") or "User confirmation is required")
    return (
        f"[SkillSecurity] Requires confirmation: {reason}\n"
        f"{json.dumps(payload, ensure_ascii=False)}"
    )
