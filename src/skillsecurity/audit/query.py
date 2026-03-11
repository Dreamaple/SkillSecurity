"""Log querying and filtering with pagination."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class AuditQuery:
    def __init__(self, log_path: str | Path) -> None:
        self._path = Path(log_path)

    def query(
        self,
        action: str | None = None,
        severity: str | None = None,
        agent_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        results: list[dict[str, Any]] = []
        skipped = 0
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not self._matches(entry, action, severity, agent_id, since, until):
                continue
            if skipped < offset:
                skipped += 1
                continue
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    def count(self, action: str | None = None) -> dict[str, int]:
        counts: dict[str, int] = {"allow": 0, "block": 0, "ask": 0, "total": 0}
        if not self._path.exists():
            return counts
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            decision = entry.get("decision", {})
            act = decision.get("action", "")
            if action and act != action:
                continue
            counts["total"] += 1
            if act in counts:
                counts[act] += 1
        return counts

    @staticmethod
    def _matches(
        entry: dict,
        action: str | None,
        severity: str | None,
        agent_id: str | None,
        since: str | None,
        until: str | None,
    ) -> bool:
        decision = entry.get("decision", {})
        if action and decision.get("action") != action:
            return False
        if severity and decision.get("severity") != severity:
            return False
        if agent_id and entry.get("agent_id") != agent_id:
            return False
        ts = entry.get("timestamp", "")
        if since and ts < since:
            return False
        return not (until and ts > until)
