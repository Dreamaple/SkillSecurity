"""Threat-intel sync helpers for OpenClaw advisories."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

_OPENCLAW_ADVISORY_API = (
    "https://api.github.com/repos/openclaw/openclaw/security-advisories?per_page={limit}"
)


def fetch_openclaw_advisories(limit: int = 100, token: str | None = None) -> list[dict[str, Any]]:
    url = _OPENCLAW_ADVISORY_API.format(limit=max(1, min(limit, 100)))
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "skillsecurity-intel-sync",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = Request(url=url, headers=headers, method="GET")
    with urlopen(req, timeout=20) as resp:  # nosec B310 - read-only public API fetch
        raw = resp.read().decode("utf-8")
    data = json.loads(raw)
    if not isinstance(data, list):
        return []
    return [_normalize_advisory(x) for x in data if isinstance(x, dict)]


def sync_openclaw_advisories(
    output_path: str | Path,
    limit: int = 100,
    token: str | None = None,
) -> dict[str, Any]:
    advisories = fetch_openclaw_advisories(limit=limit, token=token)
    payload = {
        "source": "github:openclaw/openclaw",
        "fetched_at": datetime.now(UTC).isoformat(),
        "count": len(advisories),
        "advisories": advisories,
    }
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"output": str(p), "count": len(advisories)}


def _normalize_advisory(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("ghsa_id") or item.get("id") or "",
        "summary": item.get("summary", ""),
        "severity": str(item.get("severity", "unknown")).lower(),
        "published_at": item.get("published_at", ""),
        "updated_at": item.get("updated_at", ""),
        "url": item.get("html_url") or "",
        "cve_id": _extract_cve(item),
    }


def _extract_cve(item: dict[str, Any]) -> str:
    cve = item.get("cve_id")
    if isinstance(cve, str):
        return cve
    ids = item.get("identifiers", [])
    if isinstance(ids, list):
        for i in ids:
            if not isinstance(i, dict):
                continue
            if str(i.get("type", "")).upper() == "CVE":
                return str(i.get("value", ""))
    return ""
