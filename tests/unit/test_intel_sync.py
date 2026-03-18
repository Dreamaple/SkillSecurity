from __future__ import annotations

import json

from skillsecurity.security.intel_sync import fetch_openclaw_advisories, sync_openclaw_advisories


class _FakeResponse:
    def __init__(self, payload: str) -> None:
        self._payload = payload.encode("utf-8")

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TestIntelSync:
    def test_fetch_openclaw_advisories(self, monkeypatch) -> None:
        payload = json.dumps(
            [
                {
                    "ghsa_id": "GHSA-xxxx",
                    "summary": "test advisory",
                    "severity": "high",
                    "published_at": "2026-03-15T00:00:00Z",
                    "updated_at": "2026-03-15T01:00:00Z",
                    "html_url": "https://example.com/advisory",
                    "identifiers": [{"type": "CVE", "value": "CVE-2026-0001"}],
                }
            ]
        )
        monkeypatch.setattr(
            "skillsecurity.security.intel_sync.urlopen",
            lambda req, timeout=20: _FakeResponse(payload),
        )
        advisories = fetch_openclaw_advisories(limit=10)
        assert len(advisories) == 1
        assert advisories[0]["id"] == "GHSA-xxxx"
        assert advisories[0]["cve_id"] == "CVE-2026-0001"

    def test_sync_writes_file(self, tmp_path, monkeypatch) -> None:
        payload = json.dumps(
            [{"ghsa_id": "GHSA-1", "summary": "x", "severity": "low", "html_url": "https://a"}]
        )
        monkeypatch.setattr(
            "skillsecurity.security.intel_sync.urlopen",
            lambda req, timeout=20: _FakeResponse(payload),
        )
        out = tmp_path / "openclaw-advisories.json"
        result = sync_openclaw_advisories(out, limit=5)
        assert result["count"] == 1
        assert out.exists()
