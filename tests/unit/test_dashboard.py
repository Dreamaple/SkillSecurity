"""Tests for the SkillSecurity Dashboard API and Server."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from skillsecurity.dashboard.api import DashboardAPI


def _make_log_file(entries: list[dict]) -> Path:
    f = Path(tempfile.mktemp(suffix=".jsonl"))
    f.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")
    return f


def _entry(
    action: str = "allow",
    severity: str = "low",
    reason: str = "test",
    ts: str = "2026-03-01T10:00:00",
) -> dict:
    return {
        "timestamp": ts,
        "agent_id": "agent-1",
        "decision": {"action": action, "severity": severity, "reason": reason},
        "tool_call": {"name": "test_tool"},
    }


class TestDashboardAPIStats:
    def test_empty_log(self, tmp_path: Path) -> None:
        api = DashboardAPI(log_path=str(tmp_path / "nope.jsonl"))
        stats = api.get_stats()
        assert stats["counts"]["total"] == 0
        assert stats["high_risk_blocked"] == 0
        assert stats["first_event"] is None

    def test_counts(self, tmp_path: Path) -> None:
        log = _make_log_file(
            [
                _entry("allow"),
                _entry("allow"),
                _entry("block", severity="high"),
                _entry("ask", severity="medium"),
            ]
        )
        api = DashboardAPI(log_path=str(log))
        stats = api.get_stats()
        assert stats["counts"]["total"] == 4
        assert stats["counts"]["allow"] == 2
        assert stats["counts"]["block"] == 1
        assert stats["counts"]["ask"] == 1
        assert stats["high_risk_blocked"] == 2

    def test_severity_counts(self, tmp_path: Path) -> None:
        log = _make_log_file(
            [
                _entry(severity="low"),
                _entry(severity="medium"),
                _entry(severity="high"),
                _entry(severity="critical"),
            ]
        )
        api = DashboardAPI(log_path=str(log))
        stats = api.get_stats()
        assert stats["severity"]["low"] == 1
        assert stats["severity"]["critical"] == 1

    def test_uptime_format(self, tmp_path: Path) -> None:
        api = DashboardAPI(log_path=str(tmp_path / "nope.jsonl"))
        stats = api.get_stats()
        assert "h" in stats["uptime"]
        assert "m" in stats["uptime"]


class TestDashboardAPILogs:
    def test_recent_logs_order(self) -> None:
        log = _make_log_file(
            [
                _entry(ts="2026-03-01T10:00:00"),
                _entry(ts="2026-03-01T11:00:00"),
                _entry(ts="2026-03-01T12:00:00"),
            ]
        )
        api = DashboardAPI(log_path=str(log))
        logs = api.get_recent_logs(limit=10)
        assert len(logs) == 3
        assert logs[0]["timestamp"] == "2026-03-01T12:00:00"

    def test_filter_by_action(self) -> None:
        log = _make_log_file(
            [
                _entry("allow"),
                _entry("block"),
                _entry("allow"),
            ]
        )
        api = DashboardAPI(log_path=str(log))
        blocked = api.get_recent_logs(action="block")
        assert len(blocked) == 1
        assert blocked[0]["decision"]["action"] == "block"

    def test_limit(self) -> None:
        log = _make_log_file([_entry() for _ in range(20)])
        api = DashboardAPI(log_path=str(log))
        logs = api.get_recent_logs(limit=5)
        assert len(logs) == 5

    def test_empty(self, tmp_path: Path) -> None:
        api = DashboardAPI(log_path=str(tmp_path / "nope.jsonl"))
        assert api.get_recent_logs() == []


class TestDashboardAPIFrameworks:
    def test_returns_all_known_frameworks(self) -> None:
        api = DashboardAPI()
        frameworks = api.get_frameworks()
        ids = [f["id"] for f in frameworks]
        assert "langchain" in ids
        assert "mcp" in ids

    def test_protection_status_from_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config_path = tmp_path / ".skillsecurity.yaml"
        config_path.write_text("auto_protect:\n  - langchain\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        api = DashboardAPI()
        frameworks = api.get_frameworks()
        lc = next(f for f in frameworks if f["id"] == "langchain")
        assert lc["protected"] is True


class TestDashboardAPIConfig:
    def test_no_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        api = DashboardAPI()
        config = api.get_config()
        assert config["config_exists"] is False
        assert config["auto_protect"] == []

    def test_with_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config_path = tmp_path / ".skillsecurity.yaml"
        config_path.write_text(
            "auto_protect:\n  - mcp\npolicy_file: custom.yaml\n", encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        api = DashboardAPI()
        config = api.get_config()
        assert config["config_exists"] is True
        assert "mcp" in config["auto_protect"]
        assert config["policy"] == "custom.yaml"


class TestDashboardAPIProtect:
    def test_unknown_framework(self) -> None:
        api = DashboardAPI()
        result = api.protect_framework("nonexistent")
        assert result["ok"] is False

    def test_protect_writes_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        api = DashboardAPI()
        result = api.protect_framework("langchain")
        assert result["ok"] is True
        assert result["action"] == "protected"
        config = api._read_config()
        assert "langchain" in config["auto_protect"]

    def test_protect_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        api = DashboardAPI()
        api.protect_framework("langchain")
        api.protect_framework("langchain")
        config = api._read_config()
        assert config["auto_protect"].count("langchain") == 1

    def test_unprotect_removes_from_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        api = DashboardAPI()
        api.protect_framework("langchain")
        api.protect_framework("mcp")
        result = api.unprotect_framework("langchain")
        assert result["ok"] is True
        config = api._read_config()
        assert "langchain" not in config["auto_protect"]
        assert "mcp" in config["auto_protect"]

    def test_unprotect_missing_is_ok(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        api = DashboardAPI()
        result = api.unprotect_framework("crewai")
        assert result["ok"] is True

    def test_protect_then_get_frameworks_shows_protected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        api = DashboardAPI()
        api.protect_framework("mcp")
        frameworks = api.get_frameworks()
        mcp = next(f for f in frameworks if f["id"] == "mcp")
        assert mcp["protected"] is True


class TestDashboardAPIScan:
    def test_invalid_path(self) -> None:
        api = DashboardAPI()
        result = api.scan_skill("/nonexistent/path")
        assert result["ok"] is False

    def test_empty_path(self) -> None:
        api = DashboardAPI()
        result = api.scan_skill("")
        assert result["ok"] is False


class TestDashboardAPIScanPaths:
    def test_returns_paths_list(self) -> None:
        api = DashboardAPI()
        data = api.get_scan_paths()
        assert "paths" in data
        assert "cwd" in data
        assert isinstance(data["paths"], list)
        assert len(data["paths"]) > 0

    def test_includes_cwd_entry(self) -> None:
        api = DashboardAPI()
        data = api.get_scan_paths()
        cwd_entries = [p for p in data["paths"] if p["framework"] == "_cwd"]
        assert len(cwd_entries) == 1
        assert cwd_entries[0]["exists"] is True

    def test_each_path_has_required_fields(self) -> None:
        api = DashboardAPI()
        data = api.get_scan_paths()
        for p in data["paths"]:
            assert "framework" in p
            assert "name" in p
            assert "path" in p
            assert "exists" in p

    def test_includes_mcp_paths(self) -> None:
        api = DashboardAPI()
        data = api.get_scan_paths()
        mcp_paths = [p for p in data["paths"] if p["framework"] == "mcp"]
        assert len(mcp_paths) >= 1

    def test_includes_n8n_paths(self) -> None:
        api = DashboardAPI()
        data = api.get_scan_paths()
        n8n_paths = [p for p in data["paths"] if p["framework"] == "n8n"]
        assert len(n8n_paths) >= 1


class TestDashboardAPIDetection:
    def test_n8n_detection_uses_which(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import shutil

        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/n8n" if name == "n8n" else None)
        api = DashboardAPI()
        frameworks = api.get_frameworks()
        n8n = next(f for f in frameworks if f["id"] == "n8n")
        assert n8n["installed"] is True

    def test_n8n_not_detected_when_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import shutil

        monkeypatch.setattr(shutil, "which", lambda name: None)
        api = DashboardAPI()
        frameworks = api.get_frameworks()
        n8n = next(f for f in frameworks if f["id"] == "n8n")
        assert n8n["installed"] is False

    def test_python_framework_detection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import importlib.util

        original = importlib.util.find_spec
        monkeypatch.setattr(
            importlib.util,
            "find_spec",
            lambda name: type("Spec", (), {})() if name == "langchain_core" else original(name),
        )
        api = DashboardAPI()
        frameworks = api.get_frameworks()
        lc = next(f for f in frameworks if f["id"] == "langchain")
        assert lc["installed"] is True


class TestDashboardServer:
    def test_static_file_exists(self) -> None:
        static_dir = (
            Path(__file__).parent.parent.parent / "src" / "skillsecurity" / "dashboard" / "static"
        )
        assert (static_dir / "index.html").exists()

    def test_handler_class_creation(self) -> None:
        from skillsecurity.dashboard.server import _DashboardHandler

        api = DashboardAPI()
        handler_cls = type("Handler", (_DashboardHandler,), {"api": api})
        assert hasattr(handler_cls, "api")
        assert handler_cls.api is api
