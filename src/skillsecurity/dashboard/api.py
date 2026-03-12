"""Dashboard API — aggregates stats, logs, and framework status."""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path
from typing import Any

import yaml

_CONFIG_FILE = ".skillsecurity.yaml"
_KNOWN_FRAMEWORKS = {
    "langchain": {
        "name": "LangChain",
        "pip": "langchain-core",
        "import": "langchain_core",
        "detect": "python",
        "skill_dirs": ["tools/", "langchain_tools/"],
    },
    "autogen": {
        "name": "AutoGen",
        "pip": "pyautogen",
        "import": "autogen",
        "detect": "python",
        "skill_dirs": ["skills/", "autogen_skills/"],
    },
    "crewai": {
        "name": "CrewAI",
        "pip": "crewai",
        "import": "crewai",
        "detect": "python",
        "skill_dirs": ["tools/", "crewai_tools/"],
    },
    "llamaindex": {
        "name": "LlamaIndex",
        "pip": "llama-index-core",
        "import": "llama_index",
        "detect": "python",
        "skill_dirs": ["tools/", "llama_tools/"],
    },
    "mcp": {
        "name": "MCP / OpenClaw",
        "pip": "mcp",
        "import": "mcp",
        "detect": "python",
        "skill_dirs": [
            "~/.mcp/servers/",
            "~/.config/mcp/",
            "mcp_servers/",
        ],
    },
    "n8n": {
        "name": "n8n",
        "pip": None,
        "import": None,
        "detect": "cli",
        "cli_name": "n8n",
        "skill_dirs": [
            "~/.n8n/custom/",
            "~/.n8n/nodes/",
        ],
    },
}

_start_time = time.time()


class DashboardAPI:
    def __init__(self, log_path: str = "./logs/skillsecurity-audit.jsonl") -> None:
        self._log_path = Path(log_path)

    def get_stats(self) -> dict[str, Any]:
        """Aggregate stats from audit logs."""
        counts = {"allow": 0, "block": 0, "ask": 0, "total": 0}
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        first_ts = None
        last_ts = None

        if self._log_path.exists():
            for line in self._log_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except (json.JSONDecodeError, TypeError):
                    continue
                decision = entry.get("decision", {})
                act = decision.get("action", "")
                sev = decision.get("severity", "")
                ts = entry.get("timestamp", "")

                counts["total"] += 1
                if act in counts:
                    counts[act] += 1
                if sev in severity_counts:
                    severity_counts[sev] += 1

                if first_ts is None or ts < first_ts:
                    first_ts = ts
                if last_ts is None or ts > last_ts:
                    last_ts = ts

        uptime_seconds = int(time.time() - _start_time)
        hours = uptime_seconds // 3600
        minutes = (uptime_seconds % 3600) // 60

        return {
            "counts": counts,
            "severity": severity_counts,
            "high_risk_blocked": counts["block"] + counts["ask"],
            "first_event": first_ts,
            "last_event": last_ts,
            "uptime": f"{hours}h {minutes}m",
            "uptime_seconds": uptime_seconds,
            "log_file": str(self._log_path),
        }

    def get_recent_logs(self, limit: int = 50, action: str | None = None) -> list[dict[str, Any]]:
        """Return the most recent log entries (newest first)."""
        if not self._log_path.exists():
            return []

        entries: list[dict[str, Any]] = []
        for line in self._log_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if action:
                decision = entry.get("decision", {})
                if decision.get("action") != action:
                    continue
            entries.append(entry)

        entries.reverse()
        return entries[:limit]

    def get_frameworks(self) -> list[dict[str, Any]]:
        """Detect installed frameworks and their protection status."""
        config = self._read_config()
        protected = config.get("auto_protect", [])

        result = []
        for key, meta in _KNOWN_FRAMEWORKS.items():
            installed = self._detect_framework(meta)
            result.append(
                {
                    "id": key,
                    "name": meta["name"],
                    "installed": installed,
                    "protected": key in protected,
                    "pip_package": meta.get("pip"),
                }
            )
        return result

    def get_config(self) -> dict[str, Any]:
        """Return current configuration."""
        config = self._read_config()
        return {
            "auto_protect": config.get("auto_protect", []),
            "policy": config.get("policy_file") or config.get("policy") or "default",
            "config_file": _CONFIG_FILE,
            "config_exists": Path(_CONFIG_FILE).exists(),
        }

    def protect_framework(self, framework: str, policy: str | None = None) -> dict[str, Any]:
        """Enable protection for a framework by directly updating config."""
        if framework not in _KNOWN_FRAMEWORKS:
            return {"ok": False, "error": f"Unknown framework: {framework}"}
        try:
            config = self._read_config()
            auto_protect = config.get("auto_protect", [])
            if framework not in auto_protect:
                auto_protect.append(framework)
            config["auto_protect"] = auto_protect
            if policy:
                config["policy_file"] = policy
            self._write_config(config)
            return {"ok": True, "framework": framework, "action": "protected"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def unprotect_framework(self, framework: str) -> dict[str, Any]:
        """Disable protection for a framework by directly updating config."""
        try:
            config = self._read_config()
            auto_protect = config.get("auto_protect", [])
            if framework in auto_protect:
                auto_protect.remove(framework)
            config["auto_protect"] = auto_protect
            self._write_config(config)
            return {"ok": True, "framework": framework, "action": "unprotected"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def scan_skill(self, skill_path: str) -> dict[str, Any]:
        """Scan a skill directory."""
        if not skill_path or not Path(skill_path).exists():
            return {"ok": False, "error": f"Path not found: {skill_path}"}
        try:
            from skillsecurity import SkillGuard

            guard = SkillGuard()
            report = guard.scan_skill(skill_path)
            return {"ok": True, "path": skill_path, **report}
        except Exception as e:
            return {"ok": False, "error": str(e), "path": skill_path}

    def get_scan_paths(self) -> dict[str, Any]:
        """Return default scan paths for known frameworks."""
        cwd = os.getcwd()
        paths: list[dict[str, Any]] = []

        for key, meta in _KNOWN_FRAMEWORKS.items():
            for sd in meta.get("skill_dirs", []):
                expanded = Path(sd).expanduser()
                if not expanded.is_absolute():
                    expanded = Path(cwd) / expanded
                paths.append(
                    {
                        "framework": key,
                        "name": meta["name"],
                        "path": str(expanded),
                        "exists": expanded.exists(),
                    }
                )

        paths.append(
            {
                "framework": "_cwd",
                "name": "Current Directory",
                "path": cwd,
                "exists": True,
            }
        )

        return {"paths": paths, "cwd": cwd}

    @staticmethod
    def _read_config() -> dict:
        p = Path(_CONFIG_FILE)
        if not p.exists():
            return {}
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def _write_config(config: dict) -> None:
        p = Path(_CONFIG_FILE)
        p.write_text(
            yaml.dump(config, default_flow_style=False, allow_unicode=True), encoding="utf-8"
        )

    @staticmethod
    def _detect_framework(meta: dict) -> bool:
        detect_type = meta.get("detect", "python")
        if detect_type == "python":
            import_name = meta.get("import")
            if not import_name:
                return False
            import importlib.util

            return importlib.util.find_spec(import_name) is not None
        if detect_type == "cli":
            cli_name = meta.get("cli_name", "")
            return shutil.which(cli_name) is not None
        return False
