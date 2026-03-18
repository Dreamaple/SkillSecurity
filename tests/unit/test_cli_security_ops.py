from __future__ import annotations

import json

from click.testing import CliRunner

from skillsecurity.cli.main import cli


class TestSupplychainCommand:
    def test_supplychain_json_output(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["--format", "json", "supplychain", str(tmp_path)],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["sbom"]["component_count"] >= 1


class TestIntelSyncCommand:
    def test_intel_sync_command(self, tmp_path, monkeypatch) -> None:
        out = tmp_path / "intel.json"
        monkeypatch.setattr(
            "skillsecurity.security.intel_sync.sync_openclaw_advisories",
            lambda output_path, limit=100, token=None: {"output": str(output_path), "count": 1},
        )
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["--format", "json", "intel-sync", "--output", str(out), "--limit", "5"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] == 1


class TestMetricsCommand:
    def test_metrics_json_output(self, tmp_path) -> None:
        log = tmp_path / "audit.jsonl"
        log.write_text(
            json.dumps({"decision": {"action": "allow", "severity": "low", "check_duration_ms": 1.0}})
            + "\n",
            encoding="utf-8",
        )
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["--format", "json", "metrics", "--log-path", str(log)],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_checks"] == 1
