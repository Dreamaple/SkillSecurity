"""Tests for CLI protect/unprotect/status commands and startup module."""

from __future__ import annotations

import yaml
from click.testing import CliRunner

from skillsecurity.cli.main import cli


class TestProtectCommand:
    def test_protect_creates_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["protect", "langchain"])
        assert result.exit_code == 0
        assert "langchain" in result.output.lower()

        config_path = tmp_path / ".skillsecurity.yaml"
        assert config_path.exists()
        data = yaml.safe_load(config_path.read_text())
        assert "langchain" in data["auto_protect"]

    def test_protect_with_policy(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["protect", "mcp", "--policy", "strict"])
        assert result.exit_code == 0

        data = yaml.safe_load((tmp_path / ".skillsecurity.yaml").read_text())
        assert "mcp" in data["auto_protect"]
        assert data["policy"] == "strict"

    def test_protect_multiple_frameworks(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        runner.invoke(cli, ["protect", "langchain"])
        runner.invoke(cli, ["protect", "mcp"])

        data = yaml.safe_load((tmp_path / ".skillsecurity.yaml").read_text())
        assert "langchain" in data["auto_protect"]
        assert "mcp" in data["auto_protect"]

    def test_protect_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        runner.invoke(cli, ["protect", "langchain"])
        runner.invoke(cli, ["protect", "langchain"])

        data = yaml.safe_load((tmp_path / ".skillsecurity.yaml").read_text())
        assert data["auto_protect"].count("langchain") == 1


class TestUnprotectCommand:
    def test_unprotect_removes_framework(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        runner.invoke(cli, ["protect", "langchain"])
        runner.invoke(cli, ["protect", "mcp"])

        result = runner.invoke(cli, ["unprotect", "langchain"])
        assert result.exit_code == 0
        assert "langchain" in result.output.lower()

        data = yaml.safe_load((tmp_path / ".skillsecurity.yaml").read_text())
        assert "langchain" not in data["auto_protect"]
        assert "mcp" in data["auto_protect"]

    def test_unprotect_last_removes_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        runner.invoke(cli, ["protect", "langchain"])
        runner.invoke(cli, ["unprotect", "langchain"])

        assert not (tmp_path / ".skillsecurity.yaml").exists()

    def test_unprotect_all(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        runner.invoke(cli, ["protect", "langchain"])
        runner.invoke(cli, ["protect", "mcp"])
        result = runner.invoke(cli, ["unprotect", "all"])
        assert result.exit_code == 0
        assert not (tmp_path / ".skillsecurity.yaml").exists()


class TestStatusCommand:
    def test_status_empty(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0
        assert "no frameworks" in result.output.lower() or "get started" in result.output.lower()

    def test_status_with_protected(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        runner.invoke(cli, ["protect", "langchain"])
        result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0
        assert "langchain" in result.output.lower()


class TestStartupModule:
    def test_startup_with_no_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        import importlib

        import skillsecurity.startup

        importlib.reload(skillsecurity.startup)

    def test_startup_with_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config = {"auto_protect": []}
        (tmp_path / ".skillsecurity.yaml").write_text(yaml.dump(config))
        monkeypatch.setenv("SKILLSECURITY_CONFIG", str(tmp_path / ".skillsecurity.yaml"))

        import importlib

        import skillsecurity.startup

        importlib.reload(skillsecurity.startup)

    def test_startup_with_invalid_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".skillsecurity.yaml").write_text("not valid yaml [[[")
        monkeypatch.setenv("SKILLSECURITY_CONFIG", str(tmp_path / ".skillsecurity.yaml"))

        import importlib

        import skillsecurity.startup

        importlib.reload(skillsecurity.startup)
