"""Tests for framework integration registry and adapters."""

from __future__ import annotations

import pytest

from skillsecurity.integrations._registry import (
    _ADAPTER_MAP,
    _resolve,
    installed_frameworks,
)


class TestRegistry:
    def test_resolve_known_frameworks(self) -> None:
        for name in _ADAPTER_MAP:
            assert _resolve(name) == name

    def test_resolve_aliases(self) -> None:
        assert _resolve("openclaw") == "mcp"
        assert _resolve("llama-index") == "llamaindex"
        assert _resolve("llama_index") == "llamaindex"
        assert _resolve("auto-gen") == "autogen"
        assert _resolve("crew-ai") == "crewai"
        assert _resolve("crew_ai") == "crewai"
        assert _resolve("lang-chain") == "langchain"
        assert _resolve("lang_chain") == "langchain"

    def test_resolve_unknown_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown framework"):
            _resolve("nonexistent-framework")

    def test_installed_frameworks_empty(self) -> None:
        assert isinstance(installed_frameworks(), list)


class TestBaseHelper:
    def test_get_or_create_guard_default(self) -> None:
        from skillsecurity.integrations._base import _get_or_create_guard

        guard = _get_or_create_guard()
        from skillsecurity import SkillGuard

        assert isinstance(guard, SkillGuard)

    def test_get_or_create_guard_passthrough(self) -> None:
        from skillsecurity import SkillGuard
        from skillsecurity.integrations._base import _get_or_create_guard

        g = SkillGuard()
        assert _get_or_create_guard(guard=g) is g


class TestLangChainAdapter:
    def test_infer_tool_type(self) -> None:
        from skillsecurity.integrations.langchain import _infer_tool_type

        assert _infer_tool_type("shell_executor") == "shell"
        assert _infer_tool_type("bash") == "shell"
        assert _infer_tool_type("read_file") == "file.read"
        assert _infer_tool_type("write_file") == "file.write"
        assert _infer_tool_type("http_request") == "network.request"
        assert _infer_tool_type("web_browser") == "browser"
        assert _infer_tool_type("sql_query") == "database"
        assert _infer_tool_type("custom_tool") == "shell"


class TestMCPAdapter:
    def test_tool_map_coverage(self) -> None:
        from skillsecurity.integrations.mcp import _MCP_TOOL_MAP

        assert "bash" in _MCP_TOOL_MAP
        assert "read_file" in _MCP_TOOL_MAP
        assert "write_file" in _MCP_TOOL_MAP
        assert "http_request" in _MCP_TOOL_MAP
        assert "browse" in _MCP_TOOL_MAP
        assert "sql_query" in _MCP_TOOL_MAP
        assert "send_message" in _MCP_TOOL_MAP

    def test_wrap_mcp_handler_blocks(self) -> None:
        import asyncio

        from skillsecurity.integrations.mcp import wrap_mcp_handler

        async def dummy_handler(name: str, arguments: dict | None = None) -> str:
            return "executed"

        secured = wrap_mcp_handler(dummy_handler)

        with pytest.raises(RuntimeError, match="Blocked"):
            asyncio.get_event_loop().run_until_complete(secured("bash", {"command": "rm -rf /"}))

    def test_wrap_mcp_handler_allows(self) -> None:
        import asyncio

        from skillsecurity.integrations.mcp import wrap_mcp_handler

        async def dummy_handler(name: str, arguments: dict | None = None) -> str:
            return "executed"

        secured = wrap_mcp_handler(dummy_handler)
        result = asyncio.get_event_loop().run_until_complete(
            secured("read_file", {"path": "/tmp/readme.txt"})
        )
        assert result == "executed"
