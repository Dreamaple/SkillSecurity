"""Central registry for framework integration install / uninstall lifecycle."""

from __future__ import annotations

from typing import Any

_ADAPTER_MAP: dict[str, str] = {
    "langchain": "skillsecurity.integrations.langchain",
    "autogen": "skillsecurity.integrations.autogen",
    "crewai": "skillsecurity.integrations.crewai",
    "llamaindex": "skillsecurity.integrations.llamaindex",
    "mcp": "skillsecurity.integrations.mcp",
    "n8n": "skillsecurity.integrations.n8n",
}

_ALIASES: dict[str, str] = {
    "openclaw": "mcp",
    "openai-mcp": "mcp",
    "llama_index": "llamaindex",
    "llama-index": "llamaindex",
    "auto-gen": "autogen",
    "crew-ai": "crewai",
    "crew_ai": "crewai",
    "lang-chain": "langchain",
    "lang_chain": "langchain",
}

_installed: dict[str, Any] = {}


def _resolve(name: str) -> str:
    key = name.lower().replace(" ", "").replace("-", "").replace("_", "")
    for alias, canonical in _ALIASES.items():
        if key == alias.replace("-", "").replace("_", ""):
            return canonical
    if key in _ADAPTER_MAP:
        return key
    raise ValueError(
        f"Unknown framework '{name}'. Supported: {', '.join(sorted(_ADAPTER_MAP))}. "
        f"Aliases: {', '.join(sorted(_ALIASES))}."
    )


def install(framework: str, **kwargs: Any) -> None:
    """Install SkillSecurity protection into a framework.

    Usage:
        import skillsecurity.integrations
        skillsecurity.integrations.install("langchain")
        skillsecurity.integrations.install("mcp", guard=my_guard)

    Args:
        framework: Framework name (langchain, autogen, crewai, llamaindex, mcp, n8n).
        **kwargs: Passed to the adapter's install() function (e.g. guard=, policy_file=).
    """
    key = _resolve(framework)
    if key in _installed:
        return

    import importlib

    module = importlib.import_module(_ADAPTER_MAP[key])
    module.install(**kwargs)  # type: ignore[attr-defined]
    _installed[key] = module


def uninstall(framework: str) -> None:
    """Remove SkillSecurity protection from a framework, restoring original behavior."""
    key = _resolve(framework)
    module = _installed.pop(key, None)
    if module is not None:
        module.uninstall()  # type: ignore[attr-defined]


def uninstall_all() -> None:
    """Remove SkillSecurity from all installed frameworks."""
    for key in list(_installed):
        module = _installed.pop(key)
        module.uninstall()  # type: ignore[attr-defined]


def installed_frameworks() -> list[str]:
    """Return list of currently protected framework names."""
    return list(_installed)
