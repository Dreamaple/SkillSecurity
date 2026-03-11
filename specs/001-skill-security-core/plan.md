# Implementation Plan: SkillSecurity Core

**Branch**: `001-skill-security-core` | **Date**: 2026-03-11 | **Spec**: [spec.md](spec.md)  
**Input**: Feature specification from `/specs/001-skill-security-core/spec.md`

## Summary

SkillSecurity is a security protection layer for AI Agent Skill/tool calls — a "Skill antivirus" providing runtime interception, policy-based decisions, permission declaration, static scanning, and audit logging. The system intercepts tool calls before execution, evaluates them against configurable YAML policies and Skill permission manifests, produces Allow/Block/Ask decisions with actionable feedback, and logs all activity for audit. Phase 1 delivers the core interception engine + policy + decisions + CLI. Phase 2 adds Skill permissions, static scanning, and audit logs.

## Technical Context

**Language/Version**: Python 3.11+ (core engine), with performance-critical paths upgradeable to Rust via PyO3 if needed  
**Primary Dependencies**: PyYAML (policy parsing), `re` / `regex` (pattern matching), `watchdog` (file monitoring), `click` (CLI)  
**Storage**: JSONL files (audit logs), YAML files (policies), JSON files (manifests) — no database required  
**Testing**: pytest + pytest-cov + hypothesis (property-based testing for regex patterns)  
**Target Platform**: Cross-platform — Linux, macOS, Windows  
**Project Type**: Library (embeddable SDK) + CLI tool  
**Performance Goals**: <10ms avg / <50ms P99 per check, ≥1000 checks/sec single-threaded  
**Constraints**: <50MB memory for policy engine, zero external network dependencies at runtime, fail-close by default  
**Scale/Scope**: 1000+ rules without degradation, 100K+ audit log entries queryable in <5s

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Constitution file is a blank template (no project-specific gates defined yet). Proceeding with industry-standard quality gates:

| Gate | Status | Notes |
|------|--------|-------|
| Independent testability | PASS | Each module (engine, scanner, audit, manifest) is independently testable |
| CLI text I/O | PASS | All output to stdout/stderr, supports JSON + human-readable |
| Minimal dependencies | PASS | 4 runtime deps, all well-maintained |
| Test coverage ≥80% | PLANNED | pytest-cov configured from start |

## Project Structure

### Documentation (this feature)

```text
specs/001-skill-security-core/
├── plan.md              # This file
├── spec.md              # Feature specification
├── research.md          # Phase 0: technology decisions
├── data-model.md        # Phase 1: entity definitions
├── quickstart.md        # Phase 1: developer getting started
├── contracts/           # Phase 1: public API contracts
│   ├── python-api.md    # Python SDK public interface
│   ├── cli-interface.md # CLI commands and output format
│   ├── policy-schema.md # YAML policy file schema
│   └── manifest-schema.md # skill-manifest.json schema
└── checklists/
    └── requirements.md  # Spec quality checklist
```

### Source Code (repository root)

```text
src/skillsecurity/
├── __init__.py              # Public API: SkillGuard
├── engine/
│   ├── __init__.py
│   ├── interceptor.py       # Tool call interception entry point
│   ├── policy.py            # Policy loading, parsing, hot-reload
│   ├── matcher.py           # Rule matching engine (regex, paths, rates)
│   └── decision.py          # Decision logic: Allow/Block/Ask
├── scanner/
│   ├── __init__.py
│   ├── analyzer.py          # Static code analysis engine
│   ├── patterns.py          # Dangerous pattern definitions
│   └── report.py            # Scan report generation
├── manifest/
│   ├── __init__.py
│   ├── parser.py            # skill-manifest.json parsing
│   ├── permissions.py       # Permission types and matching
│   └── namespace.py         # author/skill-name validation
├── audit/
│   ├── __init__.py
│   ├── logger.py            # Async JSONL log writer
│   ├── redactor.py          # Sensitive data redaction
│   ├── rotation.py          # Log file rotation
│   └── query.py             # Log querying and filtering
├── config/
│   ├── __init__.py
│   ├── loader.py            # YAML config loading + validation
│   ├── watcher.py           # File system watching for hot-reload
│   └── defaults.py          # Built-in default policy
├── selfprotect/
│   ├── __init__.py
│   └── guard.py             # Immutable path protection
├── cli/
│   ├── __init__.py
│   ├── main.py              # CLI entry point (click)
│   ├── formatter.py         # Terminal output formatting
│   └── prompter.py          # Ask confirmation prompting
└── models/
    ├── __init__.py
    ├── tool_call.py          # ToolCall dataclass
    ├── decision.py           # Decision dataclass
    ├── rule.py               # Rule dataclass
    └── report.py             # ScanReport dataclass

policies/
├── default.yaml              # Default policy (Unix + Windows)
├── strict.yaml               # Strict mode
├── development.yaml          # Development mode (relaxed)
└── scan-rules.yaml           # Static scanner patterns

tests/
├── conftest.py               # Shared fixtures
├── unit/
│   ├── test_matcher.py
│   ├── test_policy.py
│   ├── test_decision.py
│   ├── test_scanner.py
│   ├── test_manifest.py
│   ├── test_redactor.py
│   ├── test_selfprotect.py
│   └── test_namespace.py
├── integration/
│   ├── test_engine_e2e.py    # Full check pipeline
│   ├── test_hot_reload.py
│   ├── test_audit_pipeline.py
│   └── test_scan_pipeline.py
└── testdata/
    ├── dangerous_commands.yaml  # Known-dangerous test patterns
    ├── safe_commands.yaml       # Known-safe test patterns
    ├── sample_skills/           # Test Skill directories
    └── sample_manifests/        # Test manifest files

pyproject.toml                 # Project metadata + dependencies
```

**Structure Decision**: Single Python package (`skillsecurity`) structured as a library with CLI entry point. Modules are organized by domain responsibility (engine, scanner, manifest, audit) to support independent development and testing. No frontend/backend split needed — this is a pure library + CLI project.

## Complexity Tracking

No constitution violations to justify — structure follows single-project library pattern.
