# Contributing to SkillSecurity

Thank you for your interest in contributing to SkillSecurity! This document provides guidelines for contributing to the project.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/Dreamaple/SkillSecurity.git
cd SkillSecurity

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate     # Windows

# Install in development mode
pip install -e ".[dev]"

# Verify setup
pytest
ruff check src/ tests/
```

## Development Workflow

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b feature/my-feature`
3. **Write tests first** (TDD approach) — ensure they fail before implementation
4. **Implement** your changes
5. **Run the test suite**: `pytest --cov=skillsecurity`
6. **Run the linter**: `ruff check src/ tests/`
7. **Commit** with clear messages
8. **Open a Pull Request**

## Code Standards

- **Python 3.11+** — use modern syntax (type hints, `match`, `StrEnum`, etc.)
- **Ruff** for linting and formatting — `ruff check` and `ruff format`
- **Test coverage** must stay above 80%
- **No unnecessary comments** — code should be self-documenting
- **Type hints** on all public functions and methods

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=skillsecurity --cov-report=term-missing

# Run specific test file
pytest tests/unit/test_matcher.py

# Run specific test
pytest tests/unit/test_matcher.py::TestCommandPatternMatching::test_match_command_pattern_blocks_dangerous
```

## Project Structure

```
src/skillsecurity/        # Source code
├── models/               # Data models (dataclasses)
├── engine/               # Core interception engine
├── config/               # Configuration and policy loading
├── manifest/             # Skill permission manifests
├── scanner/              # Static code analysis
├── audit/                # Audit logging
├── selfprotect/          # Self-protection mechanism
└── cli/                  # CLI commands

tests/                    # Test suite
├── unit/                 # Unit tests
├── integration/          # Integration tests
├── testdata/             # Test fixtures and sample data
└── conftest.py           # Shared pytest fixtures

policies/                 # Built-in policy templates
```

## Adding a New Security Rule

1. Add the rule to the appropriate policy file in `policies/`
2. Add test cases in `tests/testdata/dangerous_commands.yaml` or `safe_commands.yaml`
3. Run the integration tests to verify

## Adding a New Scanner Pattern

1. Add the pattern to `src/skillsecurity/scanner/patterns.py`
2. Add a test sample in `tests/testdata/sample_skills/`
3. Add unit tests in `tests/unit/test_scanner.py`

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include Python version, OS, and SkillSecurity version
- For security vulnerabilities, please email security@skillsecurity.dev instead of opening a public issue

## Code of Conduct

Be respectful and constructive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
