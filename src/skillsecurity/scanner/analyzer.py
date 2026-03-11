"""Static code analysis engine: file traversal and per-file regex matching."""

from __future__ import annotations

from pathlib import Path

from skillsecurity.models.report import ScanIssue
from skillsecurity.scanner.patterns import LANGUAGE_EXTENSIONS, get_patterns_for_language

SKIP_DIRS = {
    "__pycache__",
    ".git",
    "node_modules",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    "dist",
    "build",
    ".eggs",
}


class Analyzer:
    def scan_directory(self, directory: str | Path) -> tuple[list[ScanIssue], int]:
        directory = Path(directory)
        issues: list[ScanIssue] = []
        file_count = 0
        for path in self._iter_files(directory):
            file_count += 1
            file_issues = self.scan_file(path)
            issues.extend(file_issues)
        return issues, file_count

    def scan_file(self, path: Path) -> list[ScanIssue]:
        language = LANGUAGE_EXTENSIONS.get(path.suffix)
        if not language:
            return []
        patterns = get_patterns_for_language(language)
        if not patterns:
            return []
        issues: list[ScanIssue] = []
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        for line_num, line_text in enumerate(lines, 1):
            stripped = line_text.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for pattern in patterns:
                if pattern.pattern.search(line_text):
                    issues.append(
                        ScanIssue(
                            file=str(path),
                            line=line_num,
                            pattern_id=pattern.id,
                            category=pattern.category,
                            severity=pattern.severity,
                            description=pattern.description,
                            code_snippet=line_text.strip()[:200],
                        )
                    )
        return issues

    @staticmethod
    def _iter_files(directory: Path):
        for item in directory.rglob("*"):
            if any(skip in item.parts for skip in SKIP_DIRS):
                continue
            if item.is_file() and item.suffix in LANGUAGE_EXTENSIONS:
                yield item
