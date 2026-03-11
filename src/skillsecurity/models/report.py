"""Scan report data models."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class RiskLevel(enum.StrEnum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanIssue:
    file: str
    line: int
    pattern_id: str
    category: str
    severity: str
    description: str
    code_snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "pattern_id": self.pattern_id,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "code_snippet": self.code_snippet,
        }


@dataclass
class PermissionAnalysis:
    declared: list[str] = field(default_factory=list)
    detected: list[str] = field(default_factory=list)
    undeclared: list[str] = field(default_factory=list)
    unused: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "declared": self.declared,
            "detected": self.detected,
            "undeclared": self.undeclared,
            "unused": self.unused,
        }


@dataclass
class ScanSummary:
    total_files: int = 0
    total_issues: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_files": self.total_files,
            "total_issues": self.total_issues,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
        }


@dataclass
class ScanReport:
    skill_path: str
    risk_level: RiskLevel = RiskLevel.SAFE
    issues: list[ScanIssue] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)
    permission_analysis: PermissionAnalysis | None = None
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "skill_path": self.skill_path,
            "risk_level": self.risk_level.value,
            "issues": [i.to_dict() for i in self.issues],
            "summary": self.summary.to_dict(),
            "recommendation": self.recommendation,
        }
        if self.permission_analysis:
            result["permission_analysis"] = self.permission_analysis.to_dict()
        return result
