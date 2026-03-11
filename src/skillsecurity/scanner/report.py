"""Scan report generation with risk level calculation."""

from __future__ import annotations

from skillsecurity.manifest.permissions import SkillManifest
from skillsecurity.models.report import (
    PermissionAnalysis,
    RiskLevel,
    ScanIssue,
    ScanReport,
    ScanSummary,
)
from skillsecurity.scanner.patterns import ALL_PATTERNS

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def generate_report(
    skill_path: str,
    issues: list[ScanIssue],
    total_files: int,
    manifest: SkillManifest | None = None,
) -> ScanReport:
    summary = ScanSummary(
        total_files=total_files,
        total_issues=len(issues),
    )
    for issue in issues:
        sev = issue.severity.lower()
        if sev == "critical":
            summary.critical += 1
        elif sev == "high":
            summary.high += 1
        elif sev == "medium":
            summary.medium += 1
        elif sev == "low":
            summary.low += 1

    risk_level = _calculate_risk_level(summary)

    perm_analysis = None
    if manifest:
        perm_analysis = _analyze_permissions(issues, manifest)

    recommendation = _generate_recommendation(risk_level, summary, perm_analysis)

    return ScanReport(
        skill_path=skill_path,
        risk_level=risk_level,
        issues=issues,
        summary=summary,
        permission_analysis=perm_analysis,
        recommendation=recommendation,
    )


def _calculate_risk_level(summary: ScanSummary) -> RiskLevel:
    if summary.critical > 0:
        return RiskLevel.CRITICAL
    if summary.high > 0:
        return RiskLevel.HIGH
    if summary.medium > 0:
        return RiskLevel.MEDIUM
    if summary.low > 0:
        return RiskLevel.LOW
    return RiskLevel.SAFE


def _analyze_permissions(issues: list[ScanIssue], manifest: SkillManifest) -> PermissionAnalysis:
    declared = list(manifest.permissions.keys())
    detected_set: set[str] = set()
    for issue in issues:
        for p in ALL_PATTERNS:
            if p.id == issue.pattern_id and p.detected_permission:
                detected_set.add(p.detected_permission)
    detected = sorted(detected_set)
    undeclared = sorted(d for d in detected if d not in declared)
    unused = sorted(d for d in declared if d not in detected)
    return PermissionAnalysis(
        declared=declared,
        detected=detected,
        undeclared=undeclared,
        unused=unused,
    )


def _generate_recommendation(
    risk_level: RiskLevel, summary: ScanSummary, perm_analysis: PermissionAnalysis | None
) -> str:
    if risk_level == RiskLevel.SAFE:
        return "No dangerous patterns detected. The Skill appears safe to use."
    parts = []
    if risk_level == RiskLevel.CRITICAL:
        parts.append(
            "CRITICAL: This Skill contains potentially dangerous code. Do NOT install without thorough review."
        )
    elif risk_level == RiskLevel.HIGH:
        parts.append("HIGH RISK: This Skill uses patterns that could compromise system security.")
    elif risk_level == RiskLevel.MEDIUM:
        parts.append(
            "MEDIUM RISK: This Skill accesses sensitive resources. Review before installing."
        )
    else:
        parts.append("LOW RISK: Minor concerns detected.")

    if summary.critical > 0:
        parts.append(f"  - {summary.critical} critical issue(s) found")
    if summary.high > 0:
        parts.append(f"  - {summary.high} high severity issue(s)")

    if perm_analysis and perm_analysis.undeclared:
        parts.append(f"  - Undeclared permissions detected: {', '.join(perm_analysis.undeclared)}")

    return "\n".join(parts)
