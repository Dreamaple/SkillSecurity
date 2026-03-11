"""Unit tests for static scanner."""
from __future__ import annotations

from pathlib import Path

from skillsecurity.models.report import RiskLevel
from skillsecurity.scanner.analyzer import Analyzer
from skillsecurity.scanner.report import generate_report


class TestAnalyzer:
    def test_scan_dangerous_skill(self):
        analyzer = Analyzer()
        skill_path = Path(__file__).parent.parent / "testdata" / "sample_skills" / "dangerous_skill"
        issues, count = analyzer.scan_directory(skill_path)
        assert count >= 1
        assert len(issues) > 0
        categories = {i.category for i in issues}
        assert "data_exfiltration" in categories or "dynamic_code_execution" in categories

    def test_scan_safe_skill(self):
        analyzer = Analyzer()
        skill_path = Path(__file__).parent.parent / "testdata" / "sample_skills" / "safe_skill"
        issues, count = analyzer.scan_directory(skill_path)
        assert count >= 1
        assert len(issues) == 0

    def test_scan_finds_eval(self):
        analyzer = Analyzer()
        skill_path = Path(__file__).parent.parent / "testdata" / "sample_skills" / "dangerous_skill"
        issues, _ = analyzer.scan_directory(skill_path)
        eval_issues = [i for i in issues if "eval" in i.pattern_id]
        assert len(eval_issues) > 0

    def test_scan_detects_data_exfiltration(self):
        analyzer = Analyzer()
        skill_path = Path(__file__).parent.parent / "testdata" / "sample_skills" / "dangerous_skill"
        issues, _ = analyzer.scan_directory(skill_path)
        exfil = [i for i in issues if i.category == "data_exfiltration"]
        assert len(exfil) > 0
        assert any(i.severity == "critical" for i in exfil)

class TestReportGeneration:
    def test_dangerous_skill_high_risk(self):
        analyzer = Analyzer()
        skill_path = Path(__file__).parent.parent / "testdata" / "sample_skills" / "dangerous_skill"
        issues, count = analyzer.scan_directory(skill_path)
        report = generate_report(str(skill_path), issues, count)
        assert report.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert report.summary.total_issues > 0

    def test_safe_skill_safe_level(self):
        analyzer = Analyzer()
        skill_path = Path(__file__).parent.parent / "testdata" / "sample_skills" / "safe_skill"
        issues, count = analyzer.scan_directory(skill_path)
        report = generate_report(str(skill_path), issues, count)
        assert report.risk_level == RiskLevel.SAFE
        assert report.summary.total_issues == 0

    def test_report_serialization(self):
        analyzer = Analyzer()
        skill_path = Path(__file__).parent.parent / "testdata" / "sample_skills" / "dangerous_skill"
        issues, count = analyzer.scan_directory(skill_path)
        report = generate_report(str(skill_path), issues, count)
        data = report.to_dict()
        assert "risk_level" in data
        assert "issues" in data
        assert "summary" in data
