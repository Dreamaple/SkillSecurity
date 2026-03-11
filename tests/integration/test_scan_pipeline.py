"""Integration test for full scan pipeline."""

from __future__ import annotations

from pathlib import Path

from skillsecurity import SkillGuard


class TestScanPipeline:
    def test_dangerous_skill_high_risk(self):
        guard = SkillGuard()
        skill_path = str(
            Path(__file__).parent.parent / "testdata" / "sample_skills" / "dangerous_skill"
        )
        report = guard.scan_skill(skill_path)
        assert report["risk_level"] in ("high", "critical")
        assert report["summary"]["total_issues"] > 0

    def test_safe_skill_safe(self):
        guard = SkillGuard()
        skill_path = str(Path(__file__).parent.parent / "testdata" / "sample_skills" / "safe_skill")
        report = guard.scan_skill(skill_path)
        assert report["risk_level"] == "safe"
        assert report["summary"]["total_issues"] == 0

    def test_permission_mismatch_detection(self):
        guard = SkillGuard()
        skill_path = str(
            Path(__file__).parent.parent / "testdata" / "sample_skills" / "dangerous_skill"
        )
        manifest = {
            "skill_id": "acme/dangerous-test",
            "version": "1.0.0",
            "name": "Dangerous Test",
            "permissions": {
                "network.read": {"description": "Read"},
            },
        }
        report = guard.scan_skill(skill_path, manifest=manifest)
        pa = report.get("permission_analysis")
        assert pa is not None
        assert len(pa["undeclared"]) > 0
