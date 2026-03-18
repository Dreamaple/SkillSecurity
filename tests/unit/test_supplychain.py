from __future__ import annotations

import json

from skillsecurity.supplychain.analyzer import analyze_supply_chain, scan_components


class TestSupplyChainAnalyzer:
    def test_scan_components_from_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.32.0\nclick>=8.1\n", encoding="utf-8")
        components = scan_components(tmp_path)
        names = {(c.ecosystem, c.name) for c in components}
        assert ("pypi", "requests") in names
        assert ("pypi", "click") in names

    def test_analyze_with_vuln_feed(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
        feed = tmp_path / "feed.json"
        feed.write_text(
            json.dumps(
                {
                    "advisories": [
                        {
                            "id": "TEST-1",
                            "ecosystem": "pypi",
                            "package": "requests",
                            "affected_versions": ["==2.32.0"],
                            "severity": "high",
                            "summary": "test vuln",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        report = analyze_supply_chain(tmp_path, vuln_feed_file=feed)
        assert report["risk_level"] in {"high", "critical"}
        assert len(report["vulnerability_findings"]) == 1

    def test_source_allowlist_finding(self, tmp_path):
        manifest = tmp_path / "skill-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "skill_id": "acme/demo",
                    "version": "1.0.0",
                    "name": "Demo",
                    "repository": "https://evil.example.com/repo",
                }
            ),
            encoding="utf-8",
        )
        report = analyze_supply_chain(tmp_path, allowed_domains=["github.com"])
        assert len(report["source_allowlist_findings"]) == 1
