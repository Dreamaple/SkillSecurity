from __future__ import annotations

import json

from skillsecurity.metrics.analyzer import MetricsInputs, analyze_metrics


class TestMetricsAnalyzer:
    def test_basic_metrics(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        entries = [
            {
                "decision": {
                    "action": "allow",
                    "severity": "low",
                    "check_duration_ms": 1.2,
                    "rule_matched": None,
                }
            },
            {
                "decision": {
                    "action": "block",
                    "severity": "high",
                    "check_duration_ms": 3.4,
                    "rule_matched": {"id": "rule-a"},
                }
            },
            {
                "decision": {
                    "action": "ask",
                    "severity": "medium",
                    "check_duration_ms": 2.5,
                    "rule_matched": {"id": "rule-a"},
                }
            },
        ]
        log.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")
        result = analyze_metrics(MetricsInputs(log_path=str(log)))
        assert result["total_checks"] == 3
        assert result["action_counts"]["block"] == 1
        assert result["top_rules"][0]["id"] == "rule-a"

    def test_optional_rates(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text("", encoding="utf-8")

        feedback = tmp_path / "feedback.json"
        feedback.write_text(
            json.dumps([{"label": "false_positive"}, {"is_false_positive": False}]), encoding="utf-8"
        )

        incidents = tmp_path / "incidents.json"
        incidents.write_text(json.dumps([{"detected": True}, {"detected": False}]), encoding="utf-8")

        remediation = tmp_path / "remediation.json"
        remediation.write_text(
            json.dumps(
                [
                    {
                        "discovered_at": "2026-03-15T00:00:00Z",
                        "resolved_at": "2026-03-15T12:00:00Z",
                    }
                ]
            ),
            encoding="utf-8",
        )

        result = analyze_metrics(
            MetricsInputs(
                log_path=str(log),
                feedback_file=str(feedback),
                incidents_file=str(incidents),
                remediation_file=str(remediation),
            )
        )
        assert result["false_positive_rate"] == 0.5
        assert result["bypass_rate"] == 0.5
        assert result["remediation_sla_hours"] == 12.0
