"""Rule effectiveness and operational metrics from audit logs."""

from __future__ import annotations

import json
import statistics
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class MetricsInputs:
    log_path: str
    feedback_file: str | None = None
    incidents_file: str | None = None
    remediation_file: str | None = None
    regression_report: str | None = None


def analyze_metrics(inputs: MetricsInputs) -> dict[str, Any]:
    entries = _load_jsonl(inputs.log_path)
    decisions = [e.get("decision", {}) for e in entries if isinstance(e, dict)]
    action_counts = {"allow": 0, "block": 0, "ask": 0}
    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    durations: list[float] = []
    rule_counts: dict[str, int] = {}

    for d in decisions:
        action = str(d.get("action", "")).lower()
        severity = str(d.get("severity", "")).lower()
        if action in action_counts:
            action_counts[action] += 1
        if severity in severity_counts:
            severity_counts[severity] += 1
        duration = d.get("check_duration_ms")
        if isinstance(duration, (int, float)):
            durations.append(float(duration))
        rule_ref = d.get("rule_matched")
        if isinstance(rule_ref, dict):
            rid = str(rule_ref.get("id", "")).strip()
            if rid:
                rule_counts[rid] = rule_counts.get(rid, 0) + 1

    total = sum(action_counts.values())
    top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    result: dict[str, Any] = {
        "total_checks": total,
        "action_counts": action_counts,
        "severity_counts": severity_counts,
        "block_rate": _safe_div(action_counts["block"], total),
        "ask_rate": _safe_div(action_counts["ask"], total),
        "allow_rate": _safe_div(action_counts["allow"], total),
        "avg_check_duration_ms": round(statistics.fmean(durations), 3) if durations else 0.0,
        "p95_check_duration_ms": _percentile(durations, 95),
        "top_rules": [{"id": rid, "count": cnt} for rid, cnt in top_rules],
    }

    result["false_positive_rate"] = _false_positive_rate(inputs.feedback_file)
    result["bypass_rate"] = _bypass_rate(inputs.incidents_file)
    result["remediation_sla_hours"] = _remediation_sla(inputs.remediation_file)
    result["regression_coverage"] = _regression_coverage(inputs.regression_report)
    return result


def _load_jsonl(path: str) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def _safe_div(a: int, b: int) -> float:
    if b <= 0:
        return 0.0
    return round(a / b, 4)


def _percentile(values: list[float], p: int) -> float:
    if not values:
        return 0.0
    vals = sorted(values)
    idx = max(0, min(len(vals) - 1, int(round((p / 100) * (len(vals) - 1)))))
    return round(vals[idx], 3)


def _false_positive_rate(path: str | None) -> float | None:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, list):
        return None
    reviewed = 0
    false_pos = 0
    for item in data:
        if not isinstance(item, dict):
            continue
        reviewed += 1
        label = item.get("label")
        is_fp = item.get("is_false_positive")
        if label == "false_positive" or is_fp is True:
            false_pos += 1
    return _safe_div(false_pos, reviewed) if reviewed else None


def _bypass_rate(path: str | None) -> float | None:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, list):
        return None
    total = 0
    bypass = 0
    for item in data:
        if not isinstance(item, dict):
            continue
        detected = item.get("detected")
        if not isinstance(detected, bool):
            continue
        total += 1
        if detected is False:
            bypass += 1
    return _safe_div(bypass, total) if total else None


def _remediation_sla(path: str | None) -> float | None:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, list):
        return None

    durations: list[float] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        discovered = _parse_iso(item.get("discovered_at"))
        resolved = _parse_iso(item.get("resolved_at"))
        if not discovered or not resolved or resolved < discovered:
            continue
        hours = (resolved - discovered).total_seconds() / 3600
        durations.append(hours)
    if not durations:
        return None
    return round(statistics.fmean(durations), 3)


def _regression_coverage(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    if p.suffix.lower() == ".json":
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if isinstance(data, dict):
            return data
        return None
    if p.suffix.lower() == ".xml":
        try:
            root = ET.fromstring(p.read_text(encoding="utf-8"))
        except (OSError, ET.ParseError):
            return None
        # junit style aggregate
        total = int(root.attrib.get("tests", 0)) if "tests" in root.attrib else 0
        failures = int(root.attrib.get("failures", 0)) if "failures" in root.attrib else 0
        errors = int(root.attrib.get("errors", 0)) if "errors" in root.attrib else 0
        passed = max(total - failures - errors, 0)
        return {"tests": total, "passed": passed, "failures": failures, "errors": errors}
    return None


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
