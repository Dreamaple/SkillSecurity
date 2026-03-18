"""Supply chain analyzer for dependencies, SBOM, and trust checks."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - py311+ should provide tomllib
    tomllib = None  # type: ignore[assignment]


@dataclass(frozen=True)
class Component:
    ecosystem: str
    name: str
    version: str
    source_file: str


def analyze_supply_chain(
    target_path: str | Path,
    vuln_feed_file: str | Path | None = None,
    allowed_domains: list[str] | None = None,
    hashes_file: str | Path | None = None,
) -> dict[str, Any]:
    base = Path(target_path)
    components = scan_components(base)
    advisories = _load_vuln_feed(vuln_feed_file) if vuln_feed_file else []
    vuln_findings = match_vulnerabilities(components, advisories)
    source_findings = check_source_allowlist(base, allowed_domains or [])
    hash_findings = verify_hashes(base, hashes_file) if hashes_file else []

    risk_level = _risk_level(vuln_findings, source_findings, hash_findings)
    return {
        "target": str(base),
        "risk_level": risk_level,
        "sbom": {
            "generated_at": datetime.now(UTC).isoformat(),
            "component_count": len(components),
            "components": [asdict(c) for c in components],
        },
        "vulnerability_findings": vuln_findings,
        "source_allowlist_findings": source_findings,
        "hash_findings": hash_findings,
    }


def scan_components(base: Path) -> list[Component]:
    components: list[Component] = []
    candidates = _find_manifest_files(base)
    for f in candidates:
        if f.name.startswith("requirements") and f.suffix == ".txt":
            components.extend(_parse_requirements_txt(f))
        elif f.name == "pyproject.toml":
            components.extend(_parse_pyproject(f))
        elif f.name == "package.json":
            components.extend(_parse_package_json(f))
    return _dedupe_components(components)


def match_vulnerabilities(
    components: list[Component],
    advisories: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for c in components:
        for adv in advisories:
            eco = str(adv.get("ecosystem", "")).lower()
            pkg = str(adv.get("package", adv.get("name", ""))).lower()
            if eco and eco != c.ecosystem.lower():
                continue
            if pkg and pkg != c.name.lower():
                continue

            affected = adv.get("affected_versions") or adv.get("versions") or []
            if affected and not _version_affected(c.version, affected):
                continue

            findings.append(
                {
                    "component": asdict(c),
                    "advisory_id": adv.get("id", ""),
                    "severity": str(adv.get("severity", "unknown")).lower(),
                    "summary": adv.get("summary", ""),
                }
            )
    return findings


def check_source_allowlist(base: Path, allowed_domains: list[str]) -> list[dict[str, Any]]:
    if not allowed_domains:
        return []
    normalized_allowlist = [d.lower() for d in allowed_domains]
    findings: list[dict[str, Any]] = []

    for manifest in base.rglob("*manifest*.json"):
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        urls = _extract_urls(data)
        for u in urls:
            domain = urlparse(u).netloc.lower()
            if not domain:
                continue
            if any(_domain_matches(domain, allowed) for allowed in normalized_allowlist):
                continue
            findings.append(
                {
                    "file": str(manifest),
                    "url": u,
                    "domain": domain,
                    "message": "Domain is not in source allowlist",
                }
            )
    return findings


def verify_hashes(base: Path, hashes_file: str | Path) -> list[dict[str, Any]]:
    p = Path(hashes_file)
    if not p.exists():
        return [{"file": str(p), "message": "hashes file not found"}]
    try:
        mapping = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [{"file": str(p), "message": "invalid hashes JSON"}]
    if not isinstance(mapping, dict):
        return [{"file": str(p), "message": "hashes JSON must be an object"}]

    findings: list[dict[str, Any]] = []
    for rel, expected in mapping.items():
        target = (base / str(rel)).resolve()
        if not target.exists():
            findings.append(
                {
                    "file": str(target),
                    "message": "expected file missing for hash verification",
                }
            )
            continue
        actual = _sha256_file(target)
        if actual != str(expected).lower():
            findings.append(
                {
                    "file": str(target),
                    "expected_sha256": str(expected).lower(),
                    "actual_sha256": actual,
                    "message": "hash mismatch",
                }
            )
    return findings


def _find_manifest_files(base: Path) -> list[Path]:
    if base.is_file():
        return [base]
    names = {"requirements.txt", "pyproject.toml", "package.json"}
    out: list[Path] = []
    for f in base.rglob("*"):
        if f.is_file() and f.name in names:
            out.append(f)
    return out


def _parse_requirements_txt(path: Path) -> list[Component]:
    components: list[Component] = []
    pattern = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*([<>=!~].+)?\s*$")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        m = pattern.match(stripped)
        if not m:
            continue
        name = m.group(1)
        spec = m.group(2) or ""
        version = _extract_version_from_spec(spec)
        components.append(
            Component(
                ecosystem="pypi",
                name=name,
                version=version,
                source_file=str(path),
            )
        )
    return components


def _parse_pyproject(path: Path) -> list[Component]:
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []

    deps = data.get("project", {}).get("dependencies", [])
    if not isinstance(deps, list):
        return []

    components: list[Component] = []
    for dep in deps:
        if not isinstance(dep, str):
            continue
        name, version = _split_dep(dep)
        components.append(
            Component(ecosystem="pypi", name=name, version=version, source_file=str(path))
        )
    return components


def _parse_package_json(path: Path) -> list[Component]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    components: list[Component] = []
    for key in ("dependencies", "devDependencies"):
        dep_map = data.get(key, {})
        if not isinstance(dep_map, dict):
            continue
        for name, version in dep_map.items():
            components.append(
                Component(
                    ecosystem="npm",
                    name=str(name),
                    version=str(version),
                    source_file=str(path),
                )
            )
    return components


def _split_dep(dep: str) -> tuple[str, str]:
    m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*([<>=!~].+)?\s*$", dep)
    if not m:
        return dep.strip(), "unknown"
    name = m.group(1)
    spec = m.group(2) or ""
    return name, _extract_version_from_spec(spec)


def _extract_version_from_spec(spec: str) -> str:
    if not spec:
        return "unknown"
    if spec.startswith("=="):
        return spec[2:].strip()
    return spec.strip()


def _dedupe_components(items: list[Component]) -> list[Component]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[Component] = []
    for c in items:
        key = (c.ecosystem.lower(), c.name.lower(), c.version, c.source_file)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def _load_vuln_feed(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        adv = data.get("advisories", [])
        if isinstance(adv, list):
            return [x for x in adv if isinstance(x, dict)]
    return []


def _version_affected(version: str, rules: list[Any]) -> bool:
    for r in rules:
        rule = str(r).strip()
        if not rule:
            continue
        if rule.startswith(("==", "=")):
            target = rule.lstrip("=")
            if version == target:
                return True
            continue
        if rule.startswith(">="):
            if _compare_version(version, rule[2:].strip()) >= 0:
                return True
            continue
        if rule.startswith("<="):
            if _compare_version(version, rule[2:].strip()) <= 0:
                return True
            continue
        if rule.startswith(">"):
            if _compare_version(version, rule[1:].strip()) > 0:
                return True
            continue
        if rule.startswith("<"):
            if _compare_version(version, rule[1:].strip()) < 0:
                return True
            continue
        if version == rule:
            return True
    return False


def _compare_version(a: str, b: str) -> int:
    def to_tuple(v: str) -> tuple[int, ...]:
        nums = re.findall(r"\d+", v)
        return tuple(int(n) for n in nums[:6]) or (0,)

    ta = to_tuple(a)
    tb = to_tuple(b)
    max_len = max(len(ta), len(tb))
    ta += (0,) * (max_len - len(ta))
    tb += (0,) * (max_len - len(tb))
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


def _extract_urls(data: Any) -> list[str]:
    urls: list[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            key = str(k).lower()
            if key in {"source", "source_url", "repository", "homepage", "download_url"}:
                if isinstance(v, str) and v.startswith(("http://", "https://")):
                    urls.append(v)
            urls.extend(_extract_urls(v))
    elif isinstance(data, list):
        for x in data:
            urls.extend(_extract_urls(x))
    return urls


def _domain_matches(domain: str, allow: str) -> bool:
    allow = allow.lower().strip()
    if allow.startswith("*."):
        suffix = allow[1:]
        return domain.endswith(suffix) or domain == allow[2:]
    return domain == allow


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _risk_level(
    vuln_findings: list[dict[str, Any]],
    source_findings: list[dict[str, Any]],
    hash_findings: list[dict[str, Any]],
) -> str:
    severities = {str(v.get("severity", "")).lower() for v in vuln_findings}
    if "critical" in severities:
        return "critical"
    if "high" in severities or hash_findings:
        return "high"
    if vuln_findings or source_findings:
        return "medium"
    return "low"
