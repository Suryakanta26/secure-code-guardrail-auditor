import json
import logging
import re

import requests

from app.config import settings
from app.schemas.analysis import Category, CodeFile, Finding, Severity

logger = logging.getLogger(__name__)

_VERSION_CLEAN_RE = re.compile(r"^[\^~>=<! ]*")
_REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)")
_SNIPPET_MAX_LEN = 300


def _snippet(line: str) -> str:
    stripped = line.strip()
    return stripped if len(stripped) <= _SNIPPET_MAX_LEN else stripped[:_SNIPPET_MAX_LEN] + "..."


def _parse_requirements_txt(content: str) -> list[tuple[str, str, str, int, str]]:
    deps: list[tuple[str, str, str, int, str]] = []
    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = _REQUIREMENT_RE.match(line)
        if match:
            deps.append((match.group(1), match.group(2), "PyPI", line_no, raw_line))
    return deps


def _parse_package_json(content: str) -> list[tuple[str, str, str, int, str]]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    lines = content.splitlines()
    deps: list[tuple[str, str, str, int, str]] = []
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            cleaned = _VERSION_CLEAN_RE.sub("", version)
            if not cleaned:
                continue
            name_pattern = re.compile(rf'"{re.escape(name)}"\s*:\s*"')
            line_no, raw_line = next(
                ((i, text) for i, text in enumerate(lines, start=1) if name_pattern.search(text)),
                (0, f'"{name}": "{version}"'),
            )
            deps.append((name, cleaned, "npm", line_no, raw_line))
    return deps


def _extract_dependencies(file: CodeFile) -> list[tuple[str, str, str, int, str]]:
    if file.path.endswith("requirements.txt"):
        return _parse_requirements_txt(file.content)
    if file.path.endswith("package.json"):
        return _parse_package_json(file.content)
    return []


def scan_dependencies(file: CodeFile) -> list[Finding]:
    deps = _extract_dependencies(file)
    if not deps:
        return []

    queries = [{"package": {"name": name, "ecosystem": eco}, "version": version} for name, version, eco, _, _ in deps]
    logger.info("dependency scan: querying OSV.dev for %d package(s) from %s", len(deps), file.path)

    try:
        response = requests.post(settings.osv_api_url, json={"queries": queries}, timeout=10)
        response.raise_for_status()
        results = response.json().get("results", [])
    except requests.RequestException:
        logger.warning("dependency scan: OSV.dev query failed for %s, skipping", file.path, exc_info=True)
        return []

    findings: list[Finding] = []
    for (name, version, eco, line_no, raw_line), result in zip(deps, results):
        for vuln in result.get("vulns", []):
            vuln_id = vuln.get("id") or "unknown-advisory"
            findings.append(
                Finding(
                    file=file.path,
                    line=line_no or None,
                    code_snippet=_snippet(raw_line),
                    category=Category.dependency_vuln,
                    severity=Severity.high,
                    title=f"Vulnerable dependency: {name}@{version} ({vuln_id})",
                    description=vuln.get("summary") or f"{vuln_id} affects {name}@{version} ({eco}).",
                    remediation_patch=f"Upgrade {name} to a version that resolves {vuln_id} "
                    "(check the advisory for the fixed version range).",
                    compliance_tags=["OWASP-A06"],
                    confidence=0.85,
                )
            )
    return findings
