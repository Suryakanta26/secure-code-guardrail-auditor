import math
import re

from app.schemas.analysis import Category, CodeFile, Finding, Severity

_SECRET_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("AWS Access Key", "aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Generic API Key", "generic_api_key", re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]")),
    ("Private Key Block", "private_key", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----")),
    ("Slack Token", "slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Generic Bearer/Secret Assignment", "hardcoded_credential", re.compile(r"(?i)(password|secret|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]")),
]

_MIN_ENTROPY = 4.0
_ENTROPY_ASSIGNMENT = re.compile(r"['\"]([A-Za-z0-9+/_\-]{20,})['\"]")
_SNIPPET_MAX_LEN = 300


def _snippet(line: str) -> str:
    stripped = line.strip()
    return stripped if len(stripped) <= _SNIPPET_MAX_LEN else stripped[:_SNIPPET_MAX_LEN] + "..."


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {ch: value.count(ch) for ch in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def scan_secrets(file: CodeFile) -> list[Finding]:
    findings: list[Finding] = []
    lines = file.content.splitlines()

    for line_no, line in enumerate(lines, start=1):
        for title, tag, pattern in _SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        file=file.path,
                        line=line_no,
                        code_snippet=_snippet(line),
                        category=Category.hardcoded_secret,
                        severity=Severity.critical,
                        title=title,
                        description=f"Detected pattern matching {title} in source code.",
                        remediation_patch="Move this value out of source control into a secret manager "
                        "(e.g. environment variables, Vault, AWS Secrets Manager) and rotate the exposed credential.",
                        compliance_tags=["OWASP-A02", "PCI-DSS-3.4"],
                        confidence=0.9,
                    )
                )

        for match in _ENTROPY_ASSIGNMENT.finditer(line):
            candidate = match.group(1)
            if _shannon_entropy(candidate) >= _MIN_ENTROPY:
                findings.append(
                    Finding(
                        file=file.path,
                        line=line_no,
                        code_snippet=_snippet(line),
                        category=Category.hardcoded_secret,
                        severity=Severity.high,
                        title="High-Entropy String",
                        description="String literal has high entropy and may be a hardcoded secret/token.",
                        remediation_patch="Verify whether this value is sensitive; if so, move it out of "
                        "source control into a secret manager and rotate it.",
                        compliance_tags=["OWASP-A02"],
                        confidence=0.55,
                    )
                )

    return findings
