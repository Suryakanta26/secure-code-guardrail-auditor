import re

from app.schemas.analysis import Category, CodeFile, Finding, Severity

_SNIPPET_MAX_LEN = 300

_CONFIG_FILENAME_RE = re.compile(
    r"(?i)(^|/)(\.env(\..+)?|docker-compose.*\.ya?ml|dockerfile|.*\.ya?ml|"
    r"settings\.py|config\.py|application\.(properties|ya?ml)|.*\.tf)$"
)

_RULES: list[tuple[str, str, str, re.Pattern, Severity, list[str]]] = [
    (
        "Wildcard CORS Origin",
        "CORS is configured to allow requests from any origin, which can enable cross-origin credential theft.",
        "Replace the wildcard with an explicit allow-list of trusted origins.",
        re.compile(r"(?i)(CORS_ORIGIN_ALLOW_ALL\s*=\s*True|Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"])"),
        Severity.high,
        ["OWASP-A05"],
    ),
    (
        "Django ALLOWED_HOSTS Wildcard",
        "ALLOWED_HOSTS set to '*' disables Django's Host header validation.",
        "Set ALLOWED_HOSTS to the specific domain(s) that serve this application.",
        re.compile(r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]"),
        Severity.medium,
        ["OWASP-A05"],
    ),
    (
        "Service Bound to All Interfaces",
        "Binding to 0.0.0.0 exposes the service on every network interface, widening the attack surface.",
        "Bind to a specific interface (e.g. 127.0.0.1) unless the service must be reachable externally.",
        re.compile(r"0\.0\.0\.0"),
        Severity.low,
        ["OWASP-A05"],
    ),
    (
        "TLS/SSL Verification Disabled",
        "Disabling TLS verification allows man-in-the-middle attacks against outbound connections.",
        "Remove the verification bypass and fix the underlying certificate issue instead.",
        re.compile(r"(?i)(ssl\s*[:=]\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)"),
        Severity.high,
        ["OWASP-A02"],
    ),
    (
        "Privileged Container",
        "Running a container in privileged mode grants it near-host-level access, breaking container isolation.",
        "Remove privileged: true and grant only the specific Linux capabilities the container needs.",
        re.compile(r"(?i)privileged\s*:\s*true"),
        Severity.high,
        ["OWASP-A05"],
    ),
    (
        "Kubernetes hostNetwork Enabled",
        "hostNetwork: true removes network namespace isolation between the pod and the host.",
        "Remove hostNetwork: true unless the workload specifically requires host networking.",
        re.compile(r"hostNetwork\s*:\s*true"),
        Severity.medium,
        ["OWASP-A05"],
    ),
    (
        "Debug Mode in Config",
        "Debug mode enabled in configuration can leak stack traces and internal application state.",
        "Disable debug mode in production and drive it from an environment variable.",
        re.compile(r"(?i)debug\s*[:=]\s*(true|1)\b"),
        Severity.low,
        ["OWASP-A05"],
    ),
    (
        "CSRF Protection Disabled",
        "Disabling CSRF protection allows cross-site request forgery against authenticated sessions.",
        "Re-enable CSRF protection for all state-changing endpoints.",
        re.compile(r"(?i)(csrf_enabled|csrf_protect|enable_csrf)\s*[:=]\s*(false|0)\b"),
        Severity.high,
        ["OWASP-A01"],
    ),
    (
        "Insecure Session Cookie",
        "Session/CSRF cookies without the Secure/HttpOnly flags can be intercepted or read via XSS.",
        "Set the Secure and HttpOnly flags on session/CSRF cookies.",
        re.compile(r"(?i)(session_cookie_secure|csrf_cookie_secure)\s*[:=]\s*(false|0)\b"),
        Severity.medium,
        ["OWASP-A05"],
    ),
]


def _snippet(line: str) -> str:
    stripped = line.strip()
    return stripped if len(stripped) <= _SNIPPET_MAX_LEN else stripped[:_SNIPPET_MAX_LEN] + "..."


def is_config_file(path: str) -> bool:
    return bool(_CONFIG_FILENAME_RE.search(path))


def scan_config(file: CodeFile) -> list[Finding]:
    if not is_config_file(file.path):
        return []

    findings: list[Finding] = []
    lines = file.content.splitlines()

    for line_no, line in enumerate(lines, start=1):
        for title, description, remediation, pattern, severity, tags in _RULES:
            if pattern.search(line):
                findings.append(
                    Finding(
                        file=file.path,
                        line=line_no,
                        code_snippet=_snippet(line),
                        category=Category.config_issue,
                        severity=severity,
                        title=title,
                        description=description,
                        remediation_patch=remediation,
                        compliance_tags=tags,
                        confidence=0.7,
                    )
                )
        for title, description, pattern, severity in _extra_rules():
            if pattern.search(line):
                findings.append(
                    Finding(
                        file=file.path,
                        line=line_no,
                        code_snippet=_snippet(line),
                        category=Category.config_issue,
                        severity=severity,
                        title=title,
                        description=description,
                        compliance_tags=["Admin-Configured"],
                        confidence=0.6,
                    )
                )

    return findings


def _extra_rules() -> list[tuple[str, str, re.Pattern, Severity]]:
    """Admin-managed extra config patterns from configurations.json."""
    from app.services import admin_store  # local import: avoids a hard import-time dependency

    return admin_store.compiled_configuration_rules()
