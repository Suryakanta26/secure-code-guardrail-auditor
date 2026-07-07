import logging
import re

from app.schemas.analysis import Category, CodeFile, Finding
from app.services import admin_store, rules_rag

logger = logging.getLogger(__name__)

_SNIPPET_MAX_LEN = 300
# OWASP Top 10 rules are well-established, low-false-positive patterns (unlike org-specific
# compliance/coding-standard rules), so they carry the same confidence the old dedicated static
# scanner used - the Risk Correlation Agent's LLM gate threshold is calibrated against this value.
_OWASP_CONFIDENCE = 0.7
_DEFAULT_CONFIDENCE = 0.6


def _snippet(line: str) -> str:
    stripped = line.strip()
    return stripped if len(stripped) <= _SNIPPET_MAX_LEN else stripped[:_SNIPPET_MAX_LEN] + "..."


def scan_compliance(file: CodeFile) -> list[Finding]:
    """Scans a file against admin-managed compliance_rules.json / coding_standards.json,
    retrieving only the RAG-relevant subset for this file's language/content before matching.
    """
    rules = rules_rag.retrieve_relevant_rules(file.path, file.content, top_k=50)
    if not rules:
        return []

    findings: list[Finding] = []
    lines = file.content.splitlines()

    for rule in rules:
        try:
            compiled = re.compile(rule.detection.pattern)
        except re.error:
            logger.debug("compliance: skipping %s, invalid pattern %r", rule.rule_id, rule.detection.pattern)
            continue

        category = admin_store.category_for_rule_id(rule.rule_id)
        compliance_tags = [rule.rule_id]
        if rule.owasp:
            compliance_tags.append(f"OWASP-{rule.owasp}")
        if rule.cwe:
            compliance_tags.append(rule.cwe)

        for line_no, line in enumerate(lines, start=1):
            if compiled.search(line):
                findings.append(
                    Finding(
                        file=file.path,
                        line=line_no,
                        code_snippet=_snippet(line),
                        category=category,
                        severity=rule.severity,
                        title=f"[{rule.rule_id}] {rule.title}",
                        description=rule.description or rule.risk,
                        exploit_explanation=rule.red_team or None,
                        remediation_patch=rule.remediation or None,
                        compliance_tags=compliance_tags,
                        confidence=_OWASP_CONFIDENCE if category == Category.owasp else _DEFAULT_CONFIDENCE,
                    )
                )

    return findings
