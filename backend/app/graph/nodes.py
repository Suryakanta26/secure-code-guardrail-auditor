import logging
from pathlib import Path

from pydantic import BaseModel

from app.core.llm import get_llm
from app.detectors.config_rules import scan_config
from app.detectors.dependency_scan import scan_dependencies
from app.detectors.secrets import scan_secrets
from app.graph.state import GraphState
from app.schemas.admin import Playbook
from app.schemas.analysis import Category, CodeFix, ComplianceStatus, Finding, ScanReport, Severity
from app.services import admin_store
from app.storage.files import load_files_from_folder

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {
    Severity.critical: 0,
    Severity.high: 1,
    Severity.medium: 2,
    Severity.low: 3,
    Severity.info: 4,
}

_SEVERITY_WEIGHT = {
    Severity.critical: 1.0,
    Severity.high: 0.75,
    Severity.medium: 0.5,
    Severity.low: 0.25,
    Severity.info: 0.1,
}

_CATEGORY_WEIGHT = {
    Category.hardcoded_secret: 1.0,
    Category.owasp: 0.9,
    Category.logic_flaw: 0.9,
    Category.compliance: 0.8,
    Category.dependency_vuln: 0.8,
    Category.config_issue: 0.7,
    Category.coding_standard: 0.5,
}

# Categories where an LLM can add real value (context-dependent exploitability/remediation);
# hardcoded secrets and known-CVE dependency findings are unambiguous and don't need reasoning.
_LLM_ELIGIBLE_CATEGORIES = {Category.owasp, Category.compliance, Category.config_issue, Category.coding_standard}
# A single high-severity OWASP finding at default confidence (0.75 * 0.7 * 0.9 = 0.4725) should
# already qualify on its own; lower-weighted categories (e.g. config_issue) need corroboration
# from other findings in the same region (the compound_boost above) to cross this bar.
_LLM_RISK_THRESHOLD = 0.45

_FRAMEWORK_CATEGORY_MAP: dict[str, set[Category]] = {
    "OWASP Top 10": {Category.owasp, Category.logic_flaw},
    "Secrets Management": {Category.hardcoded_secret},
    "Dependency Security": {Category.dependency_vuln},
    "Configuration Hardening": {Category.config_issue},
    "Internal Compliance Rules": {Category.compliance},
    "Coding Standards": {Category.coding_standard},
}


def _dedupe(findings: list[Finding]) -> list[Finding]:
    # category is part of the identity: the Security Reasoning Agent's prompt echoes back
    # existing finding titles as context, so an LLM (logic_flaw) finding can legitimately
    # share a (file, line, title) with the deterministic (owasp/config_issue/...) finding it
    # is confirming - they must not collapse into one.
    seen: set[tuple[str, int | None, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.file, finding.line, finding.category.value, finding.title)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _sort_by_risk(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.risk_score, _SEVERITY_ORDER.get(f.severity, 99)))


# --- Ingestion Agent ---
def ingest_node(state: GraphState) -> dict:
    repo_path = state.get("repo_path")
    files = load_files_from_folder(Path(repo_path)) if repo_path else []
    logger.info("ingest: loaded %d file(s) from %s", len(files), repo_path)
    return {"files": files}


# --- Configuration Agent ---
def configuration_node(state: GraphState) -> dict:
    findings: list[Finding] = []
    for file in state.get("files", []):
        findings.extend(scan_config(file))
    logger.info("configuration agent: %d finding(s)", len(findings))
    return {"config_findings": findings}


# --- Static Scan Agent ---
def static_scan_node(state: GraphState) -> dict:
    # OWASP Top 10 detection lives entirely in the admin-managed rule store now (see
    # detectors/owasp_seed.py + admin_store.py) and runs via compliance_scan_node's RAG lookup,
    # not here - this agent only covers secrets, which aren't admin-configurable rules.
    findings: list[Finding] = []
    for file in state.get("files", []):
        findings.extend(scan_secrets(file))
    logger.info("static scan agent: %d finding(s)", len(findings))
    return {"static_findings": findings}


# --- Dependency Scan Agent ---
def dependency_scan_node(state: GraphState) -> dict:
    findings: list[Finding] = []
    for file in state.get("files", []):
        findings.extend(scan_dependencies(file))
    logger.info("dependency scan agent: %d finding(s)", len(findings))
    return {"dependency_findings": findings}


# --- Compliance Agent (wired to compliance_rules.json/coding_standards.json in Phase 3) ---
def compliance_scan_node(state: GraphState) -> dict:
    from app.detectors.compliance_rules import scan_compliance  # local import: module lands in Phase 3

    findings: list[Finding] = []
    for file in state.get("files", []):
        findings.extend(scan_compliance(file))
    logger.info("compliance agent: %d finding(s)", len(findings))
    return {"compliance_findings": findings}


# --- Risk Correlation Agent ---
def _line_bucket(line: int | None) -> int:
    return (line or 0) // 4


def risk_correlation_node(state: GraphState) -> dict:
    combined = (
        state.get("config_findings", [])
        + state.get("static_findings", [])
        + state.get("dependency_findings", [])
        + state.get("compliance_findings", [])
    )
    deduped = _dedupe(combined)

    region_index: dict[tuple[str, int], list[Finding]] = {}
    file_index: dict[str, list[Finding]] = {}
    for finding in deduped:
        region_index.setdefault((finding.file, _line_bucket(finding.line)), []).append(finding)
        file_index.setdefault(finding.file, []).append(finding)

    scored: list[Finding] = []
    for finding in deduped:
        region = region_index[(finding.file, _line_bucket(finding.line))]
        compound_boost = 1.15 if len(region) > 1 else 1.0

        base = _SEVERITY_WEIGHT.get(finding.severity, 0.3) * finding.confidence
        risk_score = round(min(base * _CATEGORY_WEIGHT.get(finding.category, 0.6) * compound_boost, 1.0), 3)

        same_region = [f.id for f in region if f.id != finding.id]
        same_category_elsewhere = [
            f.id for f in file_index[finding.file]
            if f.id != finding.id and f.category == finding.category and f.id not in same_region
        ]
        evidence = [f"{finding.category.value} rule matched at {finding.file}:{finding.line or '?'}"]
        if compound_boost > 1.0:
            evidence.append(f"corroborated by {len(region) - 1} other finding(s) in the same region")

        needs_llm = risk_score >= _LLM_RISK_THRESHOLD and finding.category in _LLM_ELIGIBLE_CATEGORIES

        scored.append(
            finding.model_copy(
                update={
                    "risk_score": risk_score,
                    "related_finding_ids": (same_region + same_category_elsewhere)[:5],
                    "evidence": evidence,
                    "needs_llm": needs_llm,
                }
            )
        )

    scored = _sort_by_risk(scored)
    logger.info("risk correlation agent: %d finding(s) scored (from %d raw)", len(scored), len(combined))
    return {"deterministic_findings": scored}


def route_after_risk_correlation(state: GraphState) -> str:
    if any(f.needs_llm for f in state.get("deterministic_findings", [])):
        logger.info("LLM gate: high-risk finding(s) present -> security_reasoning")
        return "security_reasoning"
    logger.info("LLM gate: no finding needs deeper reasoning -> skipping security reasoning")
    return "merge"


# --- Security Reasoning Agent (LLM, gated to files with a needs_llm finding) ---
_SYSTEM_PROMPT = """You are a red-team application security auditor. You are given a source file
together with a list of findings automated scanners already flagged as high-risk in that file, each
with an id. Your job: (1) confirm/refine why each existing finding is exploitable in THIS specific
code context, producing a concrete exploit_explanation and remediation_patch, and (2) surface any
ADDITIONAL business-logic vulnerabilities (broken access control, race conditions, auth bypass,
insecure trust boundaries) automated scanners would miss. Be specific to this code, not generic advice.

Every finding you return MUST have a line number - the specific line in the file it applies to.

If a finding you produce is confirming/elaborating on the SAME underlying issue as one already listed
above, set refines_finding_id to that finding's id EXACTLY as given, AND set line to that EXACT same
line number given for it above - it will be merged into that finding rather than creating a duplicate
row for the same issue. Leave refines_finding_id null only for a genuinely NEW issue the scanners did
not already flag.

For each finding, if and only if you can propose an exact, safe, drop-in code fix, also include
code_fix with:
- original_snippet: the EXACT original code to replace, copied verbatim (including whitespace) from
  the file content given to you, with enough surrounding lines to be uniquely identifiable in the file.
- replacement_snippet: the fixed code that should replace it, matching the surrounding indentation.
Omit code_fix entirely if you are not confident the change is correct, if it requires broader
refactoring, or if original_snippet would not be a verbatim, unique match in the file - a wrong or
non-matching snippet cannot be applied and is worse than no suggestion. A finding that refines an
existing one should still include code_fix when you have one, so the fix appears on that finding.
Respond only via the provided tool schema."""


class LLMCodeFix(BaseModel):
    original_snippet: str
    replacement_snippet: str


class LLMFinding(BaseModel):
    line: int
    title: str
    description: str
    severity: Severity
    exploit_explanation: str
    remediation_patch: str | None = None
    compliance_tags: list[str] = []
    code_fix: LLMCodeFix | None = None
    refines_finding_id: str | None = None


class LLMFindingsResult(BaseModel):
    findings: list[LLMFinding]


def _format_existing_findings(findings: list[Finding]) -> str:
    lines = ["Findings already detected by automated scanners in this file (each has an id you can reference):"]
    for f in findings:
        lines.append(f"- id={f.id} line {f.line}: [{f.category.value}/{f.severity.value}] {f.title} - {f.description}")
    return "\n".join(lines)


def _format_playbooks(playbooks: list[Playbook]) -> str:
    if not playbooks:
        return ""
    lines = ["Relevant internal security playbook guidance:"]
    for pb in playbooks:
        lines.append(f"- {pb.title}: {pb.body[:800]}")
    return "\n".join(lines)


def _validated_fix(file_content: str, code_fix: LLMCodeFix | None) -> CodeFix | None:
    """Only trust a code_fix if its original_snippet is an exact, unique match in the file -
    otherwise it can't be safely applied later, so it's better to drop it than offer a broken fix.
    """
    if code_fix is None or not code_fix.original_snippet.strip():
        return None
    if file_content.count(code_fix.original_snippet) != 1:
        logger.warning("security reasoning: dropping code_fix, original_snippet is not a unique exact match")
        return None
    return CodeFix(original_snippet=code_fix.original_snippet, replacement_snippet=code_fix.replacement_snippet)


def security_reasoning_node(state: GraphState) -> dict:
    all_deterministic = state.get("deterministic_findings", [])
    findings_by_file: dict[str, list[Finding]] = {}
    for finding in all_deterministic:
        if finding.needs_llm:
            findings_by_file.setdefault(finding.file, []).append(finding)

    if not findings_by_file:
        return {"llm_findings": [], "used_llm": False}

    files_by_path = {f.path: f for f in state.get("files", [])}
    llm = get_llm().with_structured_output(LLMFindingsResult)
    new_findings: list[Finding] = []
    refined_by_id: dict[str, Finding] = {}

    for path, flagged in findings_by_file.items():
        file = files_by_path.get(path)
        if file is None:
            continue

        flagged_by_id = {f.id: f for f in flagged}
        tags = {tag for f in flagged for tag in f.compliance_tags} | {f.category.value for f in flagged}
        playbook_context = _format_playbooks(admin_store.playbooks_for_tags(tags))

        human_content = (
            f"{_format_existing_findings(flagged)}\n\n{playbook_context}\n\n"
            f"File: {path}\n\n```\n{file.content}\n```"
        )
        try:
            result: LLMFindingsResult = llm.invoke([("system", _SYSTEM_PROMPT), ("human", human_content)])
        except Exception:
            logger.exception("security reasoning: LLM call failed for %s", path)
            continue

        file_lines = file.content.splitlines()
        for f in result.findings:
            fix = _validated_fix(file.content, f.code_fix)

            if fix is not None:
                code_snippet = fix.original_snippet.strip()[:300]
            elif f.line and 1 <= f.line <= len(file_lines):
                code_snippet = file_lines[f.line - 1].strip()[:300]
            else:
                code_snippet = ""

            original = flagged_by_id.get(f.refines_finding_id) if f.refines_finding_id else None
            if original is None and f.line is not None:
                # The LLM doesn't always set refines_finding_id even when it's clearly re-describing
                # a scanner finding on the same line (e.g. restating "String-Built SQL Query" as its
                # own "SQL Injection Vulnerability" finding) - falling back to an exact same-file/
                # same-line match against a not-yet-refined flagged finding catches that case too,
                # so it still merges instead of producing a fix-less duplicate row.
                original = next((cand for cand in flagged if cand.line == f.line and cand.id not in refined_by_id), None)
            if original is not None:
                # Same underlying issue as an existing finding: enrich it in place (keeping its
                # original category/title/severity) instead of spawning a fix-less duplicate row.
                refined_by_id[original.id] = original.model_copy(
                    update={
                        "exploit_explanation": f.exploit_explanation or original.exploit_explanation,
                        "remediation_patch": f.remediation_patch or original.remediation_patch,
                        "code_snippet": code_snippet or original.code_snippet,
                        "evidence": original.evidence + ["Confirmed by the Security Reasoning Agent (LLM)"],
                        "suggested_fix": fix if fix is not None else original.suggested_fix,
                        "fix_status": "suggested" if fix is not None else original.fix_status,
                    }
                )
                continue

            risk_score = round(_SEVERITY_WEIGHT.get(f.severity, 0.5) * 0.75, 3)
            new_findings.append(
                Finding(
                    file=path,
                    line=f.line,
                    code_snippet=code_snippet,
                    category=Category.logic_flaw,
                    severity=f.severity,
                    title=f.title,
                    description=f.description,
                    exploit_explanation=f.exploit_explanation,
                    remediation_patch=f.remediation_patch,
                    compliance_tags=f.compliance_tags,
                    confidence=0.75,
                    risk_score=risk_score,
                    needs_llm=True,
                    evidence=["Confirmed/derived by the Security Reasoning Agent (LLM)"],
                    suggested_fix=fix,
                    fix_status="suggested" if fix is not None else "none",
                )
            )

    updated_deterministic = [refined_by_id.get(f.id, f) for f in all_deterministic]

    logger.info(
        "security reasoning agent: %d new finding(s), %d refined in-place, across %d file(s)",
        len(new_findings), len(refined_by_id), len(findings_by_file),
    )
    return {"deterministic_findings": updated_deterministic, "llm_findings": new_findings, "used_llm": True}


# --- Merge Results ---
def merge_node(state: GraphState) -> dict:
    combined = state.get("deterministic_findings", []) + state.get("llm_findings", [])
    merged = _sort_by_risk(_dedupe(combined))
    logger.info("merge: %d finding(s) after combining deterministic + LLM results", len(merged))
    return {"merged_findings": merged, "used_llm": state.get("used_llm", False)}


# --- Compliance Scoring rollup (used by the dashboard's Compliance Score stat) ---
def compliance_scoring_node(state: GraphState) -> dict:
    findings = state.get("merged_findings", [])
    statuses = [
        ComplianceStatus(framework=framework, status="fail" if violations else "pass", violation_count=len(violations))
        for framework, categories in _FRAMEWORK_CATEGORY_MAP.items()
        for violations in [[f for f in findings if f.category in categories]]
    ]
    logger.info("compliance scoring agent: %s", ", ".join(f"{s.framework}={s.status}" for s in statuses))
    return {"compliance_status": statuses}


# --- Report Generation Agent ---
def report_node(state: GraphState) -> dict:
    findings = state.get("merged_findings", [])
    files = state.get("files", [])
    critical_count = sum(1 for f in findings if f.severity == Severity.critical)
    used_llm = state.get("used_llm", False)
    reasoned_files = len({f.file for f in state.get("deterministic_findings", []) if f.needs_llm})

    if used_llm:
        llm_summary = f"Security Reasoning Agent ran on {reasoned_files} high-risk file(s)."
    else:
        llm_summary = "No file crossed the risk threshold for deeper AI reasoning."

    summary = f"Scanned {len(files)} file(s), found {len(findings)} finding(s) ({critical_count} critical). {llm_summary}"
    logger.info("report generation agent: %s", summary)

    report = ScanReport(
        findings=findings,
        files_scanned=len(files),
        used_llm=used_llm,
        compliance_status=state.get("compliance_status", []),
        summary=summary,
    )
    return {"report": report}
