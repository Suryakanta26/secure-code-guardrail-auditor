from typing import TypedDict

from app.schemas.analysis import CodeFile, ComplianceStatus, Finding, ScanReport


class GraphState(TypedDict, total=False):
    repo_id: str
    scan_id: str
    repo_path: str
    files: list[CodeFile]
    config_findings: list[Finding]
    static_findings: list[Finding]
    dependency_findings: list[Finding]
    compliance_findings: list[Finding]
    deterministic_findings: list[Finding]
    llm_findings: list[Finding]
    merged_findings: list[Finding]
    used_llm: bool
    compliance_status: list[ComplianceStatus]
    report: ScanReport
