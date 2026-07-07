import uuid
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Category(str, Enum):
    hardcoded_secret = "hardcoded_secret"
    owasp = "owasp"
    config_issue = "config_issue"
    dependency_vuln = "dependency_vuln"
    logic_flaw = "logic_flaw"
    compliance = "compliance"
    coding_standard = "coding_standard"


class CodeFile(BaseModel):
    path: str
    content: str
    language: str | None = None


class CodeFix(BaseModel):
    """A mechanically-applicable fix: the exact original code text and its replacement.

    Applied by exact-string match against the current file content (not line numbers,
    which drift as soon as one fix changes the line count) - see services/fix_apply.py.
    """
    original_snippet: str
    replacement_snippet: str
    explanation: str = ""


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: f"fnd-{uuid.uuid4().hex[:12]}")
    file: str
    line: int | None = None
    code_snippet: str = ""
    category: Category
    severity: Severity
    title: str
    description: str
    exploit_explanation: str | None = None
    remediation_patch: str | None = None
    compliance_tags: list[str] = []
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    # populated by the Risk Correlation Agent
    risk_score: float = 0.0
    evidence: list[str] = []
    related_finding_ids: list[str] = []
    needs_llm: bool = False
    # populated by the Security Reasoning Agent when it can propose a safe, exact fix
    suggested_fix: CodeFix | None = None
    fix_status: str = "none"  # none | suggested | applied


class ComplianceStatus(BaseModel):
    framework: str
    status: str
    violation_count: int


class ScanReport(BaseModel):
    findings: list[Finding] = []
    files_scanned: int = 0
    used_llm: bool = False
    compliance_status: list[ComplianceStatus] = []
    summary: str = ""


class ChunkingConfig(BaseModel):
    max_chunk_size: int = Field(default=2000, ge=200, le=20000)
    min_chunk_size: int | None = Field(default=None, ge=50)


class CustomRuleDetection(BaseModel):
    type: str = "semantic+regex"
    pattern: str = ""


class CustomRule(BaseModel):
    rule_id: str
    title: str
    category: str
    severity: Severity
    languages: list[str] = []
    owasp: str | None = None
    cwe: str | None = None
    description: str = ""
    detection: CustomRuleDetection = CustomRuleDetection()
    risk: str = ""
    red_team: str = ""
    remediation: str = ""
    secure_example: str = ""
    tags: list[str] = []
    references: list[str] = []

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity(cls, value):
        return value.lower() if isinstance(value, str) else value
