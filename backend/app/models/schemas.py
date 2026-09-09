"""Shared Pydantic models for AuthTrack scan workflows."""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


# ── Flow 1: Recon & Surface Mapping ──────────────────────────────────────────

class DiscoveredEndpoint(BaseModel):
    """A single discovered endpoint from the crawl."""
    url: str
    method: str = "GET"
    endpoint_type: str = "unknown"  # auth_page, api, static_asset, form, dashboard, unknown
    status_code: int = 0
    content_type: Optional[str] = None
    parameters: list[str] = Field(default_factory=list)
    technology: list[str] = Field(default_factory=list)
    is_interesting: bool = False
    response_size: int = 0
    response_time: float = 0.0
    form_inputs: list[str] = Field(default_factory=list)


class SurfaceReport(BaseModel):
    """The final output of Flow 1 — the attack surface map."""
    target_url: str
    total_endpoints: int = 0
    endpoints: list[DiscoveredEndpoint] = Field(default_factory=list)
    scan_timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    summary: str = ""


# ── Flow 2: Security Header & Cookie Audit ───────────────────────────────────

class HeaderCheckResult(BaseModel):
    """One checklist item evaluated for one endpoint.

    Every item on the checklist emits one of these for every endpoint —
    `status` is "pass", "fail", or "missing" — so the report shows what is
    correctly configured as well as what is not. `severity` is only populated
    for fail/missing items (passes are objectively correct and carry none).
    """
    url: str
    endpoint_type: str = "unknown"
    category: str = "header"          # header | cookie | cors
    header_name: str
    expected: str
    actual: Optional[str] = None
    status: str = "missing"           # pass | fail | missing
    severity: Optional[str] = None    # only set for fail/missing
    description: str = ""
    info: str = ""
    weight: int = 0


class HeaderAuditReport(BaseModel):
    """The final output of Flow 2 — the header/cookie audit report.

    Reports both sides: `checklist` is every check for every endpoint, `passes`
    and `findings` split it into what is configured vs what needs attention, and
    `configured_count`/`graded_total` back the "X/Y configured" summary ratio.
    """
    target_url: str
    endpoints_audited: int = 0
    checklist: list[HeaderCheckResult] = Field(default_factory=list)
    passes: list[HeaderCheckResult] = Field(default_factory=list)
    findings: list[HeaderCheckResult] = Field(default_factory=list)
    total_findings: int = 0
    total_checks: int = 0
    configured_count: int = 0
    graded_total: int = 0
    severity_breakdown: dict = Field(default_factory=dict)
    summary: str = ""
    scan_timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


# ── API Request/Response Models ──────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Request body for scan endpoints."""
    url: str
    max_depth: int = 2
    max_pages: int = 15


class HeaderScanRequest(BaseModel):
    """Request body for header-only scan (requires endpoint list)."""
    url: str
    endpoints: list[dict] = Field(default_factory=list)
    max_depth: int = 2
    max_pages: int = 15


class StaticScanRequest(BaseModel):
    """Request body for the static analysis scan (scans a local repo path)."""
    target_path: str = "."
    # CodeQL is the slow one — its database-build step dominates the run — so it
    # can be turned off for a fast pass over the other four tools.
    include_codeql: bool = True
    # "" → auto-detect from the repo's manifests and file extensions.
    codeql_language: str = ""
    # Cap on how many merged findings get an LLM triage pass. Findings are
    # triaged highest-severity-and-strongest-evidence first, so a cap trims the
    # tail rather than the interesting cases.
    max_triage: int = 25
    max_depth: int = 2
    max_pages: int = 15


class FullScanResponse(BaseModel):
    """Combined response from a full scan (Flow 1 + Flow 2)."""
    surface_report: SurfaceReport
    header_audit_report: HeaderAuditReport


# ── Flow 3: Injection Testing ────────────────────────────────────────────────

class InjectionFinding(BaseModel):
    """A single confirmed injection vulnerability."""
    url: str
    parameter: str
    injection_type: str  # sqli, xss, command_injection, path_traversal
    payload_name: str = ""
    severity: str = "medium"  # critical, high, medium, low
    evidence: str = ""
    description: str = ""
    recommendation: str = ""


class InjectionReport(BaseModel):
    """The final output of Flow 3 — the injection test report."""
    target_url: str
    total_tested: int = 0
    total_confirmed: int = 0
    total_discarded: int = 0
    findings: list[InjectionFinding] = Field(default_factory=list)
    type_breakdown: dict = Field(default_factory=dict)
    severity_breakdown: dict = Field(default_factory=dict)
    summary: str = ""
    scan_timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


class InjectionScanRequest(BaseModel):
    """Request body for injection scan endpoints."""
    url: str
    endpoints: list[dict] = Field(default_factory=list)  # from prior recon
    max_depth: int = 2  # used if endpoints empty and recon needed first
    max_pages: int = 15


# ── Flow 6: Static Analysis (multi-tool SAST) ────────────────────────────────

class TaintStep(BaseModel):
    """One hop in a CodeQL dataflow path."""
    step: int
    role: str = "intermediate"  # source, intermediate, sink
    file: str
    line: int = 0
    snippet: str = ""
    message: str = ""


class MergedFinding(BaseModel):
    """A finding after normalization and cross-tool deduplication."""
    tool_source: str  # semgrep, bearer, osv-scanner, gitleaks, codeql
    file: str
    line: int = 0
    severity: str = "medium"  # critical, high, medium, low, info
    rule_id: str = ""
    category: str = "Other"  # canonical vulnerability category
    description: str = ""
    raw_snippet: str = ""
    # Present only for CodeQL findings — the source → sink chain that proves the
    # vulnerability is actually reachable.
    taint_path: Optional[list[TaintStep]] = None
    multi_tool_confirmed: bool = False
    confirmed_by: list[str] = Field(default_factory=list)
    # Filled in by later stages.
    verdict: Optional[str] = None  # confirmed, false_positive
    triage_reason: Optional[str] = None
    triage_confidence: Optional[str] = None
    final_severity: Optional[str] = None


class StaticFixRecord(BaseModel):
    """A generated remediation for a confirmed finding."""
    finding_id: Optional[int] = None
    file: str = ""
    line: int = 0
    category: str = ""
    severity: str = ""
    rule_id: str = ""
    tool_source: str = ""
    diff_text: str = ""
    explanation: str = ""
    # Whether the fix was grounded in a paired safe example, a category match,
    # or generated without a retrieved reference.
    grounded_in: str = "none"


class ToolRunStatus(BaseModel):
    """Execution outcome for one scanner."""
    tool: str
    ok: bool = False
    finding_count: int = 0
    note: str = ""
    used_sample: bool = False
    duration_s: float = 0.0


class StaticAnalysisReport(BaseModel):
    """The final output of the Static Analysis flow."""
    # The scanned target — a local path, or the repo URL for a cloned scan.
    target_path: str
    # Set only when the scan targeted a remote Git repo (else "").
    source_repo: str = ""
    scan_timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    codeql_language: str = ""

    # Per-tool accounting: raw findings, how many survived the merge, runtime.
    findings_per_tool: dict = Field(default_factory=dict)
    tool_status: dict = Field(default_factory=dict)

    # Merge / dedup accounting.
    total_raw_findings: int = 0
    total_after_merge: int = 0
    duplicates_removed: int = 0
    multi_tool_confirmed_count: int = 0
    with_taint_path_count: int = 0

    # Triage outcome.
    confirmed_count: int = 0
    ruled_out_count: int = 0
    not_triaged_count: int = 0
    fixes_count: int = 0

    severity_breakdown: dict = Field(default_factory=dict)
    category_breakdown: dict = Field(default_factory=dict)

    confirmed_findings: list[dict] = Field(default_factory=list)
    ruled_out_findings: list[dict] = Field(default_factory=list)
    safe_patterns: list[dict] = Field(default_factory=list)
    fixes: list[dict] = Field(default_factory=list)

    # Confirmed CodeQL findings with their full source → sink chains.
    codeql_taint_evidence: list[dict] = Field(default_factory=list)

    summary: str = ""
    errors: list[str] = Field(default_factory=list)
