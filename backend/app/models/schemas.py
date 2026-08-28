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
    summary: dict = Field(default_factory=dict)  # counts by endpoint_type


# ── Flow 2: Security Header & Cookie Audit ───────────────────────────────────

class HeaderFinding(BaseModel):
    """A single security header or cookie finding."""
    url: str
    header_name: str
    expected: str
    actual: Optional[str] = None
    severity: str = "info"  # critical, high, medium, low, info
    description: str = ""


class HeaderAuditReport(BaseModel):
    """The final output of Flow 2 — the header/cookie audit report."""
    target_url: str
    total_findings: int = 0
    findings: list[HeaderFinding] = Field(default_factory=list)
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
    """Request body for static analysis scan."""
    target_path: str = "."
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
