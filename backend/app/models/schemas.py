"""Shared Pydantic models for AuthTrack scan workflows."""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


# ── Flow 1: Recon & Surface Mapping ──────────────────────────────────────────

class DiscoveredEndpoint(BaseModel):
    """A single discovered endpoint from the crawl."""
    url: str
    method: str = "GET"
    endpoint_type: str = "unknown"  # auth_page, api, static_asset, form, unknown
    status_code: int = 0
    content_type: Optional[str] = None


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


class HeaderScanRequest(BaseModel):
    """Request body for header-only scan (requires endpoint list)."""
    url: str
    endpoints: list[dict] = Field(default_factory=list)


class StaticScanRequest(BaseModel):
    """Request body for static analysis scan."""
    target_path: str = "."


class FullScanResponse(BaseModel):
    """Combined response from a full scan (Flow 1 + Flow 2)."""
    surface_report: SurfaceReport
    header_audit_report: HeaderAuditReport
