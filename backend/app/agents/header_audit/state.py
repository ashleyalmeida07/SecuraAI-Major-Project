"""LangGraph state schema for the Security Header & Cookie Audit flow."""

import operator
from typing import Annotated, TypedDict


class HeaderAuditState(TypedDict):
    """Shared state that flows through every node in the Header Audit graph.

    Keys:
        target_url:       The original target URL (for reporting).
        endpoints:        List of endpoint dicts (input — from Flow 1 output).
        header_results:   Raw response headers fetched per endpoint.
        findings:         Deterministic rule-check results.
        scored_findings:  Findings after LLM severity scoring.
        audit_report:     The final structured audit report.
        errors:           Accumulated error messages (uses add reducer).
    """
    target_url: str
    endpoints: list[dict]
    header_results: list[dict]
    findings: list[dict]
    scored_findings: list[dict]
    audit_report: dict
    errors: Annotated[list[str], operator.add]
