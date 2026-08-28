"""LangGraph state schema for the Injection Testing flow."""

import operator
from typing import Annotated, TypedDict


class InjectionState(TypedDict):
    """Shared state that flows through every node in the Injection graph.

    Keys:
        target_url:          The URL being tested (input).
        endpoints:           Endpoint + parameter pairs from Recon output.
        current_index:       Which endpoint/param pair we're testing (loop counter).
        test_cases:          Generated payloads for the current endpoint.
        injection_results:   Raw baseline vs payload comparison results.
        confirmed_findings:  LLM-confirmed real vulnerabilities.
        discarded:           LLM-discarded false positives.
        injection_report:    The final structured injection report.
        errors:              Accumulated error messages (uses add reducer).
    """
    target_url: str
    endpoints: list[dict]
    current_index: int
    test_cases: list[dict]
    injection_results: list[dict]
    confirmed_findings: list[dict]
    discarded: list[dict]
    injection_report: dict
    errors: Annotated[list[str], operator.add]
