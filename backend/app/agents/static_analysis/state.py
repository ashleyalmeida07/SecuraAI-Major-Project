"""LangGraph state schema for the Static Analysis flow."""

import operator
from typing import Annotated, TypedDict


class StaticAnalysisState(TypedDict):
    """Shared state for the Static Analysis graph.

    Keys:
        target_path:      The local repository or file path to scan.
        scan_id:          Database scan ID.
        flow_run_id:      Database flow run ID.
        semgrep_results:  Raw findings from Semgrep.
        triaged_findings: Findings confirmed as real issues by the LLM.
        false_positives:  Findings dismissed by the LLM.
        fixes:            Generated code fixes for real issues.
        errors:           Accumulated error messages.
    """
    target_path: str
    scan_id: int
    flow_run_id: int
    semgrep_results: list[dict]
    triaged_findings: list[dict]
    false_positives: list[dict]
    fixes: list[dict]
    errors: Annotated[list[str], operator.add]
