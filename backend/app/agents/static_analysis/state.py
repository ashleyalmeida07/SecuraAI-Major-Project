"""LangGraph state schema for the Static Analysis flow."""

import operator
from typing import Annotated, TypedDict


def merge_dicts(left: dict, right: dict) -> dict:
    """Reducer for state keys written by several parallel nodes at once.

    The five scanner nodes run in the same superstep, so each of them returning
    a partial `tool_status` map would clobber the others under the default
    last-write-wins reducer.
    """
    return {**(left or {}), **(right or {})}


class StaticAnalysisState(TypedDict, total=False):
    """Shared state for the Static Analysis graph.

    Keys:
        target_path:       Local repository or file path to scan.
        source_repo:       Original remote repo URL, when the target was a Git
                           URL rather than a local path (else "").
        cloned_repo_dir:   Temp directory holding the shallow clone, deleted by
                           report_builder once the scan is done (else "").
        scan_id:           NeonDB scan row id.
        flow_run_id:       NeonDB flow_run row id.
        codeql_language:   CodeQL extractor to use ("" → auto-detect).
        include_codeql:    Whether to run the CodeQL node at all.
        max_triage:        Cap on how many merged findings get an LLM triage pass.

        semgrep_results:   Raw normalized findings from Semgrep.
        bearer_results:    Raw normalized findings from Bearer.
        osv_results:       Raw normalized findings from OSV-Scanner.
        gitleaks_results:  Raw normalized findings from Gitleaks.
        codeql_results:    Raw normalized findings from CodeQL (may carry taint paths).
        tool_status:       Per-tool execution report (ran/failed, counts, duration).

        merged_findings:   Deduplicated union of all five tools' findings.
        merge_stats:       Counts before/after dedup, multi-tool overlap totals.
        safe_patterns:     Detected security controls (positive findings).

        triage_index:      Cursor into merged_findings for the triage loop.
        current_finding:   The finding being triaged this iteration.
        triage_progress:   {done, total} counters for live progress display.
        triage_cache:      Verdicts prefetched concurrently for upcoming findings,
                           keyed by stringified index. The triage loop visits one
                           finding per superstep so the UI can render progress, but
                           waiting on one LLM round-trip per superstep would make
                           the whole stage serial — so each cache miss fetches a
                           window of verdicts at once and the following iterations
                           are served from memory. Consumed entries are dropped so
                           the SSE payload stays small.
        triaged_findings:  Findings the LLM confirmed as real, with reasoning.
        false_positives:   Findings the LLM ruled out, with reasoning.
        fixes:             Generated remediation diffs for confirmed findings.
        static_report:     Final summary object written to the API response.
        errors:            Accumulated non-fatal error messages.
    """
    target_path: str
    source_repo: str
    cloned_repo_dir: str
    scan_id: int
    flow_run_id: int
    codeql_language: str
    include_codeql: bool
    max_triage: int

    semgrep_results: list[dict]
    bearer_results: list[dict]
    osv_results: list[dict]
    gitleaks_results: list[dict]
    codeql_results: list[dict]
    tool_status: Annotated[dict, merge_dicts]

    merged_findings: list[dict]
    merge_stats: dict
    safe_patterns: list[dict]

    triage_index: int
    current_finding: dict
    triage_progress: dict
    triage_cache: dict
    triaged_findings: Annotated[list[dict], operator.add]
    false_positives: Annotated[list[dict], operator.add]

    fixes: list[dict]
    static_report: dict
    errors: Annotated[list[str], operator.add]
