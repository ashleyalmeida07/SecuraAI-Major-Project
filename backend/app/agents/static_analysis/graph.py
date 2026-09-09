"""LangGraph construction for the Static Analysis flow.

    ┌──────────┐
    │ dispatch │  resolves target_path + CodeQL language
    └────┬─────┘
         │  five parallel edges — one superstep, no inter-dependencies
         ├──► run_semgrep ─────┐
         ├──► run_bearer ──────┤
         ├──► run_osv_scanner ─┼──► merge_findings ──► retrieve_context
         ├──► run_gitleaks ────┤        (barrier)          (RAG)
         └──► run_codeql ──────┘                              │
                                                              ▼
                              ┌──────────────────────────► triage ◄──────┐
                              │                              │           │
                     (no findings)                    route_verdict      │
                              │                        ┌─────┴─────┐     │
                              │                        ▼           ▼     │
                              │                confirm_finding  discard_finding
                              │                        └─────┬─────┘     │
                              │                     route_triage_loop ───┘
                              │                              │ (all done)
                              ▼                              ▼
                        report_builder ◄──────────────── fix_generator
                              │
                              ▼
                             END
"""

from langgraph.graph import END, StateGraph

from app.agents.static_analysis.nodes import (
    confirm_finding,
    discard_finding,
    dispatch_scan,
    fix_generator,
    merge_findings,
    report_builder,
    retrieve_context,
    route_triage_loop,
    route_triage_start,
    route_verdict,
    run_bearer,
    run_codeql,
    run_gitleaks,
    run_osv_scanner,
    run_semgrep,
    triage,
)
from app.agents.static_analysis.state import StaticAnalysisState

# Scanner node name → callable. Declared here so the fan-out edges and the
# fan-in barrier stay in sync automatically if a sixth tool is ever added.
SCANNER_NODES = {
    "run_semgrep": run_semgrep,
    "run_bearer": run_bearer,
    "run_osv_scanner": run_osv_scanner,
    "run_gitleaks": run_gitleaks,
    "run_codeql": run_codeql,
}


def build_static_analysis_graph():
    """Build and compile the Static Analysis LangGraph."""
    workflow = StateGraph(StaticAnalysisState)

    # ── Entry + fan-out ──
    workflow.add_node("dispatch", dispatch_scan)
    for name, node in SCANNER_NODES.items():
        workflow.add_node(name, node)

    # ── Fan-in + triage loop + reporting ──
    workflow.add_node("merge_findings", merge_findings)
    workflow.add_node("retrieve_context", retrieve_context)
    workflow.add_node("triage", triage)
    workflow.add_node("confirm_finding", confirm_finding)
    workflow.add_node("discard_finding", discard_finding)
    workflow.add_node("fix_generator", fix_generator)
    workflow.add_node("report_builder", report_builder)

    workflow.set_entry_point("dispatch")

    # All five scanners hang off `dispatch` and feed `merge_findings`. LangGraph
    # runs same-superstep nodes concurrently and treats a node with multiple
    # incoming edges as a barrier, so the merge waits for all five without any
    # explicit synchronization.
    for name in SCANNER_NODES:
        workflow.add_edge("dispatch", name)
        workflow.add_edge(name, "merge_findings")

    workflow.add_edge("merge_findings", "retrieve_context")

    # Nothing to triage → straight to the report.
    workflow.add_conditional_edges(
        "retrieve_context",
        route_triage_start,
        {"triage": "triage", "report_builder": "report_builder"},
    )

    # One finding per iteration: classify, then branch on the verdict. Both
    # branches persist the LLM's reasoning before looping.
    workflow.add_conditional_edges(
        "triage",
        route_verdict,
        {"confirm": "confirm_finding", "discard": "discard_finding"},
    )
    for branch in ("confirm_finding", "discard_finding"):
        workflow.add_conditional_edges(
            branch,
            route_triage_loop,
            {"triage": "triage", "fix_generator": "fix_generator"},
        )

    workflow.add_edge("fix_generator", "report_builder")
    workflow.add_edge("report_builder", END)

    return workflow.compile()


def triage_recursion_limit(max_triage: int) -> int:
    """Recursion limit needed to triage `max_triage` findings.

    Each finding costs two supersteps (triage → confirm/discard), plus a fixed
    overhead for dispatch, the scanner superstep, merge, RAG, fixes and the
    report. LangGraph's default limit of 25 would abort the loop after a handful
    of findings, so callers must pass this through as `recursion_limit`.
    """
    return max(50, (max(0, max_triage) * 2) + 20)


# Instantiate the compiled graph so it can be imported and run
static_analysis_graph = build_static_analysis_graph()
