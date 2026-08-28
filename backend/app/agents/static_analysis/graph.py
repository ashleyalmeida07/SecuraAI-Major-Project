"""LangGraph construction for the Static Analysis flow."""

from langgraph.graph import StateGraph, END

from app.agents.static_analysis.state import StaticAnalysisState
from app.agents.static_analysis.nodes import (
    run_semgrep,
    retrieve_context,
    triage_findings,
    conditional_triage_router,
    generate_fix
)


def build_static_analysis_graph():
    """Build and compile the Static Analysis LangGraph."""
    workflow = StateGraph(StaticAnalysisState)

    # Add nodes
    workflow.add_node("scanner", run_semgrep)
    workflow.add_node("context_retriever", retrieve_context)
    workflow.add_node("triage", triage_findings)
    workflow.add_node("generate_fix", generate_fix)

    # Build the linear part of the flow
    workflow.set_entry_point("scanner")
    workflow.add_edge("scanner", "context_retriever")
    workflow.add_edge("context_retriever", "triage")

    # Add conditional routing
    # If the LLM finds real issues, go to generate_fix. Else, end.
    workflow.add_conditional_edges(
        "triage",
        conditional_triage_router,
        {
            "generate_fix": "generate_fix",
            "__end__": END
        }
    )
    
    # End after fixes are generated
    workflow.add_edge("generate_fix", END)

    return workflow.compile()

# Instantiate the compiled graph so it can be imported and run
static_analysis_graph = build_static_analysis_graph()
