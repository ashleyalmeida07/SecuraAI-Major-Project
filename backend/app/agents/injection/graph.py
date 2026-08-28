"""LangGraph compiled graph for the Injection Testing flow.

Pipeline:
    START → payload_generator → injector → response_analyzer → should_continue
        should_continue:
            "continue" → payload_generator  (loop back for next endpoint)
            "done"     → report_builder → END
"""

from langgraph.graph import StateGraph, START, END

from app.agents.injection.state import InjectionState
from app.agents.injection.nodes import (
    payload_generator_node,
    injector_node,
    response_analyzer_node,
    should_continue,
    report_builder_node,
)


def build_injection_graph():
    """Build and compile the Injection Testing LangGraph."""
    workflow = StateGraph(InjectionState)

    # Add nodes
    workflow.add_node("payload_generator", payload_generator_node)
    workflow.add_node("injector", injector_node)
    workflow.add_node("response_analyzer", response_analyzer_node)
    workflow.add_node("report_builder", report_builder_node)

    # Linear flow: generate → inject → analyze
    workflow.add_edge(START, "payload_generator")
    workflow.add_edge("payload_generator", "injector")
    workflow.add_edge("injector", "response_analyzer")

    # Conditional loop: continue testing or build report
    workflow.add_conditional_edges(
        "response_analyzer",
        should_continue,
        {
            "continue": "payload_generator",
            "done": "report_builder",
        }
    )

    # End after report is built
    workflow.add_edge("report_builder", END)

    return workflow.compile()


# Instantiate the compiled graph so it can be imported and run
injection_graph = build_injection_graph()
