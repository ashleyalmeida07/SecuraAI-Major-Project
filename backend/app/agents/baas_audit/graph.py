"""
LangGraph graph definition for the BaaS Misconfiguration Scanner agent.

Flow:
  START → detect_baas → (should_continue) → enumerate_tables → read_access →
  write_access → storage_test → auth_config → report_builder → END

If baas_provider == "none" after detect_baas, skip straight to report_builder.
"""

from langgraph.graph import END, START, StateGraph

from app.agents.baas_audit.nodes import (
    auth_config_node,
    detect_baas_node,
    enumerate_tables_node,
    read_access_node,
    report_builder_node,
    storage_test_node,
    write_access_node,
)
from app.agents.baas_audit.state import BaaSAuditState


# ---------------------------------------------------------------------------
# Conditional edge: should we continue scanning or skip to report?
# ---------------------------------------------------------------------------


def _should_continue(state: BaaSAuditState) -> str:
    """After detect_baas: continue if a BaaS provider was found, else skip."""
    if state.get("baas_provider", "none") == "none":
        return "skip"
    return "continue"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def _build_graph() -> StateGraph:
    g = StateGraph(BaaSAuditState)

    # Register nodes
    g.add_node("detect_baas", detect_baas_node)
    g.add_node("enumerate_tables", enumerate_tables_node)
    g.add_node("read_access", read_access_node)
    g.add_node("write_access", write_access_node)
    g.add_node("storage_test", storage_test_node)
    g.add_node("auth_config", auth_config_node)
    g.add_node("report_builder", report_builder_node)

    # START → detect_baas
    g.add_edge(START, "detect_baas")

    # Conditional edge after detect_baas
    g.add_conditional_edges(
        "detect_baas",
        _should_continue,
        {
            "continue": "enumerate_tables",
            "skip": "report_builder",
        },
    )

    # Linear flow: enumerate → read → write → storage → auth → report
    g.add_edge("enumerate_tables", "read_access")
    g.add_edge("read_access", "write_access")
    g.add_edge("write_access", "storage_test")
    g.add_edge("storage_test", "auth_config")
    g.add_edge("auth_config", "report_builder")

    g.add_edge("report_builder", END)

    return g


_graph = _build_graph()
baas_audit_graph = _graph.compile()
