"""LangGraph compiled graph for the Security Header & Cookie Audit flow.

Pipeline:  START → header_fetcher → rule_checker → severity_scorer → END
"""

from langgraph.graph import StateGraph, START, END

from app.agents.header_audit.state import HeaderAuditState
from app.agents.header_audit.nodes import (
    header_fetcher_node,
    rule_checker_node,
    severity_scorer_node,
)

# ── Build the graph ──────────────────────────────────────────────────────────

builder = StateGraph(HeaderAuditState)

builder.add_node("header_fetcher", header_fetcher_node)
builder.add_node("rule_checker", rule_checker_node)
builder.add_node("severity_scorer", severity_scorer_node)

builder.add_edge(START, "header_fetcher")
builder.add_edge("header_fetcher", "rule_checker")
builder.add_edge("rule_checker", "severity_scorer")
builder.add_edge("severity_scorer", END)

header_audit_graph = builder.compile()
