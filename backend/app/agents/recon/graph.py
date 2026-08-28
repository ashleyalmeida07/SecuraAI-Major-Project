"""LangGraph compiled graph for the Recon & Surface Mapping flow.

Pipeline:  START → crawler → classifier → surface_report → END
"""

from langgraph.graph import StateGraph, START, END

from app.agents.recon.state import ReconState
from app.agents.recon.nodes import (
    crawler_node,
    classifier_node,
    surface_report_node,
)

# ── Build the graph ──────────────────────────────────────────────────────────

builder = StateGraph(ReconState)

builder.add_node("crawler", crawler_node)
builder.add_node("classifier", classifier_node)
builder.add_node("surface_report", surface_report_node)

builder.add_edge(START, "crawler")
builder.add_edge("crawler", "classifier")
builder.add_edge("classifier", "surface_report")
builder.add_edge("surface_report", END)

recon_graph = builder.compile()
