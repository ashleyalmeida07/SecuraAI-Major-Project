"""
LangGraph graph definition for the LLM Prompt-Injection Audit agent.

Flow:
  START → detector → connect → attacker → judge → router
  router "retry"   → mutation → attacker
  router "advance" → attacker  (inc attack_index, stays in loop)
  router "done"    → report_builder → END
"""

from langgraph.graph import END, START, StateGraph

from app.agents.llm_audit.nodes import (  # noqa: F401 — re-exported for scan.py
    ATTACK_CATEGORIES,
    attacker_node,
    connect_node,
    detector_node,
    judge_node,
    mutation_node,
    report_builder_node,
)
from app.agents.llm_audit.state import LLMAuditState


# ---------------------------------------------------------------------------
# Router / conditional-edge logic
# ---------------------------------------------------------------------------


def _route_after_judge(state: LLMAuditState) -> str:
    """
    Decide what to do after the judge has evaluated the last attack:

    - "retry"   → last result was PASS (blocked) and mutation_count < 3
                  → go through mutation_node then back to attacker
    - "advance" → last result was FAIL or mutation_count >= 3
                  → advance attack_index and loop back to attacker (or finish)
    - "done"    → all categories exhausted
    """
    attack_index = state.get("attack_index", 0)
    mutation_count = state.get("mutation_count", 0)
    attack_results = state.get("attack_results", [])

    # If index already beyond all categories, we're done
    if attack_index >= len(ATTACK_CATEGORIES):
        return "done"

    last_verdict = ""
    if attack_results:
        last_verdict = attack_results[-1].get("verdict", "")

    # Check if all prompts in the current category have been attempted
    category = ATTACK_CATEGORIES[attack_index]
    tried_in_cat = {
        r["prompt"]
        for r in attack_results
        if r.get("category_id") == category["id"]
        and r.get("verdict") != "pending"
    }
    all_prompts_tried = tried_in_cat.issuperset(set(category["prompts"]))

    if last_verdict == "fail":
        # Vulnerability confirmed → move to next category
        return "advance"

    if last_verdict == "pass" and mutation_count < 3 and not all_prompts_tried:
        # Blocked but can still mutate/retry
        return "retry"

    # mutation_count >= 3 or all prompts tried or error verdict
    return "advance"


def _route_after_advance(state: LLMAuditState) -> str:
    """After advancing attack_index decide: more categories ("loop") or "done"."""
    attack_index = state.get("attack_index", 0)
    if attack_index >= len(ATTACK_CATEGORIES):
        return "done"
    return "loop"


# ---------------------------------------------------------------------------
# Thin wrapper nodes for routing-related state mutations
# ---------------------------------------------------------------------------


async def _advance_index_node(state: LLMAuditState) -> dict:
    """Increment attack_index and reset mutation_count."""
    return {
        "attack_index": state.get("attack_index", 0) + 1,
        "mutation_count": 0,
    }


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def _build_graph() -> StateGraph:
    g = StateGraph(LLMAuditState)

    # Register nodes
    g.add_node("detector", detector_node)
    g.add_node("connect", connect_node)
    g.add_node("attacker", attacker_node)
    g.add_node("judge", judge_node)
    g.add_node("mutation", mutation_node)
    g.add_node("advance_index", _advance_index_node)
    g.add_node("report_builder", report_builder_node)

    # Fixed edges
    g.add_edge(START, "detector")
    g.add_edge("detector", "connect")
    g.add_edge("connect", "attacker")
    g.add_edge("attacker", "judge")

    # After judge: retry (mutate) | advance | done
    g.add_conditional_edges(
        "judge",
        _route_after_judge,
        {
            "retry": "mutation",
            "advance": "advance_index",
            "done": "report_builder",
        },
    )

    # After mutation → back to attacker for the rephrased prompt
    g.add_edge("mutation", "attacker")

    # After advancing index: loop back to attacker or finish
    g.add_conditional_edges(
        "advance_index",
        _route_after_advance,
        {
            "loop": "attacker",
            "done": "report_builder",
        },
    )

    g.add_edge("report_builder", END)

    return g


_graph = _build_graph()
llm_audit_graph = _graph.compile()
# Allow deep attack loops (5 categories × up to 5 prompts × 3 mutations + overhead)
llm_audit_graph.config = {"recursion_limit": 50}
