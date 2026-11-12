"""LangGraph state definition for the LLM Prompt-Injection Audit agent."""

import operator
from typing import Annotated, TypedDict


class LLMAuditState(TypedDict):
    target_url: str
    endpoint_hint: str           # optional user-provided endpoint hint
    ai_surfaces: list[dict]      # detected chat widgets/endpoints
    connect_method: str          # "dom" | "api" | "none"
    connect_config: dict         # how to talk to the AI surface
    attack_index: int            # current attack category index (loop counter)
    attack_results: list[dict]   # results per attack attempt
    mutation_count: int          # how many times we've mutated the current prompt
    llm_audit_report: dict       # final report
    errors: Annotated[list[str], operator.add]
