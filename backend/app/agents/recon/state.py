"""LangGraph state schema for the Recon & Surface Mapping flow."""

import operator
from typing import Annotated, TypedDict


class ReconState(TypedDict):
    """Shared state that flows through every node in the Recon graph.

    Keys:
        target_url:             The URL to crawl (input).
        max_depth:              How many link-levels deep to follow (input).
        discovered_urls:        Raw list of URLs + metadata found by the crawler.
        classified_endpoints:   Endpoints after LLM classification.
        surface_report:         The final structured attack-surface report.
        errors:                 Accumulated error messages (uses add reducer).
    """
    target_url: str
    max_depth: int
    discovered_urls: list[dict]
    classified_endpoints: list[dict]
    surface_report: dict
    errors: Annotated[list[str], operator.add]
