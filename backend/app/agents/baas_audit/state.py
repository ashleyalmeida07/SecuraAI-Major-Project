"""LangGraph state definition for the BaaS Misconfiguration Scanner agent."""

import operator
from typing import Annotated, TypedDict


class BaaSAuditState(TypedDict):
    target_url: str
    discovered_urls: list[str]          # from recon crawler
    network_requests: list[dict]        # captured browser requests
    baas_provider: str                  # "supabase" | "firebase" | "none"
    project_url: str                    # e.g. https://xyz.supabase.co
    anon_key: str                       # the public anon key extracted
    firebase_config: dict               # extracted firebase config if Firebase
    tables: list[str]                   # discovered table/collection names
    read_results: list[dict]            # per-table read-access test results
    write_results: list[dict]           # per-table write-access test results
    storage_results: list[dict]         # storage bucket test results
    auth_results: dict                  # signup/auth config test results
    baas_audit_report: dict             # final report
    errors: Annotated[list[str], operator.add]
