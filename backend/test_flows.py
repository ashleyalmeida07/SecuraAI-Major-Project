"""Quick end-to-end smoke test for BaaS Audit and LLM Audit graphs."""
import asyncio
import json
import sys
import traceback


async def test_baas():
    print("\n" + "=" * 60)
    print("TEST: BaaS Audit Graph")
    print("=" * 60)
    from app.agents.baas_audit.graph import baas_audit_graph

    state = {
        "target_url": "https://kickstart-crypto-nine.vercel.app/",
        "discovered_urls": [],
        "network_requests": [],
        "baas_provider": "",
        "project_url": "",
        "anon_key": "",
        "firebase_config": {},
        "tables": [],
        "read_results": [],
        "write_results": [],
        "storage_results": [],
        "auth_results": {},
        "baas_audit_report": {},
        "errors": [],
    }
    print("Running BaaS audit graph...")
    nodes_seen = []
    async for mode, payload in baas_audit_graph.astream(
        state, {"recursion_limit": 60}, stream_mode=["tasks", "updates"]
    ):
        if mode == "tasks":
            if isinstance(payload, (list, tuple)):
                for t in payload:
                    if t.result is None and t.error is None:
                        print(f"  [START] {t.name}")
                        nodes_seen.append(t.name)
        elif mode == "updates":
            if isinstance(payload, dict):
                for node_name, state_update in payload.items():
                    keys = list(state_update.keys()) if isinstance(state_update, dict) else []
                    print(f"  [UPDATE] {node_name}  keys={keys}")
    print(f"Nodes seen: {nodes_seen}")
    print("BaaS Audit: PASSED")


async def test_llm():
    print("\n" + "=" * 60)
    print("TEST: LLM Audit Graph (detector + connect only)")
    print("=" * 60)
    from app.agents.llm_audit.graph import llm_audit_graph, LLM_AUDIT_RECURSION_LIMIT

    state = {
        "target_url": "https://example.com",
        "endpoint_hint": "",
        "ai_surfaces": [],
        "connect_method": "",
        "connect_config": {},
        "attack_index": 0,
        "attack_results": [],
        "mutation_count": 0,
        "llm_audit_report": {},
        "errors": [],
    }
    print("Running LLM audit graph (will finish quickly since example.com has no AI surfaces)...")
    nodes_seen = []
    async for mode, payload in llm_audit_graph.astream(
        state, {"recursion_limit": LLM_AUDIT_RECURSION_LIMIT}, stream_mode=["tasks", "updates"]
    ):
        if mode == "tasks":
            if isinstance(payload, (list, tuple)):
                for t in payload:
                    if t.result is None and t.error is None:
                        print(f"  [START] {t.name}")
                        nodes_seen.append(t.name)
        elif mode == "updates":
            if isinstance(payload, dict):
                for node_name, state_update in payload.items():
                    keys = list(state_update.keys()) if isinstance(state_update, dict) else []
                    print(f"  [UPDATE] {node_name}  keys={keys}")
    print(f"Nodes seen: {nodes_seen}")
    print("LLM Audit: PASSED")


async def main():
    try:
        await test_baas()
    except Exception:
        print("BaaS Audit: FAILED")
        traceback.print_exc()

    try:
        await test_llm()
    except Exception:
        print("LLM Audit: FAILED")
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
