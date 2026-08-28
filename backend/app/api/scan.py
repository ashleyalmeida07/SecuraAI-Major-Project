"""FastAPI router for scan operations.

Endpoints:
    POST /scan/recon     — Run Flow 1 (Recon & Surface Mapping) only.
    POST /scan/headers   — Run Flow 2 (Header Audit) only.
    POST /scan/full      — Run Flow 1 → Flow 2 chained (full pipeline).
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
import json
import asyncio
from app.models.schemas import ScanRequest, HeaderScanRequest, StaticScanRequest, InjectionScanRequest
from app.agents.recon.graph import recon_graph
from app.agents.header_audit.graph import header_audit_graph
from app.agents.static_analysis.graph import static_analysis_graph
from app.agents.injection.graph import injection_graph
from app.db.session import SessionLocal
from app.db.models import Scan, FlowRun

scan_router = APIRouter(prefix="/scan", tags=["scan"])


@scan_router.post("/recon")
async def run_recon(request: ScanRequest):
    """Run Flow 1: Recon & Surface Mapping.

    Crawls the target URL, discovers endpoints, classifies them with an LLM,
    and returns a structured attack-surface report.
    """
    try:
        result = await recon_graph.ainvoke({
            "target_url": request.url,
            "max_depth": request.max_depth,
            "discovered_urls": [],
            "classified_endpoints": [],
            "surface_report": {},
            "errors": [],
        })

        return {
            "status": "success",
            "surface_report": result.get("surface_report", {}),
            "errors": result.get("errors", []),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Recon scan failed: {str(e)}")


@scan_router.post("/headers")
async def run_header_audit(request: HeaderScanRequest):
    """Run Flow 2: Security Header & Cookie Audit.

    Takes a list of endpoints (or crawls fresh if empty) and checks
    their response headers against security best practices.
    """
    try:
        endpoints = request.endpoints

        # If no endpoints provided, run recon first to get them
        if not endpoints:
            recon_result = await recon_graph.ainvoke({
                "target_url": request.url,
                "max_depth": 2,
                "max_pages": 15,
                "discovered_urls": [],
                "classified_endpoints": [],
                "surface_report": {},
                "errors": [],
            })
            endpoints = recon_result.get("classified_endpoints", [])

        result = await header_audit_graph.ainvoke({
            "target_url": request.url,
            "endpoints": endpoints,
            "header_results": [],
            "findings": [],
            "scored_findings": [],
            "audit_report": {},
            "errors": [],
        })

        return {
            "status": "success",
            "audit_report": result.get("audit_report", {}),
            "errors": result.get("errors", []),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Header audit failed: {str(e)}")


@scan_router.post("/full")
async def run_full_scan(request: ScanRequest):
    """Run the full pipeline: Flow 1 (Recon) → Flow 2 (Header Audit).

    Crawls the target, classifies endpoints, then audits their security
    headers — returning both the surface report and the audit report.
    """
    try:
        # ── Step 1: Run Recon ──
        recon_result = await recon_graph.ainvoke({
            "target_url": request.url,
            "max_depth": request.max_depth,
            "discovered_urls": [],
            "classified_endpoints": [],
            "surface_report": {},
            "errors": [],
        })

        surface_report = recon_result.get("surface_report", {})
        endpoints = recon_result.get("classified_endpoints", [])
        recon_errors = recon_result.get("errors", [])

        # ── Step 2: Run Header Audit using recon output ──
        audit_result = await header_audit_graph.ainvoke({
            "target_url": request.url,
            "endpoints": endpoints,
            "header_results": [],
            "findings": [],
            "scored_findings": [],
            "audit_report": {},
            "errors": [],
        })

        audit_report = audit_result.get("audit_report", {})
        audit_errors = audit_result.get("errors", [])

        return {
            "status": "success",
            "surface_report": surface_report,
            "header_audit_report": audit_report,
            "errors": recon_errors + audit_errors,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Full scan failed: {str(e)}")


@scan_router.post("/static")
async def run_static_analysis(request: StaticScanRequest):
    """Run Flow: Static Analysis with RAG and LLM Triage.
    
    Runs Semgrep, retrieves context from ChromaDB, triages with LLM, 
    and generates fixes for confirmed vulnerabilities.
    """
    db = SessionLocal()
    try:
        # Create Scan record
        scan = Scan(target=request.target_path, scan_type="static")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        # Create FlowRun record
        flow = FlowRun(scan_id=scan.id, flow_name="static_analysis")
        db.add(flow)
        db.commit()
        db.refresh(flow)
        
        result = await static_analysis_graph.ainvoke({
            "target_path": request.target_path,
            "scan_id": scan.id,
            "flow_run_id": flow.id,
            "semgrep_results": [],
            "triaged_findings": [],
            "false_positives": [],
            "fixes": [],
            "errors": [],
        })

        # Update DB status
        flow.status = "completed"
        scan.status = "completed"
        db.commit()

        return {
            "status": "success",
            "triaged_findings": result.get("triaged_findings", []),
            "false_positives": result.get("false_positives", []),
            "fixes": result.get("fixes", []),
            "errors": result.get("errors", []),
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Static analysis failed: {str(e)}")
    finally:
        db.close()


@scan_router.post("/stream/recon")
async def stream_recon(request: ScanRequest):
    """Stream Flow 1: Recon & Surface Mapping using SSE."""
    
    async def event_generator():
        try:
            # Yield initial state
            yield f"data: {json.dumps({'event': 'start', 'message': 'Starting Recon Flow...'})}\n\n"
            
            # Use astream to get node outputs as they complete
            async for chunk in recon_graph.astream({
                "target_url": request.url,
                "max_depth": request.max_depth,
                "discovered_urls": [],
                "classified_endpoints": [],
                "surface_report": {},
                "errors": [],
            }):
                # chunk is typically a dict with a single key (the node name)
                for node_name, state_update in chunk.items():
                    event_data = {
                        "event": "node_update",
                        "node": node_name,
                        "state": state_update
                    }
                    yield f"data: {json.dumps(event_data)}\n\n"
                    # Small delay to ensure chunking works nicely
                    await asyncio.sleep(0.1)
            
            yield f"data: {json.dumps({'event': 'complete', 'message': 'Recon Flow Complete!'})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'event': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@scan_router.post("/stream/full")
async def stream_full_scan(request: ScanRequest):
    """Stream Flow 1 (Recon) -> Flow 2 (Header Audit) using SSE."""
    
    async def event_generator():
        try:
            yield f"data: {json.dumps({'event': 'start', 'message': 'Starting Full Scan Flow...'})}\n\n"
            
            # --- Flow 1 ---
            recon_final_state = None
            async for chunk in recon_graph.astream({
                "target_url": request.url,
                "max_depth": request.max_depth,
                "discovered_urls": [],
                "classified_endpoints": [],
                "surface_report": {},
                "errors": [],
            }):
                for node_name, state_update in chunk.items():
                    event_data = {
                        "event": "node_update",
                        "node": node_name,
                        "state": state_update
                    }
                    yield f"data: {json.dumps(event_data)}\n\n"
                    recon_final_state = state_update # keep updating to get the last one
                    await asyncio.sleep(0.1)
            
            # Handoff event
            yield f"data: {json.dumps({'event': 'handoff', 'message': 'Passing endpoints to Flow 2...'})}\n\n"
            
            # Extract endpoints from the last state chunk of Flow 1
            # Note: LangGraph state merges, so recon_final_state has what the last node returned
            # Or we can just rely on the fact that `classifier` node returns `classified_endpoints`
            endpoints = recon_final_state.get("classified_endpoints", []) if recon_final_state else []

            # --- Flow 2 ---
            async for chunk in header_audit_graph.astream({
                "target_url": request.url,
                "endpoints": endpoints,
                "header_results": [],
                "findings": [],
                "scored_findings": [],
                "audit_report": {},
                "errors": [],
            }):
                for node_name, state_update in chunk.items():
                    event_data = {
                        "event": "node_update",
                        "node": node_name,
                        "state": state_update
                    }
                    yield f"data: {json.dumps(event_data)}\n\n"
                    await asyncio.sleep(0.1)

            yield f"data: {json.dumps({'event': 'complete', 'message': 'Full Scan Complete!'})}\n\n"
        except Exception as e:
            import traceback
            traceback.print_exc()
            yield f"data: {json.dumps({'event': 'error', 'message': repr(e)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@scan_router.post("/injection")
async def run_injection_scan(request: InjectionScanRequest):
    """Run Flow 3: Injection Testing.

    Takes endpoints from a prior Recon scan (or runs Recon first),
    then tests each endpoint+parameter for injection vulnerabilities.
    """
    try:
        endpoints = request.endpoints

        # If no endpoints provided, run recon first
        if not endpoints:
            recon_result = await recon_graph.ainvoke({
                "target_url": request.url,
                "max_depth": request.max_depth,
                "discovered_urls": [],
                "classified_endpoints": [],
                "surface_report": {},
                "errors": [],
            })
            endpoints = recon_result.get("classified_endpoints", [])

        # Filter to only injectable endpoints (skip static assets)
        injectable = [ep for ep in endpoints if ep.get("endpoint_type") not in ("static_asset",)]

        result = await injection_graph.ainvoke({
            "target_url": request.url,
            "endpoints": injectable,
            "current_index": 0,
            "test_cases": [],
            "injection_results": [],
            "confirmed_findings": [],
            "discarded": [],
            "injection_report": {},
            "errors": [],
        })

        return {
            "status": "success",
            "injection_report": result.get("injection_report", {}),
            "errors": result.get("errors", []),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Injection scan failed: {str(e)}")


@scan_router.post("/stream/injection")
async def stream_injection_scan(request: InjectionScanRequest):
    """Stream Flow 3: Injection Testing using SSE.
    
    Optionally runs Recon first if no endpoints are provided,
    then streams injection testing node-by-node.
    """

    async def event_generator():
        try:
            yield f"data: {json.dumps({'event': 'start', 'message': 'Starting Injection Testing Flow...'})}\n\n"

            endpoints = request.endpoints

            # If no endpoints, run recon first
            if not endpoints:
                yield f"data: {json.dumps({'event': 'start', 'message': 'No endpoints provided. Running Recon first...'})}\n\n"

                recon_final_state = None
                async for chunk in recon_graph.astream({
                    "target_url": request.url,
                    "max_depth": request.max_depth,
                    "discovered_urls": [],
                    "classified_endpoints": [],
                    "surface_report": {},
                    "errors": [],
                }):
                    for node_name, state_update in chunk.items():
                        event_data = {
                            "event": "node_update",
                            "node": node_name,
                            "state": state_update
                        }
                        yield f"data: {json.dumps(event_data)}\n\n"
                        recon_final_state = state_update
                        await asyncio.sleep(0.1)

                endpoints = recon_final_state.get("classified_endpoints", []) if recon_final_state else []
                yield f"data: {json.dumps({'event': 'handoff', 'message': f'Recon found {len(endpoints)} endpoints. Starting injection tests...'})}\n\n"

            # Filter to injectable endpoints
            injectable = [ep for ep in endpoints if ep.get("endpoint_type") not in ("static_asset",)]

            # Stream the injection graph
            async for chunk in injection_graph.astream({
                "target_url": request.url,
                "endpoints": injectable,
                "current_index": 0,
                "test_cases": [],
                "injection_results": [],
                "confirmed_findings": [],
                "discarded": [],
                "injection_report": {},
                "errors": [],
            }):
                for node_name, state_update in chunk.items():
                    event_data = {
                        "event": "node_update",
                        "node": node_name,
                        "state": state_update
                    }
                    yield f"data: {json.dumps(event_data)}\n\n"
                    await asyncio.sleep(0.1)

            yield f"data: {json.dumps({'event': 'complete', 'message': 'Injection Testing Complete!'})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'event': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")
