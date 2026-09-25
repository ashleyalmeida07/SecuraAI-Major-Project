"""FastAPI router for scan operations.

Endpoints:
    POST /scan/recon     — Run Flow 1 (Recon & Surface Mapping) only.
    POST /scan/headers   — Run Flow 2 (Header Audit) only.
    POST /scan/full      — Run Flow 1 → Flow 2 chained (full pipeline).
"""

from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from fastapi.responses import StreamingResponse
import json
import asyncio
import datetime
import os
import tarfile
import tempfile
import traceback
from app.models.schemas import ScanRequest, HeaderScanRequest, StaticScanRequest, InjectionScanRequest
from app.agents.recon.graph import recon_graph
from app.agents.header_audit.graph import header_audit_graph
from app.agents.static_analysis.graph import static_analysis_graph, triage_recursion_limit
from app.agents.static_analysis.tools import cleanup_clone
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
            "checklist_results": [],
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
            "checklist_results": [],
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
    """Run the Static Analysis flow: 5 scanners → merge → RAG triage → fixes.

    Fans out to Semgrep, Bearer, OSV-Scanner, Gitleaks and CodeQL in parallel,
    merges their findings into one deduplicated set, triages each one against
    Upstash Vector context, and generates fixes for the confirmed issues.
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

        result = await static_analysis_graph.ainvoke(
            _static_initial_state(
                request.target_path,
                request.include_codeql,
                request.codeql_language,
                request.max_triage,
                scan.id,
                flow.id,
            ),
            config={"recursion_limit": triage_recursion_limit(request.max_triage)},
        )

        report = result.get("static_report", {})

        # report_builder already marks both rows completed; this covers the
        # early-exit paths where it did not run.
        if flow.status != "completed":
            flow.status = "completed"
            scan.status = "completed"
            db.commit()

        return {
            "status": "success",
            "static_analysis_report": report,
            # Flat aliases kept for older clients.
            "triaged_findings": report.get("confirmed_findings", []),
            "false_positives": report.get("ruled_out_findings", []),
            "safe_patterns": report.get("safe_patterns", []),
            "fixes": report.get("fixes", []),
            "errors": result.get("errors", []),
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Static analysis failed: {str(e)}")
    finally:
        db.close()


def _static_initial_state(
    target_path: str,
    include_codeql: bool,
    codeql_language: str,
    max_triage: int,
    scan_id: int,
    flow_run_id: int,
) -> dict:
    """Initial graph state shared by the streaming and non-streaming endpoints."""
    return {
        "target_path": target_path,
        "scan_id": scan_id,
        "flow_run_id": flow_run_id,
        "include_codeql": include_codeql,
        "codeql_language": codeql_language,
        "max_triage": max_triage,
        "semgrep_results": [],
        "bearer_results": [],
        "osv_results": [],
        "gitleaks_results": [],
        "codeql_results": [],
        "tool_status": {},
        "merged_findings": [],
        "merge_stats": {},
        "safe_patterns": [],
        "triage_index": 0,
        "triaged_findings": [],
        "false_positives": [],
        "fixes": [],
        "static_report": {},
        "errors": [],
    }


# ── Upload transport (npm CLI, transport #3) ────────────────────────────────
# Uploaded archives are untrusted: cap what an extraction may produce and refuse
# any member that would escape the destination or is not a plain file/dir.
MAX_UPLOAD_UNCOMPRESSED = 500 * 1024 * 1024  # 500 MB, decompressed
MAX_UPLOAD_FILES = 50_000


def _is_within(base: str, target: str) -> bool:
    """True iff `target` resolves to `base` or a path underneath it."""
    base = os.path.abspath(base)
    target = os.path.abspath(target)
    return target == base or target.startswith(base + os.sep)


def _safe_extract_tar(archive_path: str, dest_root: str) -> None:
    """Extract a .tar.gz into dest_root, refusing traversal and link members.

    Guards against Zip-Slip (members like ``../../etc/passwd`` or absolute paths)
    and planted symlinks/hardlinks/devices. Only regular files and directories
    whose resolved path stays under ``dest_root`` are written; total uncompressed
    size and file count are capped. Raises ValueError on anything unsafe.
    """
    dest_root_abs = os.path.abspath(dest_root)
    total = 0
    count = 0
    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar:
            count += 1
            if count > MAX_UPLOAD_FILES:
                raise ValueError("archive contains too many entries")
            # Never materialize links or device/fifo nodes from untrusted input.
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                continue
            target = os.path.join(dest_root_abs, member.name)
            if not _is_within(dest_root_abs, target):
                raise ValueError(f"unsafe path in archive: {member.name!r}")
            if member.isreg():
                total += member.size
                if total > MAX_UPLOAD_UNCOMPRESSED:
                    raise ValueError("archive is too large when uncompressed")
            # `filter="data"` (Python 3.12+) is a second, stdlib-maintained guard:
            # it strips leading slashes, clears setuid/dev bits and re-checks paths.
            tar.extract(member, dest_root_abs, filter="data")


async def _static_event_stream(
    target_path: str,
    include_codeql: bool,
    codeql_language: str,
    max_triage: int,
    cleanup=None,
):
    """Shared SSE generator for the JSON and upload static-analysis endpoints.

    Emits a node_update per completed node. Because the five scanners run in one
    superstep, each finishing tool streams its own event — so the four fast tools'
    results render while CodeQL is still building its database. ``cleanup`` (if
    given) is invoked once the stream ends, for temp-dir removal after an upload.
    """
    with SessionLocal() as db:
        scan = Scan(target=target_path, scan_type="static")
        db.add(scan)
        db.commit()
        scan_id = scan.id

        flow = FlowRun(scan_id=scan.id, flow_name="static_analysis")
        db.add(flow)
        db.commit()
        flow_id = flow.id

    try:
        yield f"data: {json.dumps({'event': 'start', 'message': 'Starting Static Analysis Flow...'})}\n\n"

        static_accumulated: dict = {}
        async for chunk in static_analysis_graph.astream(
            _static_initial_state(
                target_path, include_codeql, codeql_language, max_triage, scan.id, flow.id
            ),
            config={"recursion_limit": triage_recursion_limit(max_triage)},
        ):
            for node_name, state_update in chunk.items():
                static_accumulated.update(state_update)
                event_data = {
                    "event": "node_update",
                    "node": node_name,
                    "state": state_update,
                }
                # default=str guards against any non-JSON-native values that
                # may ride along on DB-derived findings.
                yield f"data: {json.dumps(event_data, default=str)}\n\n"
                await asyncio.sleep(0.05)

        with SessionLocal() as db:
            scan = db.query(Scan).get(scan_id)
            flow = db.query(FlowRun).get(flow_id)
            if flow.status != "completed":
                flow.status = "completed"
                scan.status = "completed"
                scan.finished_at = datetime.datetime.utcnow()
                scan.raw_data = {
                    "static_analysis_report": static_accumulated.get("static_report", {})
                }
                db.commit()

        yield f"data: {json.dumps({'event': 'complete', 'message': 'Static Analysis Complete!', 'scan_id': str(scan_id)})}\n\n"
    except BaseException as e:
        with SessionLocal() as db:
            scan = db.query(Scan).get(scan_id)
            flow = db.query(FlowRun).get(flow_id)
            if 'static_accumulated' in locals() and static_accumulated.get("static_report"):
                flow.status = "completed"
                scan.status = "completed"
                scan.finished_at = datetime.datetime.utcnow()
                scan.raw_data = {"static_analysis_report": static_accumulated["static_report"]}
                db.commit()
            else:
                if flow and flow.status != "completed":
                    flow.status = "failed"
                if scan and scan.status != "completed":
                    scan.status = "failed"
                db.commit()
        traceback.print_exc()
        yield f"data: {json.dumps({'event': 'error', 'message': repr(e)})}\n\n"
    finally:
        if cleanup is not None:
            try:
                cleanup()
            except Exception:
                traceback.print_exc()


@scan_router.post("/stream/static")
async def stream_static_analysis(request: StaticScanRequest):
    """Stream the Static Analysis flow via SSE.

    ``target_path`` is a Git URL / ``owner/repo`` shorthand (the backend clones
    it) or a filesystem path reachable by the backend (scanned in place). For the
    upload transport used by remote backends, see ``/stream/static/upload``.
    """
    return StreamingResponse(
        _static_event_stream(
            request.target_path,
            request.include_codeql,
            request.codeql_language,
            request.max_triage,
        ),
        media_type="text/event-stream",
    )


@scan_router.post("/stream/static/upload")
async def stream_static_analysis_upload(
    file: UploadFile = File(...),
    include_codeql: bool = Form(True),
    codeql_language: str = Form(""),
    max_triage: int = Form(25),
):
    """Stream the Static Analysis flow over an uploaded ``.tar.gz`` of the code.

    Used by the npm CLI when the backend is remote (or ``--upload`` is passed):
    the client packages the local directory and posts it here. We safe-extract it
    to a temp dir, scan that copy, and delete the temp dir when the stream ends.
    """
    workdir = tempfile.mkdtemp(prefix="secura_upload_")
    src_root = os.path.join(workdir, "src")
    os.makedirs(src_root, exist_ok=True)
    archive_path = os.path.join(workdir, "upload.tar.gz")

    try:
        # Stream the upload to disk in 1 MB chunks (don't buffer it all in memory).
        with open(archive_path, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
        # Extract off the event loop — a large archive would otherwise block it.
        await asyncio.to_thread(_safe_extract_tar, archive_path, src_root)
        os.remove(archive_path)  # reclaim space before the scan runs
    except Exception as e:
        cleanup_clone(workdir)
        message = f"Upload rejected: {e}"

        async def _error_stream():
            yield f"data: {json.dumps({'event': 'error', 'message': message})}\n\n"

        return StreamingResponse(_error_stream(), media_type="text/event-stream")

    return StreamingResponse(
        _static_event_stream(
            src_root,
            include_codeql,
            codeql_language,
            max_triage,
            cleanup=lambda: cleanup_clone(workdir),
        ),
        media_type="text/event-stream",
    )


@scan_router.post("/stream/recon")
async def stream_recon(request: ScanRequest):
    """Stream Flow 1: Recon & Surface Mapping using SSE."""
    
    async def event_generator():
        with SessionLocal() as db:
            scan = Scan(target=request.url, scan_type="recon", status="running")
            db.add(scan)
            db.commit()
            scan_id = scan.id

        try:

            yield f"data: {json.dumps({'event': 'start', 'message': 'Starting Recon Flow...'})}\n\n"
            
            recon_accumulated: dict = {}
            async for chunk in recon_graph.astream({
                "target_url": request.url,
                "max_depth": request.max_depth,
                "discovered_urls": [],
                "classified_endpoints": [],
                "surface_report": {},
                "errors": [],
            }):
                for node_name, state_update in chunk.items():
                    recon_accumulated.update(state_update)
                    event_data = {
                        "event": "node_update",
                        "node": node_name,
                        "state": state_update
                    }
                    yield f"data: {json.dumps(event_data)}\n\n"
                    await asyncio.sleep(0.1)
            
            with SessionLocal() as db:
                scan = db.query(Scan).get(scan_id)
                scan.status = "completed"
                scan.finished_at = datetime.datetime.utcnow()
                scan.raw_data = {
                    "surface_report": recon_accumulated.get("surface_report", {})
                }
                db.commit()

            yield f"data: {json.dumps({'event': 'complete', 'message': 'Recon Flow Complete!', 'scan_id': str(scan_id)})}\n\n"
        except BaseException as e:
            with SessionLocal() as db:
                scan = db.query(Scan).get(scan_id)
                if 'recon_accumulated' in locals() and recon_accumulated.get("surface_report"):
                    scan.status = "completed"
                    scan.finished_at = datetime.datetime.utcnow()
                    scan.raw_data = {"surface_report": recon_accumulated["surface_report"]}
                    db.commit()
                elif scan.status == "running":
                    scan.status = "failed"
                    db.commit()
            yield f"data: {json.dumps({'event': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@scan_router.post("/stream/full")
async def stream_full_scan(request: ScanRequest):
    """Stream Flow 1 (Recon) -> Flow 2 (Header Audit) using SSE."""
    
    async def event_generator():
        with SessionLocal() as db:
            scan = Scan(target=request.url, scan_type="full", status="running")
            db.add(scan)
            db.commit()
            scan_id = scan.id

        try:
            yield f"data: {json.dumps({'event': 'start', 'message': 'Starting Full Scan Flow...'})}\n\n"

            recon_accumulated: dict = {}
            async for chunk in recon_graph.astream({
                "target_url": request.url,
                "max_depth": request.max_depth,
                "discovered_urls": [],
                "classified_endpoints": [],
                "surface_report": {},
                "errors": [],
            }):
                for node_name, state_update in chunk.items():
                    recon_accumulated.update(state_update)
                    event_data = {
                        "event": "node_update",
                        "node": node_name,
                        "state": state_update,
                    }
                    yield f"data: {json.dumps(event_data)}\n\n"
                    await asyncio.sleep(0.1)

            endpoints = recon_accumulated.get("classified_endpoints", [])
            yield f"data: {json.dumps({'event': 'handoff', 'message': f'Passing {len(endpoints)} endpoint(s) to Header Audit...'})}\n\n"

            audit_accumulated: dict = {}
            async for chunk in header_audit_graph.astream({
                "target_url": request.url,
                "endpoints": endpoints,
                "header_results": [],
                "checklist_results": [],
                "scored_findings": [],
                "audit_report": {},
                "errors": [],
            }):
                for node_name, state_update in chunk.items():
                    audit_accumulated.update(state_update)
                    event_data = {
                        "event": "node_update",
                        "node": node_name,
                        "state": state_update,
                    }
                    yield f"data: {json.dumps(event_data)}\n\n"
                    await asyncio.sleep(0.1)

            with SessionLocal() as db:
                scan = db.query(Scan).get(scan_id)
                scan.status = "completed"
                scan.finished_at = datetime.datetime.utcnow()
                scan.raw_data = {
                    "surface_report": recon_accumulated.get("surface_report", {}),
                    "header_audit_report": audit_accumulated.get("audit_report", {})
                }
                db.commit()

            yield f"data: {json.dumps({'event': 'complete', 'message': 'Full Scan Complete!', 'scan_id': str(scan_id)})}\n\n"
        except BaseException as e:
            with SessionLocal() as db:
                scan = db.query(Scan).get(scan_id)
                if 'audit_accumulated' in locals() and audit_accumulated.get("audit_report"):
                    scan.status = "completed"
                    scan.finished_at = datetime.datetime.utcnow()
                    scan.raw_data = {
                        "surface_report": recon_accumulated.get("surface_report", {}),
                        "header_audit_report": audit_accumulated["audit_report"]
                    }
                    db.commit()
                elif scan.status == "running":
                    scan.status = "failed"
                    db.commit()
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
        with SessionLocal() as db:
            scan = Scan(target=request.url, scan_type="injection", status="running")
            db.add(scan)
            db.commit()
            scan_id = scan.id

        try:
            yield f"data: {json.dumps({'event': 'start', 'message': 'Starting Injection Testing Flow...'})}\n\n"

            endpoints = request.endpoints
            recon_accumulated: dict = {}

            # If no endpoints, run recon first
            if not endpoints:
                yield f"data: {json.dumps({'event': 'start', 'message': 'No endpoints provided. Running Recon first...'})}\n\n"

                # LangGraph astream yields each NODE's partial delta — accumulate
                # all of them so classified_endpoints (written by classifier_node)
                # isn't lost when surface_report_node runs last.
                async for chunk in recon_graph.astream({
                    "target_url": request.url,
                    "max_depth": request.max_depth,
                    "discovered_urls": [],
                    "classified_endpoints": [],
                    "surface_report": {},
                    "errors": [],
                }):
                    for node_name, state_update in chunk.items():
                        recon_accumulated.update(state_update)
                        event_data = {
                            "event": "node_update",
                            "node": node_name,
                            "state": state_update,
                        }
                        yield f"data: {json.dumps(event_data)}\n\n"
                        await asyncio.sleep(0.1)

                endpoints = recon_accumulated.get("classified_endpoints", [])
                yield f"data: {json.dumps({'event': 'handoff', 'message': f'Recon found {len(endpoints)} endpoints. Starting injection tests...'})}\n\n"

            # Filter to injectable endpoints
            injectable = [ep for ep in endpoints if ep.get("endpoint_type") not in ("static_asset",)]

            injection_accumulated: dict = {}
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
                    injection_accumulated.update(state_update)
                    event_data = {
                        "event": "node_update",
                        "node": node_name,
                        "state": state_update
                    }
                    yield f"data: {json.dumps(event_data)}\n\n"
                    await asyncio.sleep(0.1)

            with SessionLocal() as db:
                scan = db.query(Scan).get(scan_id)
                scan.status = "completed"
                scan.finished_at = datetime.datetime.utcnow()
                raw_data = {
                    "injection_report": injection_accumulated.get("injection_report", {})
                }
                if not request.endpoints:
                    raw_data["surface_report"] = recon_accumulated.get("surface_report", {})
                scan.raw_data = raw_data
                db.commit()

            yield f"data: {json.dumps({'event': 'complete', 'message': 'Injection Testing Complete!', 'scan_id': str(scan_id)})}\n\n"
        except BaseException as e:
            with SessionLocal() as db:
                scan = db.query(Scan).get(scan_id)
                if 'injection_accumulated' in locals() and injection_accumulated.get("injection_report"):
                    scan.status = "completed"
                    scan.finished_at = datetime.datetime.utcnow()
                    raw_data = {"injection_report": injection_accumulated["injection_report"]}
                    if not request.endpoints:
                        raw_data["surface_report"] = recon_accumulated.get("surface_report", {})
                    scan.raw_data = raw_data
                    db.commit()
                elif scan.status == "running":
                    scan.status = "failed"
                    db.commit()
            yield f"data: {json.dumps({'event': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@scan_router.get("/history")
async def get_scan_history():
    """Fetch all completed scan reports for the dashboard."""
    db = SessionLocal()
    try:
        scans = db.query(Scan).filter(Scan.status == "completed", Scan.raw_data.isnot(None)).order_by(Scan.started_at.desc()).all()
        history = []
        for s in scans:
            history.append({
                "id": str(s.id),
                "timestamp": s.started_at.isoformat() + "Z",
                "url": s.target,
                "mode": s.scan_type,
                "data": s.raw_data
            })
        return {"status": "success", "history": history}
    finally:
        db.close()
