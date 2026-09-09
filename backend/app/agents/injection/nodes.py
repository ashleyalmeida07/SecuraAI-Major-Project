"""Node functions for the Injection Testing LangGraph flow.

Nodes:
    payload_generator_node  — Generates test payloads (SQLi, XSS, etc.) for each endpoint+parameter.
    injector_node           — Sends baseline + payload requests, records response diffs.
    response_analyzer_node  — LLM compares responses and reasons about real flaws.
    report_builder_node     — Assembles the final injection report with recommendations.
    should_continue         — Conditional router: loop or finish.
"""

import httpx
import json
import re
import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from datetime import datetime

from app.agents.injection.state import InjectionState
from app.core.llm import get_llm


# ── Payload Library ──────────────────────────────────────────────────────────

PAYLOADS = {
    "sqli": [
        {"name": "Classic OR", "value": "' OR '1'='1", "detection": "boolean"},
        {"name": "Union probe", "value": "' UNION SELECT NULL--", "detection": "union"},
        {"name": "Error trigger", "value": "' AND 1=CONVERT(int, @@version)--", "detection": "error"},
        {"name": "Time-based blind", "value": "' OR SLEEP(3)--", "detection": "time"},
        {"name": "Double-quote OR", "value": '" OR "1"="1', "detection": "boolean"},
    ],
    "xss": [
        {"name": "Script tag", "value": "<script>alert('XSS')</script>", "detection": "reflection"},
        {"name": "Img onerror", "value": '<img src=x onerror=alert(1)>', "detection": "reflection"},
        {"name": "SVG onload", "value": '<svg onload=alert(1)>', "detection": "reflection"},
        {"name": "Event handler", "value": '" onfocus="alert(1)" autofocus="', "detection": "reflection"},
        {"name": "JS protocol", "value": "javascript:alert(document.domain)", "detection": "reflection"},
    ],
    "command_injection": [
        {"name": "Semicolon ls", "value": "; ls -la", "detection": "output"},
        {"name": "Pipe id", "value": "| id", "detection": "output"},
        {"name": "Backtick whoami", "value": "`whoami`", "detection": "output"},
        {"name": "AND echo", "value": "&& echo INJECTED", "detection": "output"},
    ],
    "path_traversal": [
        {"name": "Dot-dot-slash passwd", "value": "../../etc/passwd", "detection": "file_content"},
        {"name": "Deep traversal", "value": "..%2F..%2F..%2Fetc%2Fpasswd", "detection": "file_content"},
        {"name": "Windows traversal", "value": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "detection": "file_content"},
    ],
}

# SQL error signatures for detection (works in both HTML and JSON responses)
SQL_ERROR_SIGNATURES = [
    "syntax error", "mysql", "mariadb", "postgresql", "sqlite",
    "ora-", "sql server", "unclosed quotation", "quoted string",
    "unterminated", "unexpected end", "you have an error in your sql",
    "warning: mysql", "valid mysql result", "mysqlclient",
    "pg_query", "pg_exec", "sqlstate",
]

# JSON API error field names (FastAPI, Express, Django, etc.)
JSON_ERROR_FIELDS = ["detail", "error", "message", "traceback", "exc_info", "stack"]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_path_segments(url: str) -> list[dict]:
    """Extract injectable path segments from URLs like /api/users/123."""
    parsed = urlparse(url)
    segments = [s for s in parsed.path.split("/") if s]
    targets = []
    for i, seg in enumerate(segments):
        # Look for numeric IDs, UUIDs, or short alphanumeric tokens
        if re.match(r'^(\d+|[0-9a-f]{8,}|[a-zA-Z0-9]{2,8})$', seg) and i > 0:
            targets.append({
                "name": f"path[{i}]:{seg}",
                "location": "path",
                "segment_index": i,
                "original_value": seg,
            })
    return targets


def _detect_json_error(body: str) -> bool:
    """Check if a response body looks like a JSON error from a modern framework."""
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            lower_keys = {k.lower() for k in data.keys()}
            return bool(lower_keys & set(JSON_ERROR_FIELDS))
    except (json.JSONDecodeError, ValueError):
        pass
    return False


def _is_json_content(content_type: str) -> bool:
    """Check if content_type indicates JSON."""
    return "json" in (content_type or "").lower()


# ── Node 1: Payload Generator ────────────────────────────────────────────────

async def payload_generator_node(state: InjectionState) -> dict:
    """Generate test payloads for the current endpoint+parameter pair.

    Supports three injection surfaces:
      - query: Traditional ?param=value query strings
      - body:  HTML form inputs (application/x-www-form-urlencoded)
      - json:  JSON API body payloads (application/json)
      - path:  URL path segments like /api/users/[id]
    """
    endpoints = state.get("endpoints", [])
    current_index = state.get("current_index", 0)

    if current_index >= len(endpoints):
        return {"test_cases": []}

    ep = endpoints[current_index]
    url = ep.get("url", "")
    method = ep.get("method", "GET")
    params = ep.get("parameters", [])
    form_inputs = ep.get("form_inputs", [])
    ep_type = ep.get("endpoint_type", "unknown")
    content_type = ep.get("content_type", "")

    # Combine all injectable targets
    targets = []

    # 1. Query string parameters
    for p in params:
        targets.append({"name": p, "location": "query"})

    # 2. Form inputs (traditional HTML forms)
    for f in form_inputs:
        targets.append({"name": f, "location": "body"})

    # 3. JSON body parameters for API endpoints
    if ep_type in ("api", "api_reference") or _is_json_content(content_type):
        # For JSON APIs, test common parameter names if none discovered
        if not params and not form_inputs:
            for json_param in ["id", "query", "search", "name", "username", "email"]:
                targets.append({"name": json_param, "location": "json"})
        else:
            # Also duplicate existing params as JSON body params
            for p in params:
                targets.append({"name": p, "location": "json"})

    # 4. Path segment parameters (e.g., /api/users/123)
    path_targets = _extract_path_segments(url)
    targets.extend(path_targets)

    # 5. Fallback: if still no targets, try a generic query param
    if not targets:
        targets.append({"name": "q", "location": "query"})

    test_cases = []
    for target in targets:
        # Choose relevant payload categories based on endpoint type
        categories = ["sqli", "xss"]  # always test these
        if ep_type in ("api", "api_reference", "form", "unknown"):
            categories.append("command_injection")
        if ep_type in ("static_asset", "unknown"):
            categories.append("path_traversal")

        for category in categories:
            for payload in PAYLOADS.get(category, []):
                test_cases.append({
                    "url": url,
                    "method": method,
                    "parameter": target["name"],
                    "param_location": target["location"],
                    "injection_type": category,
                    "payload_name": payload["name"],
                    "payload_value": payload["value"],
                    "detection_method": payload["detection"],
                    "content_type": content_type,
                    # For path injection, store segment details
                    "segment_index": target.get("segment_index"),
                    "original_value": target.get("original_value"),
                })

    return {"test_cases": test_cases}


# ── Node 2: Injector ─────────────────────────────────────────────────────────

async def injector_node(state: InjectionState) -> dict:
    """Send baseline + payload requests and record response differences.

    Supports four injection surfaces:
      - query:  Injects into URL query string
      - body:   Injects into form-urlencoded POST body
      - json:   Injects into JSON POST/PUT body
      - path:   Injects into URL path segments
    """
    test_cases = state.get("test_cases", [])
    results = []
    errors: list[str] = []

    async with httpx.AsyncClient(
        timeout=15.0,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "AuthTrack-InjectionTester/0.1"},
    ) as client:
        for tc in test_cases:
            url = tc["url"]
            method = tc["method"]
            param = tc["parameter"]
            location = tc["param_location"]
            payload = tc["payload_value"]

            try:
                # ── Build baseline + payload requests based on location ──
                baseline_kwargs = {"method": method}
                payload_kwargs = {"method": method}

                if location == "query":
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query)
                    qs[param] = ["test"]
                    baseline_kwargs["url"] = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                    qs[param] = [payload]
                    payload_kwargs["url"] = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

                elif location == "body":
                    baseline_kwargs["url"] = url
                    baseline_kwargs["data"] = {param: "test"}
                    payload_kwargs["url"] = url
                    payload_kwargs["data"] = {param: payload}

                elif location == "json":
                    baseline_kwargs["url"] = url
                    baseline_kwargs["json"] = {param: "test"}
                    baseline_kwargs["headers"] = {"Content-Type": "application/json"}
                    payload_kwargs["url"] = url
                    payload_kwargs["json"] = {param: payload}
                    payload_kwargs["headers"] = {"Content-Type": "application/json"}
                    # Use POST for JSON APIs if method is GET
                    if method.upper() == "GET":
                        baseline_kwargs["method"] = "POST"
                        payload_kwargs["method"] = "POST"

                elif location == "path":
                    seg_idx = tc.get("segment_index")
                    orig_val = tc.get("original_value", "")
                    parsed = urlparse(url)
                    segments = parsed.path.split("/")
                    # Baseline: use original value (already in URL)
                    baseline_kwargs["url"] = url
                    # Payload: replace the path segment
                    if seg_idx is not None and seg_idx + 1 < len(segments):
                        payload_segments = list(segments)
                        payload_segments[seg_idx + 1] = payload  # +1 because split("/") gives empty first element
                        payload_path = "/".join(payload_segments)
                        payload_kwargs["url"] = urlunparse(parsed._replace(path=payload_path))
                    else:
                        payload_kwargs["url"] = url

                else:
                    baseline_kwargs["url"] = url
                    payload_kwargs["url"] = url

                # ── Send baseline request ──
                baseline_start = time.time()
                baseline_resp = await client.request(**baseline_kwargs)
                baseline_time = round(time.time() - baseline_start, 3)

                # ── Send payload request ──
                payload_start = time.time()
                payload_resp = await client.request(**payload_kwargs)
                payload_time = round(time.time() - payload_start, 3)

                # ── Record the comparison ──
                baseline_body = baseline_resp.text[:2000]
                payload_body = payload_resp.text[:2000]

                # Check for obvious indicators
                payload_reflected = payload in payload_body
                sql_error_found = any(sig in payload_body.lower() for sig in SQL_ERROR_SIGNATURES)
                json_error_found = _detect_json_error(payload_body)
                status_diff = payload_resp.status_code != baseline_resp.status_code
                size_diff = abs(len(payload_resp.text) - len(baseline_resp.text))
                time_diff = round(payload_time - baseline_time, 3)

                results.append({
                    **tc,
                    "baseline_status": baseline_resp.status_code,
                    "baseline_size": len(baseline_resp.text),
                    "baseline_time": baseline_time,
                    "payload_status": payload_resp.status_code,
                    "payload_size": len(payload_resp.text),
                    "payload_time": payload_time,
                    "payload_reflected": payload_reflected,
                    "sql_error_found": sql_error_found,
                    "json_error_found": json_error_found,
                    "status_diff": status_diff,
                    "size_diff": size_diff,
                    "time_diff": time_diff,
                    "baseline_body_snippet": baseline_body[:500],
                    "payload_body_snippet": payload_body[:500],
                })

            except httpx.HTTPError as e:
                errors.append(f"Injection test failed for {url}?{param}: {str(e)}")
            except Exception as e:
                errors.append(f"Unexpected error testing {url}?{param}: {str(e)}")

    return {
        "injection_results": results,
        "errors": errors,
    }


# ── Node 3: Response Analyzer (LLM) ──────────────────────────────────────────

async def response_analyzer_node(state: InjectionState) -> dict:
    """LLM compares baseline vs payload responses to confirm or discard findings."""
    results = state.get("injection_results", [])
    existing_confirmed = state.get("confirmed_findings", [])
    existing_discarded = state.get("discarded", [])
    current_index = state.get("current_index", 0)
    errors: list[str] = []

    if not results:
        return {
            "confirmed_findings": existing_confirmed,
            "discarded": existing_discarded,
            "current_index": current_index + 1,
        }

    # Pre-filter: only send interesting results to LLM (save tokens)
    interesting = [r for r in results if (
        r.get("payload_reflected") or
        r.get("sql_error_found") or
        r.get("json_error_found") or
        r.get("status_diff") or
        r.get("size_diff", 0) > 200 or
        abs(r.get("time_diff", 0)) > 1.5
    )]

    if not interesting:
        # Nothing suspicious — discard all
        return {
            "confirmed_findings": existing_confirmed,
            "discarded": existing_discarded + [
                {
                    "url": r["url"],
                    "parameter": r["parameter"],
                    "injection_type": r["injection_type"],
                    "payload_name": r["payload_name"],
                    "payload_value": r["payload_value"],
                    "time_diff": r.get("time_diff", 0),
                    "baseline_snippet": r.get("baseline_body_snippet", ""),
                    "payload_snippet": r.get("payload_body_snippet", ""),
                    "reason": "No anomaly detected in response comparison",
                }
                for r in results
            ],
            "current_index": current_index + 1,
        }

    llm = get_llm()

    # Build the analysis prompt
    results_summary = json.dumps([
        {
            "url": r["url"],
            "parameter": r["parameter"],
            "param_location": r.get("param_location", "query"),
            "injection_type": r["injection_type"],
            "payload_name": r["payload_name"],
            "payload_value": r["payload_value"],
            "baseline_status": r["baseline_status"],
            "payload_status": r["payload_status"],
            "baseline_size": r["baseline_size"],
            "payload_size": r["payload_size"],
            "time_diff": r["time_diff"],
            "payload_reflected": r["payload_reflected"],
            "sql_error_found": r["sql_error_found"],
            "json_error_found": r.get("json_error_found", False),
            "status_diff": r["status_diff"],
            "size_diff": r["size_diff"],
            "baseline_body_snippet": r["baseline_body_snippet"][:300],
            "payload_body_snippet": r["payload_body_snippet"][:300],
        }
        for r in interesting
    ], indent=2)

    prompt = f"""You are a senior penetration tester analyzing injection test results.

For each test result below, determine if the behavior change between the baseline and payload request indicates a REAL vulnerability or a false positive.

Consider:
- Status code changes (e.g., 200 → 500 suggests server error from injection)
- Response size differences (large changes may indicate different content returned)
- Payload reflection in response body (XSS confirmation)
- SQL error messages in response — both HTML error pages AND JSON error responses (SQLi confirmation)
- JSON API error fields like "detail", "error", "message" containing database/SQL references
- Response time differences > 1.5s (blind SQLi with SLEEP or heavy query)
- Error messages that reveal internal details (stack traces, file paths, DB schema)

For each result, provide:
1. "verdict": "confirmed" or "discarded"
2. "severity": "critical", "high", "medium", or "low"
3. "evidence": What specifically indicates the vulnerability
4. "description": Clear explanation of the vulnerability
5. "recommendation": Specific remediation steps (e.g., "Use parameterized queries instead of string concatenation", "Implement Content-Security-Policy header and sanitize output with DOMPurify")

Test Results:
{results_summary}

Respond with ONLY a valid JSON array of objects with the fields above plus "url", "parameter", "injection_type", and "payload_name".

JSON array:"""

    try:
        response = await llm.ainvoke(prompt)
        response_text = response.content.strip()

        json_match = re.search(r'\[.*\]', response_text, re.DOTALL)
        if json_match:
            analyzed = json.loads(json_match.group())
        else:
            analyzed = json.loads(response_text)

        new_confirmed = []
        new_discarded = []

        # Build a lookup so we can attach snippets + timing to LLM results
        result_lookup = {}
        for r in interesting:
            key = (r["url"], r["parameter"], r["injection_type"], r["payload_name"])
            result_lookup[key] = r

        for a in analyzed:
            key = (a.get("url"), a.get("parameter"), a.get("injection_type"), a.get("payload_name"))
            raw = result_lookup.get(key, {})
            # Attach response data for display
            a["time_diff"] = raw.get("time_diff", 0)
            a["baseline_snippet"] = raw.get("baseline_body_snippet", "")
            a["payload_snippet"] = raw.get("payload_body_snippet", "")
            a["payload_value"] = raw.get("payload_value", a.get("payload_value", ""))
            a["baseline_status"] = raw.get("baseline_status", 0)
            a["payload_status"] = raw.get("payload_status", 0)

            if a.get("verdict") == "confirmed":
                new_confirmed.append(a)
            else:
                a["reason"] = a.get("evidence", "LLM determined no real vulnerability")
                new_discarded.append(a)

    except (json.JSONDecodeError, Exception) as e:
        errors.append(f"LLM analysis failed: {str(e)}")
        # Fallback: use heuristics
        new_confirmed = []
        new_discarded = []
        for r in interesting:
            finding = {
                "url": r["url"],
                "parameter": r["parameter"],
                "injection_type": r["injection_type"],
                "payload_name": r["payload_name"],
                "payload_value": r.get("payload_value", ""),
                "time_diff": r.get("time_diff", 0),
                "baseline_snippet": r.get("baseline_body_snippet", ""),
                "payload_snippet": r.get("payload_body_snippet", ""),
                "baseline_status": r.get("baseline_status", 0),
                "payload_status": r.get("payload_status", 0),
                "evidence": "",
                "description": "",
                "recommendation": "",
            }
            if r.get("sql_error_found") or (r.get("json_error_found") and r["injection_type"] == "sqli"):
                finding["verdict"] = "confirmed"
                finding["severity"] = "critical"
                finding["evidence"] = "SQL/database error detected in response"
                finding["description"] = f"SQL injection via parameter '{r['parameter']}' — server returned database error messages."
                finding["recommendation"] = "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings."
                new_confirmed.append(finding)
            elif r.get("payload_reflected") and r["injection_type"] == "xss":
                finding["verdict"] = "confirmed"
                finding["severity"] = "high"
                finding["evidence"] = "Payload reflected unescaped in response body"
                finding["description"] = f"Reflected XSS via parameter '{r['parameter']}' — injected script tags appear in the response."
                finding["recommendation"] = "Sanitize all user input on output. Use Content-Security-Policy headers and encode HTML entities."
                new_confirmed.append(finding)
            elif abs(r.get("time_diff", 0)) > 1.5 and r["injection_type"] == "sqli":
                finding["verdict"] = "confirmed"
                finding["severity"] = "high"
                finding["evidence"] = f"Response time delta of {r['time_diff']}s indicates blind SQL injection (SLEEP-based)"
                finding["description"] = f"Blind SQL injection via parameter '{r['parameter']}' — response was significantly delayed after payload injection."
                finding["recommendation"] = "Use parameterized queries. Implement query timeouts and rate limiting."
                new_confirmed.append(finding)
            elif r.get("status_diff"):
                finding["verdict"] = "confirmed"
                finding["severity"] = "medium"
                finding["evidence"] = f"Status code changed from {r['baseline_status']} to {r['payload_status']}"
                finding["description"] = f"Potential injection vulnerability via '{r['parameter']}' — server behavior changed with injected input."
                finding["recommendation"] = "Validate and sanitize all user-supplied input. Implement input whitelisting."
                new_confirmed.append(finding)
            else:
                finding["verdict"] = "discarded"
                finding["severity"] = "info"
                finding["reason"] = "No clear exploitation evidence found"
                new_discarded.append(finding)

    # Also discard non-interesting results
    non_interesting_discarded = [
        {
            "url": r["url"],
            "parameter": r["parameter"],
            "injection_type": r["injection_type"],
            "payload_name": r["payload_name"],
            "payload_value": r.get("payload_value", ""),
            "time_diff": r.get("time_diff", 0),
            "reason": "No anomaly detected in response comparison",
        }
        for r in results if r not in interesting
    ]

    return {
        "confirmed_findings": existing_confirmed + new_confirmed,
        "discarded": existing_discarded + new_discarded + non_interesting_discarded,
        "current_index": current_index + 1,
        "errors": errors,
    }


# ── Conditional Router ────────────────────────────────────────────────────────

def should_continue(state: InjectionState) -> str:
    """Check if there are more endpoints to test."""
    current_index = state.get("current_index", 0)
    endpoints = state.get("endpoints", [])

    if current_index < len(endpoints):
        return "continue"
    return "done"


# ── Node 4: Report Builder ───────────────────────────────────────────────────

async def report_builder_node(state: InjectionState) -> dict:
    """Assemble the final injection report with an LLM executive summary."""
    confirmed = state.get("confirmed_findings", [])
    discarded = state.get("discarded", [])
    target_url = state.get("target_url", "unknown")
    endpoints = state.get("endpoints", [])

    # Count total parameters tested (confirmed + discarded = everything)
    total_params_tested = len(confirmed) + len(discarded)

    # Count by type and severity
    type_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for f in confirmed:
        itype = f.get("injection_type", "unknown")
        type_counts[itype] = type_counts.get(itype, 0) + 1
        sev = f.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Build tested endpoints detail for coverage reporting
    endpoint_coverage: dict[str, dict] = {}
    for item in confirmed + discarded:
        url = item.get("url", "")
        if url not in endpoint_coverage:
            endpoint_coverage[url] = {"url": url, "parameters_tested": set(), "injection_types_tested": set()}
        endpoint_coverage[url]["parameters_tested"].add(item.get("parameter", ""))
        endpoint_coverage[url]["injection_types_tested"].add(item.get("injection_type", ""))

    tested_endpoints_detail = [
        {
            "url": v["url"],
            "parameters_tested": list(v["parameters_tested"]),
            "injection_types_tested": list(v["injection_types_tested"]),
            "param_count": len(v["parameters_tested"]),
        }
        for v in endpoint_coverage.values()
    ]

    # Generate executive summary
    summary = f"Injection testing completed for {target_url}. "
    summary += f"Tested {total_params_tested} payload(s) across {len(endpoints)} endpoint(s). "
    summary += f"Found {len(confirmed)} confirmed vulnerability(ies) and discarded {len(discarded)} false positive(s). "

    if confirmed:
        llm = get_llm()
        try:
            findings_text = json.dumps(confirmed[:10], indent=2)  # cap to avoid token overflow
            prompt = f"""You are a senior security auditor. Write a 3-4 sentence executive summary for this injection test report.

Target: {target_url}
Confirmed findings: {len(confirmed)}
Discarded: {len(discarded)}
Endpoints tested: {len(endpoints)}
Total payloads tested: {total_params_tested}

Finding details:
{findings_text}

Write a professional, actionable summary focusing on:
1. The most critical risks found
2. The overall injection security posture
3. Priority recommendations

Summary (plain text, no markdown):"""

            response = await llm.ainvoke(prompt)
            summary = response.content.strip()
        except Exception:
            pass  # keep the fallback summary
    elif not confirmed:
        summary += "No injection vulnerabilities were confirmed. The tested endpoints appear resilient to standard injection payloads."

    report = {
        "target_url": target_url,
        "total_tested": len(endpoints),
        "total_params_tested": total_params_tested,
        "total_confirmed": len(confirmed),
        "total_discarded": len(discarded),
        "findings": confirmed,
        "discarded_findings": discarded,
        "type_breakdown": type_counts,
        "severity_breakdown": severity_counts,
        "tested_endpoints_detail": tested_endpoints_detail,
        "summary": summary,
        "scan_timestamp": datetime.now().isoformat(),
    }

    return {"injection_report": report}
