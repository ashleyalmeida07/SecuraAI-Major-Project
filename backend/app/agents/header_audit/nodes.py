"""Node functions for the Security Header & Cookie Audit LangGraph flow.

Nodes:
    header_fetcher_node    — Fetches response headers from each endpoint.
    rule_checker_node      — Checks headers/cookies against a security checklist.
    severity_scorer_node   — Uses an LLM to assign severity and generate summaries.
"""

import httpx
import json
import re
from datetime import datetime

from app.agents.header_audit.state import HeaderAuditState
from app.core.llm import get_llm


# ── Security header rules ────────────────────────────────────────────────────

REQUIRED_HEADERS = {
    "strict-transport-security": {
        "expected": "max-age=31536000; includeSubDomains",
        "description": "HSTS header enforces HTTPS connections. Missing HSTS allows downgrade attacks.",
    },
    "content-security-policy": {
        "expected": "Present (restrictive policy)",
        "description": "CSP prevents XSS and data injection by restricting resource origins.",
    },
    "x-content-type-options": {
        "expected": "nosniff",
        "description": "Prevents MIME-type sniffing which can lead to XSS attacks.",
    },
    "x-frame-options": {
        "expected": "DENY or SAMEORIGIN",
        "description": "Prevents clickjacking by controlling whether the page can be framed.",
    },
    "referrer-policy": {
        "expected": "strict-origin-when-cross-origin or no-referrer",
        "description": "Controls how much referrer information is sent with requests.",
    },
    "permissions-policy": {
        "expected": "Present (restrictive policy)",
        "description": "Controls which browser features (camera, mic, etc.) the page can use.",
    },
    "x-xss-protection": {
        "expected": "0 (disabled, rely on CSP instead)",
        "description": "Legacy XSS filter. Modern best practice is to set to 0 and use CSP.",
    },
}

COOKIE_FLAGS = ["Secure", "HttpOnly", "SameSite"]


# ── Node 1: Header Fetcher ───────────────────────────────────────────────────

async def header_fetcher_node(state: HeaderAuditState) -> dict:
    """Fetch response headers and cookies from each endpoint."""
    endpoints = state.get("endpoints", [])
    errors: list[str] = []
    results: list[dict] = []

    async with httpx.AsyncClient(
        timeout=10.0,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "AuthTrack-Auditor/0.1"},
    ) as client:
        for ep in endpoints:
            url = ep.get("url", "")
            # Skip non-HTTP endpoints and static assets
            if not url.startswith("http"):
                continue

            try:
                response = await client.get(url)
                # Collect all response headers
                headers_dict = dict(response.headers)
                # Collect Set-Cookie headers
                cookies_raw = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
                # Fallback: extract from headers
                if not cookies_raw:
                    cookie_val = response.headers.get("set-cookie")
                    cookies_raw = [cookie_val] if cookie_val else []

                results.append({
                    "url": url,
                    "status_code": response.status_code,
                    "headers": headers_dict,
                    "cookies_raw": cookies_raw,
                })
            except httpx.HTTPError as e:
                errors.append(f"Failed to fetch headers for {url}: {str(e)}")
            except Exception as e:
                errors.append(f"Unexpected error fetching {url}: {str(e)}")

    return {
        "header_results": results,
        "errors": errors,
    }


# ── Node 2: Rule Checker ─────────────────────────────────────────────────────

async def rule_checker_node(state: HeaderAuditState) -> dict:
    """Check fetched headers against the security checklist.

    This is purely deterministic — no LLM involved.
    Produces a finding for every missing or misconfigured header/cookie flag.
    """
    header_results = state.get("header_results", [])
    findings: list[dict] = []

    for result in header_results:
        url = result["url"]
        headers = result.get("headers", {})
        cookies = result.get("cookies_raw", [])

        # Normalize header keys to lowercase for comparison
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # ── Check required security headers ──
        for header_name, rule in REQUIRED_HEADERS.items():
            actual_value = headers_lower.get(header_name)
            if actual_value is None:
                findings.append({
                    "url": url,
                    "header_name": header_name,
                    "expected": rule["expected"],
                    "actual": "MISSING",
                    "severity": "medium",      # default; LLM will refine
                    "description": rule["description"],
                })
            else:
                # Header is present — check for weak configurations
                if header_name == "x-content-type-options" and actual_value.lower() != "nosniff":
                    findings.append({
                        "url": url,
                        "header_name": header_name,
                        "expected": "nosniff",
                        "actual": actual_value,
                        "severity": "medium",
                        "description": f"X-Content-Type-Options is set to '{actual_value}' instead of 'nosniff'.",
                    })
                elif header_name == "x-frame-options" and actual_value.upper() not in ("DENY", "SAMEORIGIN"):
                    findings.append({
                        "url": url,
                        "header_name": header_name,
                        "expected": "DENY or SAMEORIGIN",
                        "actual": actual_value,
                        "severity": "medium",
                        "description": f"X-Frame-Options is set to '{actual_value}' which may allow clickjacking.",
                    })

        # ── Check cookie security flags ──
        for cookie_str in cookies:
            cookie_name = cookie_str.split("=")[0].strip() if "=" in cookie_str else "unknown"
            cookie_lower = cookie_str.lower()

            for flag in COOKIE_FLAGS:
                if flag.lower() not in cookie_lower:
                    findings.append({
                        "url": url,
                        "header_name": f"Cookie:{cookie_name}:{flag}",
                        "expected": f"{flag} flag present",
                        "actual": "MISSING",
                        "severity": "medium",
                        "description": f"Cookie '{cookie_name}' is missing the '{flag}' flag.",
                    })

    return {"findings": findings}


# ── Node 3: Severity Scorer (LLM) ────────────────────────────────────────────

async def severity_scorer_node(state: HeaderAuditState) -> dict:
    """Use an LLM to refine severity ratings and generate a summary.

    The rule checker assigns a default 'medium' to everything.
    The LLM reasons about context (which endpoint, what type, exposure)
    to produce more nuanced severities and an overall summary.
    """
    findings = state.get("findings", [])
    target_url = state.get("target_url", "unknown")
    errors: list[str] = []

    if not findings:
        report = {
            "target_url": target_url,
            "total_findings": 0,
            "findings": [],
            "summary": "No security header issues found. All checked headers are properly configured.",
            "scan_timestamp": datetime.now().isoformat(),
        }
        return {"scored_findings": [], "audit_report": report}

    llm = get_llm()

    # Build the scoring prompt
    findings_text = json.dumps(findings, indent=2)

    prompt = f"""You are a senior web security auditor. Review these security header and cookie findings from a scan of {target_url}.

For each finding, assign a refined severity level based on the context:
- "critical": Direct, easily exploitable vulnerability (e.g., missing HSTS on a login page)
- "high": Significant risk that could be exploited with moderate effort
- "medium": Notable weakness, industry best practice violation
- "low": Minor issue, defense-in-depth recommendation
- "info": Informational, no direct security impact

Also provide a brief, actionable description for each finding.

Findings to score:
{findings_text}

Respond with a JSON object containing:
1. "findings": array of the same findings but with updated "severity" and "description" fields
2. "summary": a 2-3 sentence executive summary of the overall security posture

JSON response:"""

    try:
        response = await llm.ainvoke(prompt)
        response_text = response.content.strip()

        # Extract JSON from the response
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            scored_data = json.loads(json_match.group())
        else:
            scored_data = json.loads(response_text)

        scored_findings = scored_data.get("findings", findings)
        summary = scored_data.get("summary", "Scan completed. Review findings for details.")

    except (json.JSONDecodeError, Exception) as e:
        errors.append(f"LLM scoring failed, using default severities: {str(e)}")
        scored_findings = findings
        summary = f"Scan completed with {len(findings)} findings. LLM scoring was unavailable; default severities applied."

    report = {
        "target_url": target_url,
        "total_findings": len(scored_findings),
        "findings": scored_findings,
        "summary": summary,
        "scan_timestamp": datetime.now().isoformat(),
    }

    return {
        "scored_findings": scored_findings,
        "audit_report": report,
        "errors": errors,
    }
