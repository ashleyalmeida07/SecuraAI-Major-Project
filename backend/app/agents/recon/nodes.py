"""Node functions for the Recon & Surface Mapping LangGraph flow.

Nodes:
    crawler_node          — Crawls the target URL, discovers pages and endpoints.
    classifier_node       — Uses an LLM to classify each endpoint by type.
    surface_report_node   — Assembles the final structured attack-surface report.
"""

import httpx
import json
import re
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from datetime import datetime

from app.agents.recon.state import ReconState
from app.core.llm import get_llm


# ── Node 1: Crawler ──────────────────────────────────────────────────────────

async def crawler_node(state: ReconState) -> dict:
    """Crawl the target URL and discover linked pages, forms, and API endpoints.

    Uses httpx + BeautifulSoup.  Follows links up to `max_depth` levels.
    Only visits pages on the same domain as the target.
    """
    target_url = state["target_url"].rstrip("/")
    max_depth = state.get("max_depth", 2)
    parsed_target = urlparse(target_url)
    base_domain = parsed_target.netloc

    visited: set[str] = set()
    discovered: list[dict] = []
    queue: list[tuple[str, int]] = [(target_url, 0)]
    errors: list[str] = []

    async with httpx.AsyncClient(
        timeout=15.0,
        follow_redirects=True,
        verify=False,          # allow self-signed certs on dev targets
        headers={"User-Agent": "AuthTrack-Crawler/0.1"},
    ) as client:
        while queue:
            url, depth = queue.pop(0)

            if url in visited or depth > max_depth:
                continue
            visited.add(url)

            try:
                response = await client.get(url)
                content_type = response.headers.get("content-type", "")

                endpoint_info = {
                    "url": url,
                    "method": "GET",
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "response_time": round(response.elapsed.total_seconds(), 3),
                    "response_size": len(response.content),
                    "technology": [],
                    "parameters": list(parse_qs(urlparse(url).query).keys()),
                    "is_interesting": bool(re.search(r'(robots\.txt|sitemap\.xml|/api/docs|\.env|/admin)', url, re.IGNORECASE)),
                    "form_inputs": []
                }
                
                server_hdr = response.headers.get("server")
                if server_hdr: endpoint_info["technology"].append(server_hdr)
                xp_hdr = response.headers.get("x-powered-by")
                if xp_hdr: endpoint_info["technology"].append(xp_hdr)

                discovered.append(endpoint_info)

                # Only parse HTML pages for more links
                if "text/html" not in content_type:
                    continue

                soup = BeautifulSoup(response.text, "html.parser")

                # ── Extract <a> links ──
                for anchor in soup.find_all("a", href=True):
                    href = anchor["href"]
                    full_url = urljoin(url, href).split("#")[0].split("?")[0]
                    if urlparse(full_url).netloc == base_domain and full_url not in visited:
                        queue.append((full_url, depth + 1))

                # ── Extract <form> actions ──
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "GET").upper()
                    form_url = urljoin(url, action) if action else url
                    if urlparse(form_url).netloc == base_domain:
                        inputs = []
                        for inp in form.find_all(["input", "select", "textarea"]):
                            name = inp.get("name") or inp.get("id")
                            if name: inputs.append(name)
                        discovered.append({
                            "url": form_url,
                            "method": method,
                            "status_code": 0,
                            "content_type": "form",
                            "response_time": 0.0,
                            "response_size": 0,
                            "technology": [],
                            "parameters": [],
                            "is_interesting": False,
                            "form_inputs": inputs
                        })

                # ── Extract API-like paths from scripts ──
                for script in soup.find_all("script"):
                    if script.string:
                        # Look for fetch/axios calls with /api/ paths
                        api_patterns = re.findall(
                            r'["\'](/api/[^"\']+)["\']', script.string
                        )
                        for path in api_patterns:
                            api_url = urljoin(url, path)
                            if api_url not in visited:
                                discovered.append({
                                    "url": api_url,
                                    "method": "GET",
                                    "status_code": 0,
                                    "content_type": "api_reference",
                                    "response_time": 0.0,
                                    "response_size": 0,
                                    "technology": [],
                                    "parameters": [],
                                    "is_interesting": bool(re.search(r'(robots\.txt|sitemap\.xml|/api/docs|\.env|/admin)', api_url, re.IGNORECASE)),
                                    "form_inputs": []
                                })

            except httpx.HTTPError as e:
                errors.append(f"Failed to crawl {url}: {str(e)}")
            except Exception as e:
                errors.append(f"Unexpected error crawling {url}: {str(e)}")

    # Deduplicate by URL+method
    seen = set()
    unique_discovered = []
    for ep in discovered:
        key = (ep["url"], ep["method"])
        if key not in seen:
            seen.add(key)
            unique_discovered.append(ep)

    return {
        "discovered_urls": unique_discovered,
        "errors": errors,
    }


# ── Node 2: Endpoint Classifier (LLM) ────────────────────────────────────────

async def classifier_node(state: ReconState) -> dict:
    """Classify each discovered URL using an LLM.

    Sends the URL list to the LLM with a structured prompt asking it
    to tag each endpoint as one of:
        auth_page, api, static_asset, form, dashboard, unknown
    """
    discovered = state.get("discovered_urls", [])
    errors: list[str] = []

    if not discovered:
        return {"classified_endpoints": [], "errors": ["No URLs discovered to classify."]}

    llm = get_llm()

    # Build the classification prompt
    endpoint_list_text = "\n".join(
        f"- URL: {ep['url']}  |  Method: {ep['method']}  |  Status: {ep['status_code']}  |  Content-Type: {ep['content_type']}"
        for ep in discovered
    )

    prompt = f"""You are a web security expert. Classify each of the following discovered web endpoints into one of these categories:

Categories:
- "auth_page": Login, signup, password reset, or authentication-related pages
- "api": REST API endpoints (usually return JSON, under /api/ paths)
- "static_asset": CSS, JS, image, font, or other static files
- "form": Pages containing forms that accept user input
- "dashboard": Admin panels, dashboards, or authenticated content pages
- "unknown": Cannot be determined from the available information

Endpoints to classify:
{endpoint_list_text}

Respond with ONLY a valid JSON array where each element has:
{{"url": "<url>", "method": "<method>", "endpoint_type": "<category>", "status_code": <code>, "content_type": "<type>"}}

JSON array:"""

    try:
        response = await llm.ainvoke(prompt)
        response_text = response.content.strip()

        # Extract JSON from the response (handle markdown code blocks)
        json_match = re.search(r'\[.*\]', response_text, re.DOTALL)
        if json_match:
            classified = json.loads(json_match.group())
        else:
            classified = json.loads(response_text)

    except json.JSONDecodeError as e:
        errors.append(f"LLM returned invalid JSON for classification: {str(e)}")
        # Fallback: keep original URLs with "unknown" type
        classified = [
            {**ep, "endpoint_type": "unknown"} for ep in discovered
        ]
    except Exception as e:
        errors.append(f"LLM classification failed: {str(e)}")
        classified = [
            {**ep, "endpoint_type": "unknown"} for ep in discovered
        ]

    # ── Fallback Rules ──
    for ep in classified:
        if ep.get("endpoint_type") == "unknown":
            path = urlparse(ep["url"]).path.lower()
            if path.startswith("/api/"):
                ep["endpoint_type"] = "api"
            elif any(path.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".svg", ".ico"]):
                ep["endpoint_type"] = "static_asset"
            elif "admin" in path or "dashboard" in path:
                ep["endpoint_type"] = "dashboard"
            elif "login" in path or "auth" in path or "signup" in path:
                ep["endpoint_type"] = "auth_page"

    return {
        "classified_endpoints": classified,
        "errors": errors,
    }


# ── Node 3: Surface Report Builder ───────────────────────────────────────────

async def surface_report_node(state: ReconState) -> dict:
    """Assemble the classified endpoints into a structured SurfaceReport."""
    classified = state.get("classified_endpoints", [])
    target_url = state["target_url"]

    # Count endpoints by type
    type_counts: dict[str, int] = {}
    for ep in classified:
        ep_type = ep.get("endpoint_type", "unknown")
        type_counts[ep_type] = type_counts.get(ep_type, 0) + 1

    report = {
        "target_url": target_url,
        "total_endpoints": len(classified),
        "endpoints": classified,
        "scan_timestamp": datetime.now().isoformat(),
        "summary": type_counts,
    }

    return {"surface_report": report}
