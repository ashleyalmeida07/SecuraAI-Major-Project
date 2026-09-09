"""Node functions for the Recon & Surface Mapping LangGraph flow.

Nodes:
    crawler_node          — Crawls the target URL, discovers pages and endpoints.
    classifier_node       — Uses an LLM to classify each endpoint by type.
    surface_report_node   — Assembles the final structured attack-surface report.
"""

import json
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from datetime import datetime
from playwright.async_api import async_playwright

from app.agents.recon.state import ReconState
from app.core.llm import get_llm


# ── Crawler helpers ──────────────────────────────────────────────────────────

# Sensitive/interesting paths worth flagging wherever a URL turns up.
SENSITIVE_RE = re.compile(
    r'(robots\.txt|sitemap\.xml|/api/docs|\.env|/admin|/swagger|/graphql)',
    re.IGNORECASE,
)

# Heavy sub-resources we never inspect — aborting them speeds the crawl up
# without changing which links, forms or API calls we discover.
_BLOCKED_RESOURCE_TYPES = {"image", "media", "font"}


def _same_site(host: str, base: str) -> bool:
    """True if `host` is the base host or a same-site sub-domain.

    Registrable domain is approximated by the last two labels — good enough for
    recon, and it lets us record ``api.example.com`` calls fired while crawling
    ``www.example.com`` without dragging in unrelated third parties.
    """
    host = (host or "").split(":")[0].lower()
    base = (base or "").split(":")[0].lower()
    if not host or not base:
        return False
    if host == base:
        return True
    h, b = host.split("."), base.split(".")
    if len(h) < 2 or len(b) < 2:
        return host == base
    return h[-2:] == b[-2:]


async def _settle_page(page) -> None:
    """Give a JS-heavy page time to finish its initial data fetches, scroll it to
    trigger lazy / infinite-scroll content, then let the network settle again.

    Best-effort throughout: ``networkidle`` legitimately never fires on pages
    with websockets, long-polling or analytics beacons, so timeouts here are
    expected and swallowed rather than surfaced as crawl errors.
    """
    try:
        await page.wait_for_load_state("networkidle", timeout=3500)
    except Exception:
        pass
    try:
        for _ in range(4):
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(250)
        await page.evaluate("window.scrollTo(0, 0)")
    except Exception:
        pass
    try:
        await page.wait_for_load_state("networkidle", timeout=1500)
    except Exception:
        pass


# ── Node 1: Crawler ──────────────────────────────────────────────────────────

async def crawler_node(state: ReconState) -> dict:
    """Crawl the target URL and discover linked pages, forms, and API endpoints.

    Renders every page in a headless Chromium via Playwright, so JavaScript apps
    and SPAs work: the DOM is parsed *after* scripts run, and — the part that
    matters for modern sites — the actual XHR/fetch calls the page fires at
    runtime are captured from the network layer, not scraped out of inline
    ``<script>`` text (which misses bundled/minified code entirely). Follows
    links up to ``max_depth`` levels and only *navigates* same-host pages, but
    records the same-site (sub-domain) API calls it observes along the way.
    """
    target_url = state["target_url"].rstrip("/")
    max_depth = state.get("max_depth", 2)
    max_pages = state.get("max_pages", 15)
    parsed_target = urlparse(target_url)
    base_domain = parsed_target.netloc

    visited: set[str] = set()
    discovered: list[dict] = []
    queue: list[tuple[str, int]] = [(target_url, 0)]
    errors: list[str] = []

    # Live network calls captured across the whole crawl, keyed (url, method) so
    # a call seen on several pages is recorded once. Filled by the response
    # listener below; `current` tells that listener which page is in flight.
    network_map: dict[tuple[str, str], dict] = {}
    current = {"url": target_url}

    def _on_response(response) -> None:
        """Record same-site XHR/fetch responses — the real API surface of an SPA.

        Runs as a Playwright event callback, so it touches only *synchronous*
        Response/Request properties (never ``await response.body()``) and never
        raises, since an exception here would tear the page down mid-crawl.
        """
        try:
            req = response.request
            rtype = req.resource_type
            if rtype not in ("xhr", "fetch"):
                return
            url = response.url.split("#")[0]
            if not _same_site(urlparse(url).netloc, base_domain):
                return
            method = (req.method or "GET").upper()
            key = (url, method)
            if key in network_map:
                return

            try:
                content_type = response.headers.get("content-type", "")
            except Exception:
                content_type = ""
            try:
                status_code = response.status
            except Exception:
                status_code = 0

            flags = [f"Live {rtype.upper()} {method} {url} → {status_code} {content_type}".rstrip()]
            sensitive_matches = SENSITIVE_RE.findall(url)
            for match in sensitive_matches:
                flags.append(f"Sensitive path: {match}")
            looks_api = (
                "/api/" in url.lower() or "graphql" in url.lower() or "json" in content_type.lower()
            )

            network_map[key] = {
                "url": url,
                "method": method,
                "status_code": status_code,
                "content_type": content_type or "xhr",
                "response_time": 0.0,
                "response_size": 0,
                "technology": [],
                "parameters": list(parse_qs(urlparse(url).query).keys()),
                "is_interesting": bool(looks_api or sensitive_matches),
                "flags": flags,
                "form_inputs": [],
                "detection_source": f"network {rtype} from {current['url']}",
            }
        except Exception:
            # A listener must never abort the crawl.
            pass

    async def _route(route) -> None:
        # Drop heavy sub-resources; keep everything else so JS, stylesheets and —
        # the point — XHR/fetch calls still run.
        try:
            if route.request.resource_type in _BLOCKED_RESOURCE_TYPES:
                await route.abort()
            else:
                await route.continue_()
        except Exception:
            pass

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            ignore_https_errors=True,
            user_agent="AuthTrack-Crawler/0.1",
        )
        page = await context.new_page()
        page.on("response", _on_response)
        await page.route("**/*", _route)

        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)

            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            current["url"] = url

            try:
                start_time = time.time()
                response = await page.goto(url, wait_until="domcontentloaded", timeout=20000)

                if not response:
                    continue

                response_time = round(time.time() - start_time, 3)

                headers = response.headers
                content_type = headers.get("content-type", "")
                status_code = response.status

                # Prefer the declared length; only download the body if we must.
                try:
                    content_length = headers.get("content-length")
                    if content_length and content_length.isdigit():
                        response_size = int(content_length)
                    else:
                        response_size = len(await response.body())
                except Exception:
                    response_size = 0

                endpoint_info = {
                    "url": url,
                    "method": "GET",
                    "status_code": status_code,
                    "content_type": content_type,
                    "response_time": response_time,
                    "response_size": response_size,
                    "technology": [],
                    "parameters": list(parse_qs(urlparse(url).query).keys()),
                    "is_interesting": False,
                    "flags": [],
                    "form_inputs": []
                }

                # Flag sensitive/interesting paths with evidence
                sensitive_matches = SENSITIVE_RE.findall(url)
                if sensitive_matches:
                    endpoint_info["is_interesting"] = True
                    for match in sensitive_matches:
                        endpoint_info["flags"].append(f"{match} found — {status_code} {content_type}")

                # Record technology detection evidence
                server_hdr = headers.get("server")
                if server_hdr:
                    endpoint_info["technology"].append(f"{server_hdr} (via Server header)")
                xp_hdr = headers.get("x-powered-by")
                if xp_hdr:
                    endpoint_info["technology"].append(f"{xp_hdr} (via X-Powered-By header)")

                discovered.append(endpoint_info)

                # Only HTML pages are worth rendering fully and parsing for links.
                if "text/html" not in content_type:
                    continue

                # Let the SPA finish its initial fetches and lazy-load, then read
                # the fully-rendered DOM.
                await _settle_page(page)
                try:
                    html_content = await page.content()
                except Exception:
                    html_content = ""

                soup = BeautifulSoup(html_content, "html.parser")

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
                            if name:
                                inputs.append(name)
                        form_flags = [f"Form action={form_url} method={method} inputs=[{', '.join(inputs)}]"]
                        discovered.append({
                            "url": form_url,
                            "method": method,
                            "status_code": 0,
                            "content_type": "form",
                            "response_time": 0.0,
                            "response_size": 0,
                            "technology": [],
                            "parameters": [],
                            "is_interesting": bool(inputs),
                            "flags": form_flags,
                            "form_inputs": inputs,
                            "detection_source": f"<form> on {url}"
                        })

                # ── Extract API-like paths from inline scripts (a cheap bonus on
                #    top of the live network capture above) ──
                for script in soup.find_all("script"):
                    if script.string:
                        # Look for fetch/axios calls with /api/ paths
                        api_patterns = re.findall(
                            r'["\'](/api/[^"\']+)["\']', script.string
                        )
                        for path in api_patterns:
                            api_url = urljoin(url, path)
                            if api_url not in visited:
                                api_flags = [f"API path '{path}' found in JavaScript on {url}"]
                                api_sensitive = SENSITIVE_RE.findall(api_url)
                                for match in api_sensitive:
                                    api_flags.append(f"Sensitive path: {match}")
                                discovered.append({
                                    "url": api_url,
                                    "method": "GET",
                                    "status_code": 0,
                                    "content_type": "api_reference",
                                    "response_time": 0.0,
                                    "response_size": 0,
                                    "technology": [],
                                    "parameters": [],
                                    "is_interesting": bool(api_sensitive),
                                    "flags": api_flags,
                                    "form_inputs": [],
                                    "detection_source": f"JavaScript on {url}"
                                })

            except Exception as e:
                errors.append(f"Unexpected error crawling {url}: {str(e)}")

        await browser.close()

    # Merge live network endpoints in, then deduplicate by URL+method, preferring
    # the record that actually got a response code and unioning evidence flags.
    best: dict[tuple[str, str], dict] = {}
    for ep in discovered + list(network_map.values()):
        key = (ep["url"], ep["method"])
        cur = best.get(key)
        if cur is None:
            best[key] = ep
            continue
        union_flags = list(dict.fromkeys((cur.get("flags") or []) + (ep.get("flags") or [])))
        if cur.get("status_code", 0) == 0 and ep.get("status_code", 0) != 0:
            winner, loser = ep, cur
        else:
            winner, loser = cur, ep
        winner["flags"] = union_flags
        winner["is_interesting"] = bool(winner.get("is_interesting") or loser.get("is_interesting"))
        if not winner.get("detection_source") and loser.get("detection_source"):
            winner["detection_source"] = loser["detection_source"]
        best[key] = winner

    unique_discovered = list(best.values())

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
{{"url": "<url>", "method": "<method>", "endpoint_type": "<category>", "classification_reason": "<short reason why you chose this category, referencing URL path, content-type, or status code>", "status_code": <code>, "content_type": "<type>"}}

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
            {**ep, "endpoint_type": "unknown", "classification_reason": "LLM classification failed — defaulting to unknown"} for ep in discovered
        ]
    except Exception as e:
        errors.append(f"LLM classification failed: {str(e)}")
        classified = [
            {**ep, "endpoint_type": "unknown", "classification_reason": "LLM classification failed — defaulting to unknown"} for ep in discovered
        ]

    # ── Fallback Rules ──
    for ep in classified:
        if ep.get("endpoint_type") == "unknown":
            path = urlparse(ep["url"]).path.lower()
            if path.startswith("/api/"):
                ep["endpoint_type"] = "api"
                ep["classification_reason"] = f"Path starts with /api/ ({path})"
            elif any(path.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".svg", ".ico"]):
                ep["endpoint_type"] = "static_asset"
                ep["classification_reason"] = f"File extension detected in path ({path})"
            elif "admin" in path or "dashboard" in path:
                ep["endpoint_type"] = "dashboard"
                ep["classification_reason"] = f"Admin/dashboard keyword in path ({path})"
            elif "login" in path or "auth" in path or "signup" in path:
                ep["endpoint_type"] = "auth_page"
                ep["classification_reason"] = f"Auth keyword in path ({path})"

    # Merge evidence data from discovered into classified
    discovered_lookup = {ep["url"]: ep for ep in discovered}
    for ep in classified:
        src = discovered_lookup.get(ep["url"], {})
        # Carry over evidence fields that the LLM wouldn't return
        for field in ("technology", "parameters", "form_inputs", "response_size", "response_time", "is_interesting", "flags", "detection_source"):
            if field in src and field not in ep:
                ep[field] = src[field]

    return {
        "classified_endpoints": classified,
        "errors": errors,
    }


# ── Node 3: Surface Report Builder ───────────────────────────────────────────

async def surface_report_node(state: ReconState) -> dict:
    """Assemble the classified endpoints into a structured SurfaceReport and generate a text summary."""
    classified = state.get("classified_endpoints", [])
    target_url = state["target_url"]

    # Count endpoints by type
    type_counts: dict[str, int] = {}
    for ep in classified:
        ep_type = ep.get("endpoint_type", "unknown")
        type_counts[ep_type] = type_counts.get(ep_type, 0) + 1

    summary_text = "Surface mapping completed. "
    if classified:
        try:
            llm = get_llm()
            prompt = f"""You are a senior security researcher. Write a 2-3 sentence executive summary for an attack surface map of {target_url}.

Total Endpoints Discovered: {len(classified)}
Type breakdown: {json.dumps(type_counts)}

Focus on the overall surface area, highlighting if there is a large number of APIs or Auth pages. Do not use markdown.
Summary (plain text):"""
            response = await llm.ainvoke(prompt)
            summary_text = response.content.strip()
        except Exception:
            summary_text += f"Found {len(classified)} endpoints."
    else:
        summary_text += "No endpoints were found."

    report = {
        "target_url": target_url,
        "total_endpoints": len(classified),
        "endpoints": classified,
        "scan_timestamp": datetime.now().isoformat(),
        "summary": summary_text,
    }

    return {"surface_report": report}
