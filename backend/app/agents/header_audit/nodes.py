"""Node functions for the Security Header & Cookie Audit LangGraph flow.

Nodes:
    header_fetcher_node    — Fetches response headers from each endpoint.
    rule_checker_node      — Evaluates every checklist item for every endpoint.
    severity_scorer_node   — LLM scores ONLY the failing/missing items.

Design (checklist model, à la securityheaders.com / Mozilla Observatory):
    The checklist is explicit and fixed. Every item on it is evaluated for every
    endpoint and emits a result — pass, fail, or missing — not just the problems.
    A header being present with an acceptable value is objectively true/false, so
    passes never touch the LLM: they are recorded deterministically. Only the
    failing/missing items are handed to the LLM for context-aware severity and an
    explanation. The report and summary then show both sides, so a mostly-solid
    app reads as "8/10 configured" rather than a wall of red.
"""

import httpx
import json
import re
from datetime import datetime

from app.agents.header_audit.state import HeaderAuditState
from app.core.llm import get_llm


# ── The explicit checklist ───────────────────────────────────────────────────
# Each header item carries a `check(value) -> (ok, detail)` used only when the
# header is present; `expected` is the human-readable target; `weight` counts
# toward the "X/Y configured" ratio (informational-only items are weighted 0).

def _csp_check(value: str) -> tuple[bool, str]:
    weak = []
    low = value.lower()
    if "unsafe-inline" in low:
        weak.append("unsafe-inline")
    if "unsafe-eval" in low:
        weak.append("unsafe-eval")
    if "*" in value:
        weak.append("wildcard (*)")
    if weak:
        return False, f"Present but contains weak directives: {', '.join(weak)}."
    return True, "Restrictive policy present."


def _hsts_check(value: str) -> tuple[bool, str]:
    m = re.search(r"max-age=(\d+)", value.lower())
    if not m:
        return False, "Present but has no max-age directive."
    if int(m.group(1)) < 15552000:  # < ~180 days
        return False, f"max-age is {m.group(1)}s — below the recommended 15552000s (180 days)."
    return True, "Long max-age set."


def _xfo_check(value: str) -> tuple[bool, str]:
    if value.upper() in ("DENY", "SAMEORIGIN"):
        return True, f"Set to {value.upper()}."
    return False, f"Set to '{value}', which may allow framing/clickjacking."


def _xcto_check(value: str) -> tuple[bool, str]:
    if value.lower() == "nosniff":
        return True, "Set to nosniff."
    return False, f"Set to '{value}' instead of 'nosniff'."


def _referrer_check(value: str) -> tuple[bool, str]:
    safe = {
        "no-referrer", "strict-origin-when-cross-origin", "same-origin",
        "strict-origin", "no-referrer-when-downgrade",
    }
    if value.lower() in safe:
        return True, f"Set to a safe value ({value})."
    return False, f"Set to '{value}', which may leak URL info to third parties."


def _permissions_check(value: str) -> tuple[bool, str]:
    if value.strip():
        return True, "Feature policy present."
    return False, "Present but empty."


HEADER_CHECKLIST = [
    {
        "key": "content-security-policy",
        "label": "Content-Security-Policy",
        "expected": "Present with a restrictive policy (no unsafe-inline/eval/wildcards)",
        "check": _csp_check,
        "weight": 1,
        "info": "CSP restricts resource origins, the primary defence against XSS and injection.",
    },
    {
        "key": "strict-transport-security",
        "label": "Strict-Transport-Security",
        "expected": "max-age >= 15552000 (add includeSubDomains)",
        "check": _hsts_check,
        "weight": 1,
        "info": "HSTS forces HTTPS; without it a downgrade/SSL-strip attack is possible.",
    },
    {
        "key": "x-frame-options",
        "label": "X-Frame-Options",
        "expected": "DENY or SAMEORIGIN",
        "check": _xfo_check,
        "weight": 1,
        "info": "Controls framing; prevents clickjacking (superseded by CSP frame-ancestors).",
    },
    {
        "key": "x-content-type-options",
        "label": "X-Content-Type-Options",
        "expected": "nosniff",
        "check": _xcto_check,
        "weight": 1,
        "info": "Stops MIME-type sniffing that can turn uploads into script execution.",
    },
    {
        "key": "referrer-policy",
        "label": "Referrer-Policy",
        "expected": "strict-origin-when-cross-origin or no-referrer",
        "check": _referrer_check,
        "weight": 1,
        "info": "Limits how much URL information leaks in the Referer header.",
    },
    {
        "key": "permissions-policy",
        "label": "Permissions-Policy",
        "expected": "Present (restrict camera, mic, geolocation, etc.)",
        "check": _permissions_check,
        "weight": 1,
        "info": "Restricts which powerful browser features the page may use.",
    },
]

# Cookie flags checked on every Set-Cookie. Each contributes one checklist item
# per cookie per endpoint.
COOKIE_FLAGS = [
    {
        "flag": "HttpOnly",
        "expected": "HttpOnly attribute present",
        "info": "Keeps the cookie out of reach of JavaScript, blunting XSS session theft.",
    },
    {
        "flag": "Secure",
        "expected": "Secure attribute present",
        "info": "Ensures the cookie is only sent over HTTPS.",
    },
    {
        "flag": "SameSite",
        "expected": "SameSite=Lax or SameSite=Strict",
        "info": "Mitigates CSRF by limiting cross-site cookie sending.",
    },
]


# ── Node 1: Header Fetcher ───────────────────────────────────────────────────

async def header_fetcher_node(state: HeaderAuditState) -> dict:
    """Fetch response headers and cookies from each endpoint."""
    endpoints = state.get("endpoints", [])
    errors: list[str] = []
    results: list[dict] = []

    # Only fetch each URL once, even if recon listed it several times.
    seen: set[str] = set()

    async with httpx.AsyncClient(
        timeout=10.0,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "AuthTrack-Auditor/0.1"},
    ) as client:
        for ep in endpoints:
            url = ep.get("url", "")
            if not url.startswith("http") or url in seen:
                continue
            seen.add(url)

            try:
                response = await client.get(url)
                headers_dict = dict(response.headers)
                cookies_raw = (
                    response.headers.get_list("set-cookie")
                    if hasattr(response.headers, "get_list") else []
                )
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


# ── Node 2: Rule Checker (deterministic — evaluates the whole checklist) ──────

def _cookie_name(cookie_str: str) -> str:
    return cookie_str.split("=")[0].strip() if "=" in cookie_str else "cookie"


async def rule_checker_node(state: HeaderAuditState) -> dict:
    """Evaluate every checklist item for every endpoint.

    Emits one result record per checklist item per endpoint — pass, fail, or
    missing — never only the failures. This is fully deterministic; no LLM is
    involved. The severity on fail/missing items is a placeholder that the LLM
    refines in the next node; passes carry no severity and are final.
    """
    header_results = state.get("header_results", [])
    endpoints = state.get("endpoints", [])
    checklist: list[dict] = []

    ep_types = {ep.get("url", ""): ep.get("endpoint_type", "unknown") for ep in endpoints}

    for result in header_results:
        url = result["url"]
        status_code = result.get("status_code", 200)
        headers = result.get("headers", {})
        cookies = result.get("cookies_raw", [])
        ep_type = ep_types.get(url, "unknown")
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # ── Every required security header ──
        for item in HEADER_CHECKLIST:
            actual = headers_lower.get(item["key"])
            base = {
                "url": url,
                "endpoint_type": ep_type,
                "category": "header",
                "header_name": item["label"],
                "expected": item["expected"],
                "info": item["info"],
                "weight": item["weight"],
            }
            if actual is None:
                checklist.append({
                    **base,
                    "status": "missing",
                    "actual": None,
                    "severity": "medium",   # placeholder; LLM refines
                    "description": f"{item['label']} is not present. {item['info']}",
                })
            else:
                ok, detail = item["check"](actual)
                checklist.append({
                    **base,
                    "status": "pass" if ok else "fail",
                    "actual": actual[:300],
                    # Passes are final and carry no severity; fails get a placeholder.
                    "severity": None if ok else "medium",
                    "description": detail,
                })

        # ── CORS posture for API endpoints (fail-only checks) ──
        if ep_type in ("api", "api_reference") or "/api/" in url.lower():
            acao = headers_lower.get("access-control-allow-origin")
            acac = headers_lower.get("access-control-allow-credentials")
            if acao == "*" and acac and acac.lower() == "true":
                checklist.append({
                    "url": url, "endpoint_type": ep_type, "category": "cors",
                    "header_name": "CORS (credentials + wildcard)", "weight": 0,
                    "expected": "Specific origin when credentials are allowed",
                    "actual": "Access-Control-Allow-Origin: * with credentials: true",
                    "status": "fail", "severity": "critical",
                    "info": "Wildcard CORS with credentials enables cross-origin credential theft.",
                    "description": "API allows credentials with a wildcard origin — a critical misconfiguration.",
                })
            elif acao == "*":
                checklist.append({
                    "url": url, "endpoint_type": ep_type, "category": "cors",
                    "header_name": "CORS (wildcard origin)", "weight": 0,
                    "expected": "Specific origin or absent",
                    "actual": "Access-Control-Allow-Origin: *",
                    "status": "fail", "severity": "high",
                    "info": "Wildcard CORS lets any site call this API.",
                    "description": "API sets Access-Control-Allow-Origin: * — any origin can call it.",
                })

        # ── Cookie flags — one checklist item per flag per cookie ──
        for cookie_str in cookies:
            name = _cookie_name(cookie_str)
            low = cookie_str.lower()
            for cf in COOKIE_FLAGS:
                present = cf["flag"].lower() in low
                checklist.append({
                    "url": url,
                    "endpoint_type": ep_type,
                    "category": "cookie",
                    "header_name": f"Cookie '{name}' · {cf['flag']}",
                    "expected": cf["expected"],
                    "info": cf["info"],
                    "weight": 1,
                    "actual": None if not present else f"{cf['flag']} present",
                    "status": "pass" if present else "missing",
                    "severity": None if present else "medium",
                    "description": (
                        f"'{name}' sets {cf['flag']}."
                        if present
                        else f"'{name}' is missing {cf['flag']}. {cf['info']}"
                    ),
                })

    return {"checklist_results": checklist}


# ── Node 3: Severity Scorer (LLM — scores ONLY fail/missing) ──────────────────

def _severity_counts(items: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for it in items:
        sev = (it.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


async def severity_scorer_node(state: HeaderAuditState) -> dict:
    """LLM-score only the failing/missing checklist items, then build the report.

    Passing items are objectively correct and never sent to the model — they are
    carried through untouched. Only the problems get context-aware severities and
    explanations, which keeps the run cheap and removes any chance of the model
    hallucinating a problem on something that deterministically passed.
    """
    checklist = state.get("checklist_results", [])
    target_url = state.get("target_url", "unknown")
    errors: list[str] = []

    passes = [c for c in checklist if c["status"] == "pass"]
    problems = [c for c in checklist if c["status"] in ("fail", "missing")]

    # Ratio for the executive summary — weighted checklist items only.
    graded = [c for c in checklist if c.get("weight", 0) > 0]
    configured = sum(1 for c in graded if c["status"] == "pass")
    graded_total = len(graded)

    scored_problems = problems
    if problems:
        llm = get_llm()
        # Send only what the model needs to judge — no passes.
        slim = [
            {
                "i": idx,
                "url": p["url"],
                "endpoint_type": p.get("endpoint_type", "unknown"),
                "header_name": p["header_name"],
                "status": p["status"],
                "expected": p["expected"],
                "actual": p.get("actual"),
            }
            for idx, p in enumerate(problems)
        ]
        prompt = f"""You are a senior web security auditor reviewing FAILING or MISSING \
security-header and cookie checks from a scan of {target_url}.

Assign a context-aware severity to each item. Consider the endpoint type: a \
missing header on an auth_page/dashboard/api is more serious than on a \
static_asset. Severity scale:
- "critical": directly, easily exploitable (e.g. wildcard CORS with credentials)
- "high": significant risk, exploitable with moderate effort
- "medium": best-practice violation, real but not urgent
- "low": defence-in-depth / minor
- "info": negligible security impact in context

Items (each has an index "i"):
{json.dumps(slim, indent=2)}

Respond with ONLY a JSON array. One object per item:
{{"i": <index>, "severity": "<critical|high|medium|low|info>", "description": "<one concise, actionable sentence>"}}

JSON array:"""
        try:
            response = await llm.ainvoke(prompt)
            text = response.content.strip()
            match = re.search(r"\[.*\]", text, re.DOTALL)
            scored = json.loads(match.group() if match else text)
            by_index = {int(s["i"]): s for s in scored if "i" in s}
            scored_problems = []
            for idx, p in enumerate(problems):
                s = by_index.get(idx)
                if s:
                    p = {
                        **p,
                        "severity": (s.get("severity") or p["severity"] or "medium").lower(),
                        "description": s.get("description") or p["description"],
                    }
                scored_problems.append(p)
        except Exception as e:
            errors.append(f"LLM scoring failed, using default severities: {str(e)}")
            scored_problems = problems

    # Full checklist = scored problems + untouched passes, stable-ordered.
    scored_by_key = {(p["url"], p["header_name"]): p for p in scored_problems}
    full_checklist = [
        scored_by_key.get((c["url"], c["header_name"]), c) if c["status"] != "pass" else c
        for c in checklist
    ]

    sev_counts = _severity_counts(scored_problems)
    summary = _build_summary(
        target_url, configured, graded_total, len(passes), scored_problems, sev_counts
    )

    report = {
        "target_url": target_url,
        "endpoints_audited": len({c["url"] for c in checklist}),
        "checklist": full_checklist,
        "passes": passes,
        "findings": scored_problems,          # fail/missing only — the "problems"
        "total_findings": len(scored_problems),
        "total_checks": len(checklist),
        "configured_count": configured,
        "graded_total": graded_total,
        "severity_breakdown": sev_counts,
        "summary": summary,
        "scan_timestamp": datetime.now().isoformat(),
    }

    return {
        "scored_findings": scored_problems,
        "audit_report": report,
        "errors": errors,
    }


def _build_summary(
    target_url: str, configured: int, graded_total: int,
    total_passes: int, problems: list[dict], sev_counts: dict,
) -> str:
    """A ratio-first executive summary — configured vs total, then the risks."""
    if graded_total == 0:
        return "No endpoints returned headers to audit."

    ratio = f"{configured}/{graded_total} graded security controls are correctly configured"
    if not problems:
        return f"{ratio}. No missing or misconfigured headers or cookie flags were found."

    top = ", ".join(
        f"{sev_counts[s]} {s}" for s in ("critical", "high", "medium", "low")
        if sev_counts.get(s)
    )
    return (
        f"{ratio}. {len(problems)} item(s) need attention"
        + (f" ({top})" if top else "")
        + ". The report lists every check per endpoint — green for correctly set, "
        "red or amber for missing or misconfigured."
    )
