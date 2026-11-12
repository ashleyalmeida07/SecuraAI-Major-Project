"""
LangGraph nodes for the BaaS Misconfiguration Scanner agent.

Node execution order:
  detect_baas → (should_continue) → enumerate_tables → read_access →
  write_access → storage_test → auth_config → report_builder → END

If no BaaS provider is detected, skips straight to report_builder.
"""

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import aiohttp
from app.agents.baas_audit.state import BaaSAuditState
from app.core.llm import get_llm


# ---------------------------------------------------------------------------
# Node 1: detect_baas_node
# ---------------------------------------------------------------------------


async def detect_baas_node(state: BaaSAuditState) -> dict:
    """Load target URL in a headless browser and detect Supabase/Firebase usage."""
    target_url = state["target_url"]
    network_requests: list[dict] = []
    errors: list[str] = []

    baas_provider = "none"
    project_url = ""
    anon_key = ""
    firebase_config: dict = {}

    try:
        from playwright.async_api import async_playwright  # noqa: PLC0415

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page()

            def _on_request(req: Any) -> None:
                entry: dict = {
                    "url": req.url,
                    "method": req.method,
                    "headers": dict(req.headers) if req.headers else {},
                }
                network_requests.append(entry)

            page.on("request", _on_request)

            try:
                await page.goto(target_url, wait_until="networkidle", timeout=30_000)
            except Exception as exc:
                errors.append(f"detect_baas_node: page.goto error: {exc}")

            # ------ Scan network requests for Supabase / Firebase ------
            for req_entry in network_requests:
                url = req_entry.get("url", "")
                headers = req_entry.get("headers", {})

                # Supabase detection
                if ".supabase.co" in url:
                    baas_provider = "supabase"
                    # Extract project URL (scheme + host)
                    parsed = urlparse(url)
                    project_url = f"{parsed.scheme}://{parsed.netloc}"
                    # Look for anon key
                    if "apikey" in headers:
                        anon_key = headers["apikey"]
                    auth_header = headers.get("authorization", "")
                    if auth_header.startswith("Bearer ") and not anon_key:
                        anon_key = auth_header.split("Bearer ", 1)[1].strip()

                # Firebase detection
                if any(
                    pat in url
                    for pat in [
                        ".firebaseio.com",
                        ".firebaseapp.com",
                        "identitytoolkit.googleapis.com",
                    ]
                ):
                    baas_provider = "firebase"

            # ------ Scan page JavaScript source for config objects ------
            try:
                page_source = await page.content()

                # Supabase: supabaseUrl / supabaseKey
                if baas_provider == "none" or baas_provider == "supabase":
                    sb_url_match = re.search(
                        r'supabaseUrl\s*[=:]\s*["\']([^"\']+)["\']', page_source
                    )
                    sb_key_match = re.search(
                        r'supabaseKey\s*[=:]\s*["\']([^"\']+)["\']', page_source
                    )
                    # Also try NEXT_PUBLIC_ patterns
                    if not sb_url_match:
                        sb_url_match = re.search(
                            r'NEXT_PUBLIC_SUPABASE_URL\s*[=:]\s*["\']([^"\']+)["\']',
                            page_source,
                        )
                    if not sb_key_match:
                        sb_key_match = re.search(
                            r'NEXT_PUBLIC_SUPABASE_ANON_KEY\s*[=:]\s*["\']([^"\']+)["\']',
                            page_source,
                        )
                    # Try generic supabase patterns
                    if not sb_url_match:
                        sb_url_match = re.search(
                            r'(https://[a-zA-Z0-9-]+\.supabase\.co)', page_source
                        )
                    if sb_url_match:
                        baas_provider = "supabase"
                        if not project_url:
                            project_url = sb_url_match.group(1).rstrip("/")
                    if sb_key_match and not anon_key:
                        anon_key = sb_key_match.group(1)

                # Firebase: firebaseConfig object
                if baas_provider == "none" or baas_provider == "firebase":
                    fb_match = re.search(
                        r'(?:firebaseConfig|firebase\.initializeApp)\s*\(\s*(\{[^}]+\})',
                        page_source,
                        re.DOTALL,
                    )
                    if fb_match:
                        try:
                            # Attempt to parse the JS object as JSON (works for
                            # simple configs with quoted keys)
                            raw = fb_match.group(1)
                            # Fix JS-style keys: apiKey → "apiKey"
                            raw_fixed = re.sub(
                                r'(\w+)\s*:', r'"\1":', raw
                            )
                            raw_fixed = raw_fixed.replace("'", '"')
                            firebase_config = json.loads(raw_fixed)
                            baas_provider = "firebase"
                        except Exception:
                            pass

                    # Also look for individual Firebase config values
                    if baas_provider != "firebase":
                        api_key_match = re.search(
                            r'apiKey\s*[=:]\s*["\']([^"\']+)["\']', page_source
                        )
                        auth_domain_match = re.search(
                            r'authDomain\s*[=:]\s*["\']([^"\']+)["\']', page_source
                        )
                        project_id_match = re.search(
                            r'projectId\s*[=:]\s*["\']([^"\']+)["\']', page_source
                        )
                        if api_key_match and (auth_domain_match or project_id_match):
                            baas_provider = "firebase"
                            firebase_config = {
                                "apiKey": api_key_match.group(1),
                            }
                            if auth_domain_match:
                                firebase_config["authDomain"] = auth_domain_match.group(1)
                            if project_id_match:
                                firebase_config["projectId"] = project_id_match.group(1)

                # Extract script source URLs and fetch them for deeper scanning
                script_urls = await page.eval_on_selector_all(
                    "script[src]", "els => els.map(e => e.src)"
                )
                for script_url in script_urls[:20]:  # cap to prevent abuse
                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.get(
                                script_url,
                                timeout=aiohttp.ClientTimeout(total=10),
                            ) as resp:
                                if resp.status == 200:
                                    js_text = await resp.text()

                                    # Supabase in JS bundles
                                    if baas_provider == "none":
                                        sb_url_m = re.search(
                                            r'(https://[a-zA-Z0-9-]+\.supabase\.co)',
                                            js_text,
                                        )
                                        sb_key_m = re.search(
                                            r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+',
                                            js_text,
                                        )
                                        if sb_url_m:
                                            baas_provider = "supabase"
                                            project_url = sb_url_m.group(1).rstrip("/")
                                        if sb_key_m and not anon_key:
                                            anon_key = sb_key_m.group(0)

                                    # Firebase in JS bundles
                                    if baas_provider == "none":
                                        fb_m = re.search(
                                            r'(?:firebaseConfig|firebase\.initializeApp)\s*\(\s*(\{[^}]+\})',
                                            js_text,
                                            re.DOTALL,
                                        )
                                        if fb_m:
                                            try:
                                                raw = fb_m.group(1)
                                                raw_fixed = re.sub(
                                                    r'(\w+)\s*:', r'"\1":', raw
                                                )
                                                raw_fixed = raw_fixed.replace("'", '"')
                                                firebase_config = json.loads(raw_fixed)
                                                baas_provider = "firebase"
                                            except Exception:
                                                pass
                    except Exception:
                        pass

            except Exception as exc:
                errors.append(f"detect_baas_node: source scan error: {exc}")

            await browser.close()
    except Exception as exc:
        errors.append(f"detect_baas_node: playwright error: {exc}")

    # For Firebase: extract project_url and anon_key from config
    if baas_provider == "firebase" and firebase_config:
        if not project_url and firebase_config.get("projectId"):
            project_url = firebase_config["projectId"]
        if not anon_key and firebase_config.get("apiKey"):
            anon_key = firebase_config["apiKey"]

    return {
        "network_requests": network_requests,
        "baas_provider": baas_provider,
        "project_url": project_url,
        "anon_key": anon_key,
        "firebase_config": firebase_config,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Node 2: enumerate_tables_node
# ---------------------------------------------------------------------------


async def enumerate_tables_node(state: BaaSAuditState) -> dict:
    """Discover tables (Supabase) or collections (Firebase)."""
    baas_provider = state.get("baas_provider", "none")
    project_url = state.get("project_url", "")
    anon_key = state.get("anon_key", "")
    firebase_config = state.get("firebase_config", {})
    network_requests = state.get("network_requests", [])
    tables: list[str] = []
    errors: list[str] = []

    if baas_provider == "supabase" and project_url and anon_key:
        # PostgREST OpenAPI spec endpoint
        try:
            headers = {
                "apikey": anon_key,
                "Authorization": f"Bearer {anon_key}",
            }
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{project_url}/rest/v1/",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # PostgREST returns OpenAPI spec with paths or definitions
                        if "paths" in data:
                            for path_key in data["paths"]:
                                table_name = path_key.strip("/")
                                if table_name and not table_name.startswith("rpc/"):
                                    tables.append(table_name)
                        elif "definitions" in data:
                            tables.extend(data["definitions"].keys())
                    else:
                        errors.append(
                            f"enumerate_tables_node: PostgREST returned {resp.status}"
                        )
        except Exception as exc:
            errors.append(f"enumerate_tables_node: supabase error: {exc}")

    elif baas_provider == "firebase":
        # Grep captured JS / network requests for collection() / doc() patterns
        all_text = ""
        for req_entry in network_requests:
            url = req_entry.get("url", "")
            all_text += url + " "

        # Also try to fetch page source via a quick request
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    state["target_url"],
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        all_text += await resp.text()
        except Exception:
            pass

        # Find collection("name") and doc("name") patterns
        collection_matches = re.findall(r'collection\(["\']([^"\']+)["\']\)', all_text)
        doc_matches = re.findall(r'doc\(["\']([^"\']+)["\']\)', all_text)

        seen: set[str] = set()
        for name in collection_matches + doc_matches:
            # doc paths like "users/abc" → extract collection name
            parts = name.split("/")
            collection_name = parts[0]
            if collection_name and collection_name not in seen:
                seen.add(collection_name)
                tables.append(collection_name)

        # Common Firebase collections as fallback candidates
        if not tables:
            tables = ["users", "posts", "messages", "orders", "products", "items"]

    return {"tables": tables, "errors": errors}


# ---------------------------------------------------------------------------
# Node 3: read_access_node
# ---------------------------------------------------------------------------


async def read_access_node(state: BaaSAuditState) -> dict:
    """Test anonymous read access on each discovered table/collection."""
    baas_provider = state.get("baas_provider", "none")
    project_url = state.get("project_url", "")
    anon_key = state.get("anon_key", "")
    firebase_config = state.get("firebase_config", {})
    tables = state.get("tables", [])
    read_results: list[dict] = []
    errors: list[str] = []

    if baas_provider == "supabase" and project_url and anon_key:
        headers = {
            "apikey": anon_key,
            "Authorization": f"Bearer {anon_key}",
        }
        async with aiohttp.ClientSession() as session:
            for table in tables:
                try:
                    async with session.get(
                        f"{project_url}/rest/v1/{table}?limit=5",
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        status = resp.status
                        body = await resp.text()
                        if status == 200:
                            try:
                                rows = json.loads(body)
                                if isinstance(rows, list) and len(rows) > 0:
                                    # Log field names only, NEVER full row contents
                                    field_names = (
                                        list(rows[0].keys()) if rows else []
                                    )
                                    read_results.append(
                                        {
                                            "table": table,
                                            "status": "fail",
                                            "severity": "high",
                                            "evidence": f"Returned {len(rows)} row(s). Fields: {field_names}",
                                            "fix_suggestion": f"Enable RLS: ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; "
                                            f"CREATE POLICY \"deny_anon_read\" ON {table} FOR SELECT USING (auth.role() = 'authenticated');",
                                        }
                                    )
                                else:
                                    read_results.append(
                                        {
                                            "table": table,
                                            "status": "pass",
                                            "severity": "none",
                                            "evidence": "200 but empty result set — RLS likely active",
                                            "fix_suggestion": "",
                                        }
                                    )
                            except json.JSONDecodeError:
                                read_results.append(
                                    {
                                        "table": table,
                                        "status": "pass",
                                        "severity": "none",
                                        "evidence": "Non-JSON 200 response",
                                        "fix_suggestion": "",
                                    }
                                )
                        elif status in (401, 403):
                            read_results.append(
                                {
                                    "table": table,
                                    "status": "pass",
                                    "severity": "none",
                                    "evidence": f"HTTP {status} — access denied",
                                    "fix_suggestion": "",
                                }
                            )
                        else:
                            read_results.append(
                                {
                                    "table": table,
                                    "status": "pass",
                                    "severity": "none",
                                    "evidence": f"HTTP {status}",
                                    "fix_suggestion": "",
                                }
                            )
                except Exception as exc:
                    errors.append(f"read_access_node: {table}: {exc}")

    elif baas_provider == "firebase":
        project_id = firebase_config.get("projectId", project_url)
        async with aiohttp.ClientSession() as session:
            for collection in tables:
                try:
                    url = (
                        f"https://firestore.googleapis.com/v1/projects/{project_id}"
                        f"/databases/(default)/documents/{collection}"
                    )
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        status = resp.status
                        body = await resp.text()
                        if status == 200:
                            try:
                                data = json.loads(body)
                                documents = data.get("documents", [])
                                if documents:
                                    read_results.append(
                                        {
                                            "table": collection,
                                            "status": "fail",
                                            "severity": "high",
                                            "evidence": f"Returned {len(documents)} document(s) without auth",
                                            "fix_suggestion": f'Set Firestore rules: match /{collection}/{{doc}} {{ allow read: if request.auth != null; }}',
                                        }
                                    )
                                else:
                                    read_results.append(
                                        {
                                            "table": collection,
                                            "status": "pass",
                                            "severity": "none",
                                            "evidence": "200 but no documents returned",
                                            "fix_suggestion": "",
                                        }
                                    )
                            except json.JSONDecodeError:
                                read_results.append(
                                    {
                                        "table": collection,
                                        "status": "pass",
                                        "severity": "none",
                                        "evidence": "Non-JSON response",
                                        "fix_suggestion": "",
                                    }
                                )
                        else:
                            read_results.append(
                                {
                                    "table": collection,
                                    "status": "pass",
                                    "severity": "none",
                                    "evidence": f"HTTP {status} — access denied",
                                    "fix_suggestion": "",
                                }
                            )
                except Exception as exc:
                    errors.append(f"read_access_node: {collection}: {exc}")

    return {"read_results": read_results, "errors": errors}


# ---------------------------------------------------------------------------
# Node 4: write_access_node
# ---------------------------------------------------------------------------


async def write_access_node(state: BaaSAuditState) -> dict:
    """Test anonymous write access — insert a probe row then immediately delete it."""
    baas_provider = state.get("baas_provider", "none")
    project_url = state.get("project_url", "")
    anon_key = state.get("anon_key", "")
    firebase_config = state.get("firebase_config", {})
    tables = state.get("tables", [])
    write_results: list[dict] = []
    errors: list[str] = []

    probe_body = {"secura_test": True, "_secura_marker": "baas_audit_probe"}

    if baas_provider == "supabase" and project_url and anon_key:
        headers = {
            "apikey": anon_key,
            "Authorization": f"Bearer {anon_key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }
        async with aiohttp.ClientSession() as session:
            for table in tables:
                try:
                    async with session.post(
                        f"{project_url}/rest/v1/{table}",
                        json=probe_body,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        status = resp.status
                        body = await resp.text()
                        if status == 201:
                            # Immediately DELETE the created row
                            try:
                                rows = json.loads(body)
                                if isinstance(rows, list) and rows:
                                    row_id = rows[0].get("id")
                                    if row_id is not None:
                                        await session.delete(
                                            f"{project_url}/rest/v1/{table}?id=eq.{row_id}",
                                            headers={
                                                "apikey": anon_key,
                                                "Authorization": f"Bearer {anon_key}",
                                            },
                                            timeout=aiohttp.ClientTimeout(total=10),
                                        )
                            except Exception as del_exc:
                                errors.append(
                                    f"write_access_node: cleanup {table}: {del_exc}"
                                )

                            write_results.append(
                                {
                                    "table": table,
                                    "status": "fail",
                                    "severity": "critical",
                                    "evidence": f"Anonymous write succeeded (HTTP 201) on {table}",
                                    "fix_suggestion": f"Enable RLS: ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; "
                                    f"CREATE POLICY \"deny_anon_insert\" ON {table} FOR INSERT WITH CHECK (auth.role() = 'authenticated');",
                                }
                            )
                        elif status in (401, 403):
                            write_results.append(
                                {
                                    "table": table,
                                    "status": "pass",
                                    "severity": "none",
                                    "evidence": f"HTTP {status} — write denied",
                                    "fix_suggestion": "",
                                }
                            )
                        else:
                            write_results.append(
                                {
                                    "table": table,
                                    "status": "pass",
                                    "severity": "none",
                                    "evidence": f"HTTP {status} — write not permitted",
                                    "fix_suggestion": "",
                                }
                            )
                except Exception as exc:
                    errors.append(f"write_access_node: {table}: {exc}")

    elif baas_provider == "firebase":
        project_id = firebase_config.get("projectId", project_url)
        async with aiohttp.ClientSession() as session:
            for collection in tables:
                try:
                    url = (
                        f"https://firestore.googleapis.com/v1/projects/{project_id}"
                        f"/databases/(default)/documents/{collection}"
                    )
                    # Firestore REST: create a document
                    firestore_body = {
                        "fields": {
                            "secura_test": {"booleanValue": True},
                            "_secura_marker": {"stringValue": "baas_audit_probe"},
                        }
                    }
                    async with session.post(
                        url,
                        json=firestore_body,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        status = resp.status
                        body = await resp.text()
                        if status == 200:
                            # Immediately delete the created document
                            try:
                                data = json.loads(body)
                                doc_name = data.get("name", "")
                                if doc_name:
                                    delete_url = f"https://firestore.googleapis.com/v1/{doc_name}"
                                    await session.delete(
                                        delete_url,
                                        timeout=aiohttp.ClientTimeout(total=10),
                                    )
                            except Exception as del_exc:
                                errors.append(
                                    f"write_access_node: cleanup {collection}: {del_exc}"
                                )

                            write_results.append(
                                {
                                    "table": collection,
                                    "status": "fail",
                                    "severity": "critical",
                                    "evidence": f"Anonymous write succeeded on {collection}",
                                    "fix_suggestion": f'Set Firestore rules: match /{collection}/{{doc}} {{ allow write: if request.auth != null; }}',
                                }
                            )
                        else:
                            write_results.append(
                                {
                                    "table": collection,
                                    "status": "pass",
                                    "severity": "none",
                                    "evidence": f"HTTP {status} — write denied",
                                    "fix_suggestion": "",
                                }
                            )
                except Exception as exc:
                    errors.append(f"write_access_node: {collection}: {exc}")

    return {"write_results": write_results, "errors": errors}


# ---------------------------------------------------------------------------
# Node 5: storage_test_node
# ---------------------------------------------------------------------------


async def storage_test_node(state: BaaSAuditState) -> dict:
    """Test storage bucket access — listing and public object enumeration."""
    baas_provider = state.get("baas_provider", "none")
    project_url = state.get("project_url", "")
    anon_key = state.get("anon_key", "")
    firebase_config = state.get("firebase_config", {})
    storage_results: list[dict] = []
    errors: list[str] = []

    if baas_provider == "supabase" and project_url and anon_key:
        headers = {
            "apikey": anon_key,
            "Authorization": f"Bearer {anon_key}",
        }
        async with aiohttp.ClientSession() as session:
            # List all buckets
            try:
                async with session.get(
                    f"{project_url}/storage/v1/bucket",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    status = resp.status
                    body = await resp.text()
                    if status == 200:
                        try:
                            buckets = json.loads(body)
                            if isinstance(buckets, list) and buckets:
                                bucket_names = [
                                    b.get("name", b.get("id", "unknown"))
                                    for b in buckets
                                ]
                                storage_results.append(
                                    {
                                        "resource": "bucket_list",
                                        "status": "fail",
                                        "severity": "medium",
                                        "evidence": f"Listed {len(buckets)} bucket(s): {bucket_names}",
                                        "fix_suggestion": "Restrict bucket listing via RLS policies on storage.buckets or use Supabase dashboard to set buckets as private.",
                                    }
                                )

                                # Try listing objects in each bucket
                                for bucket_name in bucket_names:
                                    try:
                                        list_body = {
                                            "prefix": "",
                                            "limit": 10,
                                            "offset": 0,
                                        }
                                        async with session.post(
                                            f"{project_url}/storage/v1/object/list/{bucket_name}",
                                            json=list_body,
                                            headers={
                                                **headers,
                                                "Content-Type": "application/json",
                                            },
                                            timeout=aiohttp.ClientTimeout(total=10),
                                        ) as obj_resp:
                                            if obj_resp.status == 200:
                                                objs = await obj_resp.json()
                                                if isinstance(objs, list) and objs:
                                                    storage_results.append(
                                                        {
                                                            "resource": f"bucket:{bucket_name}",
                                                            "status": "fail",
                                                            "severity": "medium",
                                                            "evidence": f"Listed {len(objs)} object(s) in bucket '{bucket_name}'",
                                                            "fix_suggestion": f"Set bucket '{bucket_name}' to private and add RLS policies on storage.objects.",
                                                        }
                                                    )
                                                else:
                                                    storage_results.append(
                                                        {
                                                            "resource": f"bucket:{bucket_name}",
                                                            "status": "pass",
                                                            "severity": "none",
                                                            "evidence": "Bucket accessible but empty or listing blocked",
                                                            "fix_suggestion": "",
                                                        }
                                                    )
                                            else:
                                                storage_results.append(
                                                    {
                                                        "resource": f"bucket:{bucket_name}",
                                                        "status": "pass",
                                                        "severity": "none",
                                                        "evidence": f"HTTP {obj_resp.status} — object listing denied",
                                                        "fix_suggestion": "",
                                                    }
                                                )
                                    except Exception as exc:
                                        errors.append(
                                            f"storage_test_node: list objects {bucket_name}: {exc}"
                                        )
                            else:
                                storage_results.append(
                                    {
                                        "resource": "bucket_list",
                                        "status": "pass",
                                        "severity": "none",
                                        "evidence": "200 but no buckets returned",
                                        "fix_suggestion": "",
                                    }
                                )
                        except json.JSONDecodeError:
                            storage_results.append(
                                {
                                    "resource": "bucket_list",
                                    "status": "pass",
                                    "severity": "none",
                                    "evidence": "Non-JSON response",
                                    "fix_suggestion": "",
                                }
                            )
                    elif status in (401, 403):
                        storage_results.append(
                            {
                                "resource": "bucket_list",
                                "status": "pass",
                                "severity": "none",
                                "evidence": f"HTTP {status} — bucket listing denied",
                                "fix_suggestion": "",
                            }
                        )
                    else:
                        storage_results.append(
                            {
                                "resource": "bucket_list",
                                "status": "pass",
                                "severity": "none",
                                "evidence": f"HTTP {status}",
                                "fix_suggestion": "",
                            }
                        )
            except Exception as exc:
                errors.append(f"storage_test_node: supabase bucket list: {exc}")

    elif baas_provider == "firebase":
        project_id = firebase_config.get("projectId", project_url)
        # Check default Firebase Storage bucket
        storage_bucket = firebase_config.get(
            "storageBucket", f"{project_id}.appspot.com"
        )
        if storage_bucket:
            try:
                async with aiohttp.ClientSession() as session:
                    # Firebase Storage REST API — list objects
                    url = f"https://firebasestorage.googleapis.com/v0/b/{storage_bucket}/o"
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        status = resp.status
                        if status == 200:
                            data = await resp.json()
                            items = data.get("items", [])
                            if items:
                                storage_results.append(
                                    {
                                        "resource": f"firebase_storage:{storage_bucket}",
                                        "status": "fail",
                                        "severity": "medium",
                                        "evidence": f"Public listing returned {len(items)} object(s)",
                                        "fix_suggestion": "Set Firebase Storage rules: allow read, write: if request.auth != null;",
                                    }
                                )
                            else:
                                storage_results.append(
                                    {
                                        "resource": f"firebase_storage:{storage_bucket}",
                                        "status": "pass",
                                        "severity": "none",
                                        "evidence": "200 but no items listed",
                                        "fix_suggestion": "",
                                    }
                                )
                        else:
                            storage_results.append(
                                {
                                    "resource": f"firebase_storage:{storage_bucket}",
                                    "status": "pass",
                                    "severity": "none",
                                    "evidence": f"HTTP {status} — listing denied",
                                    "fix_suggestion": "",
                                }
                            )
            except Exception as exc:
                errors.append(f"storage_test_node: firebase storage: {exc}")

    return {"storage_results": storage_results, "errors": errors}


# ---------------------------------------------------------------------------
# Node 6: auth_config_node
# ---------------------------------------------------------------------------


async def auth_config_node(state: BaaSAuditState) -> dict:
    """Test signup/auth configuration for unsafe defaults."""
    baas_provider = state.get("baas_provider", "none")
    project_url = state.get("project_url", "")
    anon_key = state.get("anon_key", "")
    firebase_config = state.get("firebase_config", {})
    auth_results: dict = {}
    errors: list[str] = []

    test_email = f"secura-test-{uuid.uuid4().hex[:8]}@test.invalid"
    test_password = "SecuraTestP@ss123!"

    if baas_provider == "supabase" and project_url and anon_key:
        try:
            headers = {
                "apikey": anon_key,
                "Authorization": f"Bearer {anon_key}",
                "Content-Type": "application/json",
            }
            body = {"email": test_email, "password": test_password}
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{project_url}/auth/v1/signup",
                    json=body,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    status = resp.status
                    resp_text = await resp.text()
                    try:
                        data = json.loads(resp_text)
                    except json.JSONDecodeError:
                        data = {}

                    if status == 200 and data.get("access_token"):
                        # Session token returned immediately → email confirmation off
                        auth_results = {
                            "signup_test": "fail",
                            "severity": "high",
                            "evidence": "Signup returned session token immediately — email confirmation disabled",
                            "fix_suggestion": "Enable email confirmation in Supabase Auth settings: Authentication → Settings → Enable email confirmations",
                            "email_confirmation_required": False,
                        }
                    elif status == 200 and not data.get("access_token"):
                        # 200 but no token → email confirmation required
                        auth_results = {
                            "signup_test": "pass",
                            "severity": "none",
                            "evidence": "Signup requires email confirmation before session is issued",
                            "fix_suggestion": "",
                            "email_confirmation_required": True,
                        }
                    elif status == 422 or status == 429:
                        auth_results = {
                            "signup_test": "pass",
                            "severity": "none",
                            "evidence": f"Signup rejected with HTTP {status} — rate-limited or validation enabled",
                            "fix_suggestion": "",
                            "email_confirmation_required": True,
                        }
                    else:
                        auth_results = {
                            "signup_test": "pass",
                            "severity": "none",
                            "evidence": f"HTTP {status} — signup not openly accessible",
                            "fix_suggestion": "",
                            "email_confirmation_required": True,
                        }
        except Exception as exc:
            errors.append(f"auth_config_node: supabase: {exc}")

    elif baas_provider == "firebase":
        api_key = firebase_config.get("apiKey", anon_key)
        if api_key:
            try:
                body = {
                    "email": test_email,
                    "password": test_password,
                    "returnSecureToken": True,
                }
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}",
                        json=body,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        status = resp.status
                        resp_text = await resp.text()
                        try:
                            data = json.loads(resp_text)
                        except json.JSONDecodeError:
                            data = {}

                        if status == 200 and data.get("idToken"):
                            auth_results = {
                                "signup_test": "fail",
                                "severity": "high",
                                "evidence": "Firebase signup accepted with no restrictions — anyone can create accounts",
                                "fix_suggestion": "Restrict signup: disable Email/Password auth if not needed, or add domain restrictions and enable email verification in Firebase Console → Authentication → Settings",
                            }
                        elif status == 400:
                            error_message = (
                                data.get("error", {}).get("message", "")
                            )
                            auth_results = {
                                "signup_test": "pass",
                                "severity": "none",
                                "evidence": f"Signup rejected: {error_message}",
                                "fix_suggestion": "",
                            }
                        else:
                            auth_results = {
                                "signup_test": "pass",
                                "severity": "none",
                                "evidence": f"HTTP {status} — signup restricted",
                                "fix_suggestion": "",
                            }
            except Exception as exc:
                errors.append(f"auth_config_node: firebase: {exc}")

    return {"auth_results": auth_results, "errors": errors}


# ---------------------------------------------------------------------------
# Node 7: report_builder_node
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


async def report_builder_node(state: BaaSAuditState) -> dict:
    """Compile all test results into the final BaaS audit report."""
    baas_provider = state.get("baas_provider", "none")
    project_url = state.get("project_url", "")
    tables = state.get("tables", [])
    read_results = state.get("read_results", [])
    write_results = state.get("write_results", [])
    storage_results = state.get("storage_results", [])
    auth_results = state.get("auth_results", {})
    errors: list[str] = list(state.get("errors", []))

    # Build findings list
    findings: list[dict] = []

    for r in read_results:
        findings.append(
            {
                "category": "read_access",
                "table_or_resource": r.get("table", ""),
                "status": r.get("status", "pass"),
                "severity": r.get("severity", "none"),
                "evidence": r.get("evidence", ""),
                "fix_suggestion": r.get("fix_suggestion", ""),
            }
        )

    for w in write_results:
        findings.append(
            {
                "category": "write_access",
                "table_or_resource": w.get("table", ""),
                "status": w.get("status", "pass"),
                "severity": w.get("severity", "none"),
                "evidence": w.get("evidence", ""),
                "fix_suggestion": w.get("fix_suggestion", ""),
            }
        )

    for s in storage_results:
        findings.append(
            {
                "category": "storage",
                "table_or_resource": s.get("resource", ""),
                "status": s.get("status", "pass"),
                "severity": s.get("severity", "none"),
                "evidence": s.get("evidence", ""),
                "fix_suggestion": s.get("fix_suggestion", ""),
            }
        )

    if auth_results:
        findings.append(
            {
                "category": "auth",
                "table_or_resource": "signup_config",
                "status": auth_results.get("signup_test", "pass"),
                "severity": auth_results.get("severity", "none"),
                "evidence": auth_results.get("evidence", ""),
                "fix_suggestion": auth_results.get("fix_suggestion", ""),
            }
        )

    total_checks = len(findings)
    total_passed = sum(1 for f in findings if f["status"] == "pass")
    total_failed = sum(1 for f in findings if f["status"] == "fail")

    severity_breakdown: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    for f in findings:
        if f["status"] == "fail":
            sev = f.get("severity", "medium").lower()
            if sev in severity_breakdown:
                severity_breakdown[sev] += 1

    # Map to relevant security standards
    standard_mappings: list[str] = []
    if total_failed > 0:
        if any(f["category"] == "read_access" and f["status"] == "fail" for f in findings):
            standard_mappings.append("OWASP API1:2023 Broken Object Level Authorization")
        if any(f["category"] == "write_access" and f["status"] == "fail" for f in findings):
            standard_mappings.append("OWASP API1:2023 Broken Object Level Authorization")
            standard_mappings.append("CWE-284 Improper Access Control")
        if any(f["category"] == "storage" and f["status"] == "fail" for f in findings):
            standard_mappings.append("OWASP API8:2023 Security Misconfiguration")
        if any(f["category"] == "auth" and f["status"] == "fail" for f in findings):
            standard_mappings.append("OWASP API2:2023 Broken Authentication")
    standard_mappings = list(dict.fromkeys(standard_mappings))  # dedupe, keep order

    # LLM executive summary
    summary = ""
    if baas_provider == "none":
        summary = "No Backend-as-a-Service (Supabase or Firebase) was detected on the target URL. No BaaS misconfiguration tests were performed."
    else:
        try:
            llm = get_llm()
            failed_list = ", ".join(
                f"{f['category']}/{f['table_or_resource']} ({f['severity']})"
                for f in findings
                if f["status"] == "fail"
            ) or "none"
            s_prompt = (
                f"You are a senior cloud security consultant writing an executive summary for a BaaS misconfiguration audit.\n"
                f"Target: {state.get('target_url', 'unknown')}\n"
                f"BaaS Provider: {baas_provider}\n"
                f"Project URL: {project_url}\n"
                f"Tables discovered: {len(tables)}\n"
                f"Total checks: {total_checks} | Passed: {total_passed} | Failed: {total_failed}\n"
                f"Severity breakdown: {severity_breakdown}\n"
                f"Failed checks: {failed_list}\n"
                f"Security standards: {', '.join(standard_mappings) if standard_mappings else 'none'}\n\n"
                "Write a concise 3-5 sentence executive summary covering risk level, main findings, and recommended actions."
            )
            resp = await llm.ainvoke(s_prompt)
            summary = resp.content.strip() if hasattr(resp, "content") else str(resp).strip()
        except Exception as exc:
            errors.append(f"report_builder_node summary error: {exc}")
            summary = (
                f"BaaS audit complete for {baas_provider}. "
                f"{total_failed} of {total_checks} checks failed. "
                "Review the findings for remediation guidance."
            )

    report = {
        "target_url": state.get("target_url", ""),
        "baas_provider": baas_provider,
        "project_url": project_url,
        "tables_discovered": len(tables),
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "total_checks": total_checks,
        "total_passed": total_passed,
        "total_failed": total_failed,
        "severity_breakdown": severity_breakdown,
        "standard_mappings": standard_mappings,
        "summary": summary,
        "errors": errors,
    }

    return {"baas_audit_report": report}
