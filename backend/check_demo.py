"""Check what Supabase artifacts the demo site exposes."""
import re
from playwright.sync_api import sync_playwright

def run():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        requests_logged = []
        headers_logged = []

        def on_req(req):
            requests_logged.append(req.url)
            headers_logged.append(dict(req.headers) if req.headers else {})

        page.on("request", on_req)
        page.goto("https://kickstart-crypto-nine.vercel.app/", wait_until="load", timeout=20_000)
        try:
            page.wait_for_load_state("networkidle", timeout=5_000)
        except Exception:
            pass

        source = page.content()

        # Also fetch JS bundles
        script_urls = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
        browser.close()

        print("=" * 60)
        print("PAGE SOURCE ANALYSIS")
        print("=" * 60)

        # 1. Supabase URL pattern
        sb_urls = re.findall(r"(https://[a-zA-Z0-9-]+\.supabase\.co)", source)
        print(f"Supabase URLs in source: {sb_urls}")

        # 2. Publishable key pattern (new Supabase format)
        pub_keys = re.findall(r"(sb_publishable_[A-Za-z0-9_-]+)", source)
        print(f"Publishable keys in source: {pub_keys}")

        # 3. Classic JWT keys
        jwt_keys = re.findall(r"(eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+)", source)
        print(f"JWT keys in source: {jwt_keys[:2]}")

        # 4. Any "supabase" text
        sb_mentions = re.findall(r"supabase", source, re.IGNORECASE)
        print(f"'supabase' mentions in source: {len(sb_mentions)}")

        # 5. supabaseUrl / supabaseKey assignments
        sb_url_assign = re.findall(r'supabaseUrl\s*[=:]\s*["\']([^"\']+)["\']', source)
        sb_key_assign = re.findall(r'supabaseKey\s*[=:]\s*["\']([^"\']+)["\']', source)
        print(f"supabaseUrl assignments: {sb_url_assign}")
        print(f"supabaseKey assignments: {sb_key_assign}")

        print(f"\n{'=' * 60}")
        print("NETWORK REQUESTS")
        print("=" * 60)
        sb_reqs = [u for u in requests_logged if "supabase" in u.lower()]
        print(f"Supabase network requests ({len(sb_reqs)}):")
        for u in sb_reqs[:10]:
            print(f"  {u[:120]}")

        # Check headers for apikey
        for i, url in enumerate(requests_logged):
            if "supabase" in url.lower():
                h = headers_logged[i]
                if "apikey" in h:
                    print(f"  apikey header: {h['apikey'][:40]}...")

        print(f"\n{'=' * 60}")
        print("JS BUNDLES")
        print("=" * 60)
        print(f"Script URLs: {len(script_urls)}")
        for s in script_urls[:10]:
            print(f"  {s[:120]}")

        # Quick scan of first few JS bundles for supabase
        import requests as sync_requests
        for script_url in script_urls[:15]:
            try:
                r = sync_requests.get(script_url, timeout=5)
                if r.status_code == 200:
                    js = r.text
                    if "supabase" in js.lower():
                        sb_in_js = re.findall(r"(https://[a-zA-Z0-9-]+\.supabase\.co)", js)
                        pub_in_js = re.findall(r"(sb_publishable_[A-Za-z0-9_-]+)", js)
                        jwt_in_js = re.findall(r"(eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+)", js)
                        if sb_in_js or pub_in_js or jwt_in_js:
                            print(f"\n  FOUND in {script_url[-60:]}:")
                            if sb_in_js: print(f"    URLs: {sb_in_js}")
                            if pub_in_js: print(f"    Publishable keys: {pub_in_js}")
                            if jwt_in_js: print(f"    JWT keys: {jwt_in_js[:1]}")
            except Exception:
                pass


if __name__ == "__main__":
    run()
