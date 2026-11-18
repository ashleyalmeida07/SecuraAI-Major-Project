"""Quick scan of all JS chunks for supabase credentials."""
import re
import requests

BASE = "https://kickstart-crypto-nine.vercel.app"

# First get the page to find all script URLs
r = requests.get(BASE, timeout=10)
html = r.text

# Find all chunk URLs
chunks = re.findall(r'/_next/static/chunks/[^"\'\\s]+', html)
# Also try the page source for any __NEXT_DATA__ or build manifest
manifest_urls = re.findall(r'/_next/[^"\'\\s]+(?:buildManifest|ssgManifest|_buildManifest)[^"\'\\s]*', html)

print(f"Found {len(chunks)} chunk refs in HTML, {len(manifest_urls)} manifests")

# Check build manifest for more chunk URLs
for murl in manifest_urls[:3]:
    try:
        mr = requests.get(f"{BASE}{murl}", timeout=5)
        if mr.status_code == 200:
            more_chunks = re.findall(r'/_next/static/chunks/[^"\'\\s,\]]+', mr.text)
            chunks.extend(more_chunks)
            print(f"  Manifest {murl[-40:]} added {len(more_chunks)} chunks")
    except:
        pass

chunks = list(set(chunks))
print(f"Total unique chunks: {len(chunks)}")

# Scan each chunk for supabase
found_in = []
for i, chunk_path in enumerate(chunks):
    url = f"{BASE}{chunk_path}" if chunk_path.startswith("/") else chunk_path
    try:
        cr = requests.get(url, timeout=5)
        if cr.status_code == 200:
            js = cr.text
            if "supabase" in js.lower():
                sb_urls = re.findall(r'(https://[a-zA-Z0-9-]+\.supabase\.co)', js)
                pub_keys = re.findall(r'(sb_publishable_[A-Za-z0-9_-]+)', js)
                jwt_keys = re.findall(r'(eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+)', js)
                anon_refs = re.findall(r'supabaseUrl|supabaseKey|SUPABASE_URL|SUPABASE_ANON|SUPABASE_PUBLISHABLE|createClient', js, re.IGNORECASE)
                print(f"\n  SUPABASE found in chunk #{i}: {chunk_path[-50:]}")
                print(f"    URLs: {sb_urls}")
                print(f"    Publishable keys: {pub_keys}")
                print(f"    JWT keys: {jwt_keys[:1]}")
                print(f"    Refs: {anon_refs[:5]}")
                found_in.append(chunk_path)
    except:
        pass

print(f"\nTotal chunks with supabase: {len(found_in)}")
