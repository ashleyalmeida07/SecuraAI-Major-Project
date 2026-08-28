import chromadb
import uuid
import sys
import os

# Add backend directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import settings

def seed_chroma():
    chroma_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "chroma_db")
    print(f"Connecting to ChromaDB at {chroma_path}")
    client = chromadb.PersistentClient(path=chroma_path)

    print("Re-creating collections: vulnerable_patterns, safe_patterns")
    try:
        client.delete_collection("vulnerable_patterns")
    except:
        pass
    try:
        client.delete_collection("safe_patterns")
    except:
        pass

    vuln_col = client.create_collection("vulnerable_patterns")
    safe_col = client.create_collection("safe_patterns")

    # Seed data
    # Format: (vuln_code, safe_code, metadata)
    seed_data = [
        # SQL Injection (Express)
        (
            "db.query('SELECT * FROM users WHERE id = ' + req.params.id)",
            "db.query('SELECT * FROM users WHERE id = ?', [req.params.id])",
            {"vuln_type": "SQL Injection", "framework": "Express", "severity": "high", "cwe": "CWE-89"}
        ),
        (
            "const query = `SELECT * FROM users WHERE username = '${req.body.username}'`; db.execute(query);",
            "const query = 'SELECT * FROM users WHERE username = ?'; db.execute(query, [req.body.username]);",
            {"vuln_type": "SQL Injection", "framework": "Express", "severity": "high", "cwe": "CWE-89"}
        ),
        # SQL Injection (Django)
        (
            "User.objects.raw('SELECT * FROM auth_user WHERE username = %s' % username)",
            "User.objects.raw('SELECT * FROM auth_user WHERE username = %s', [username])",
            {"vuln_type": "SQL Injection", "framework": "Django", "severity": "high", "cwe": "CWE-89"}
        ),
        (
            "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            {"vuln_type": "SQL Injection", "framework": "Django", "severity": "high", "cwe": "CWE-89"}
        ),
        # SQL Injection (FastAPI / SQLAlchemy)
        (
            "session.execute(f'SELECT * FROM users WHERE username = \\'{username}\\'')",
            "session.execute(text('SELECT * FROM users WHERE username = :username'), {'username': username})",
            {"vuln_type": "SQL Injection", "framework": "FastAPI", "severity": "high", "cwe": "CWE-89"}
        ),

        # XSS (Express)
        (
            "res.send('<html><body>Hello ' + req.query.name + '</body></html>')",
            "const escapeHtml = require('escape-html'); res.send('<html><body>Hello ' + escapeHtml(req.query.name) + '</body></html>')",
            {"vuln_type": "Cross-Site Scripting (XSS)", "framework": "Express", "severity": "medium", "cwe": "CWE-79"}
        ),
        (
            "document.getElementById('greeting').innerHTML = 'Hello ' + new URLSearchParams(window.location.search).get('name');",
            "document.getElementById('greeting').textContent = 'Hello ' + new URLSearchParams(window.location.search).get('name');",
            {"vuln_type": "Cross-Site Scripting (XSS)", "framework": "Vanilla JS", "severity": "medium", "cwe": "CWE-79"}
        ),
        # XSS (Django)
        (
            "from django.utils.safestring import mark_safe\ndef my_view(request):\n    return HttpResponse(mark_safe(f'Hello {request.GET.get(\"name\")}'))",
            "from django.utils.html import escape\ndef my_view(request):\n    return HttpResponse(f'Hello {escape(request.GET.get(\"name\"))}')",
            {"vuln_type": "Cross-Site Scripting (XSS)", "framework": "Django", "severity": "medium", "cwe": "CWE-79"}
        ),

        # SSRF (Express)
        (
            "const request = require('request');\nrequest(req.query.url, function (error, response, body) { res.send(body); });",
            "// SSRF Fixed by validating URL against allowlist\nconst allowed = ['https://api.example.com'];\nif (allowed.includes(req.query.url)) {\n  request(req.query.url, function (error, response, body) { res.send(body); });\n}",
            {"vuln_type": "Server-Side Request Forgery (SSRF)", "framework": "Express", "severity": "high", "cwe": "CWE-918"}
        ),
        # SSRF (FastAPI)
        (
            "import requests\n@app.get('/fetch')\ndef fetch_url(url: str):\n    return requests.get(url).text",
            "import requests\nfrom urllib.parse import urlparse\n@app.get('/fetch')\ndef fetch_url(url: str):\n    parsed = urlparse(url)\n    if parsed.hostname in ['api.example.com']:\n        return requests.get(url).text\n    return 'Invalid URL'",
            {"vuln_type": "Server-Side Request Forgery (SSRF)", "framework": "FastAPI", "severity": "high", "cwe": "CWE-918"}
        ),

        # Insecure Deserialization (FastAPI / Python)
        (
            "import pickle\n@app.post('/load')\ndef load_data(data: bytes):\n    return pickle.loads(data)",
            "import json\n@app.post('/load')\ndef load_data(data: bytes):\n    return json.loads(data)",
            {"vuln_type": "Insecure Deserialization", "framework": "FastAPI", "severity": "critical", "cwe": "CWE-502"}
        ),
        (
            "import yaml\n@app.post('/parse')\ndef parse_yaml(data: str):\n    return yaml.load(data)",
            "import yaml\n@app.post('/parse')\ndef parse_yaml(data: str):\n    return yaml.safe_load(data)",
            {"vuln_type": "Insecure Deserialization", "framework": "FastAPI", "severity": "critical", "cwe": "CWE-502"}
        ),

        # Command Injection (Express)
        (
            "const { exec } = require('child_process');\nexec('ping -c 1 ' + req.body.ip, (err, stdout, stderr) => { res.send(stdout); });",
            "const { execFile } = require('child_process');\nexecFile('ping', ['-c', '1', req.body.ip], (err, stdout, stderr) => { res.send(stdout); });",
            {"vuln_type": "Command Injection", "framework": "Express", "severity": "critical", "cwe": "CWE-78"}
        ),
        # Command Injection (FastAPI)
        (
            "import os\n@app.get('/ping')\ndef ping(ip: str):\n    os.system(f'ping -c 1 {ip}')\n    return 'Done'",
            "import subprocess\n@app.get('/ping')\ndef ping(ip: str):\n    subprocess.run(['ping', '-c', '1', ip])\n    return 'Done'",
            {"vuln_type": "Command Injection", "framework": "FastAPI", "severity": "critical", "cwe": "CWE-78"}
        ),

        # Path Traversal (Express)
        (
            "const fs = require('fs');\napp.get('/file', (req, res) => {\n  fs.readFile(__dirname + '/public/' + req.query.file, 'utf8', (err, data) => { res.send(data); });\n});",
            "const fs = require('fs');\nconst path = require('path');\napp.get('/file', (req, res) => {\n  const safePath = path.join(__dirname, 'public', path.basename(req.query.file));\n  fs.readFile(safePath, 'utf8', (err, data) => { res.send(data); });\n});",
            {"vuln_type": "Path Traversal", "framework": "Express", "severity": "high", "cwe": "CWE-22"}
        ),
    ]

    vuln_docs = []
    vuln_metas = []
    vuln_ids = []

    safe_docs = []
    safe_metas = []
    safe_ids = []

    for vuln, safe, meta in seed_data:
        v_id = str(uuid.uuid4())
        s_id = str(uuid.uuid4())

        vuln_docs.append(vuln)
        vuln_metas.append(meta)
        vuln_ids.append(v_id)

        safe_meta = meta.copy()
        safe_meta["fix_for"] = v_id
        safe_docs.append(safe)
        safe_metas.append(safe_meta)
        safe_ids.append(s_id)

    print(f"Adding {len(vuln_docs)} vulnerable patterns to ChromaDB...")
    vuln_col.add(documents=vuln_docs, metadatas=vuln_metas, ids=vuln_ids)

    print(f"Adding {len(safe_docs)} safe patterns to ChromaDB...")
    safe_col.add(documents=safe_docs, metadatas=safe_metas, ids=safe_ids)

    print("ChromaDB seeding complete!")

if __name__ == "__main__":
    seed_chroma()
