"""
Seed Upstash Vector with vulnerable and safe code patterns.
Two pattern types in one index:
1. vulnerable - Known vulnerable code snippets with metadata
2. safe - Fixed/secure versions with links to vulnerable patterns

Source: OWASP vulnerable code samples, CVE writeups, OWASP Juice Shop, WebGoat, DVWA
"""

import uuid
import sys
import os

# Add backend directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import settings
from upstash_vector import Index


# Comprehensive seed data covering top OWASP categories
# Format: (vuln_code, safe_code, metadata)
SEED_PATTERNS = [
    # ============ SQL Injection Patterns ============
    # Express
    (
        'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
        'db.query("SELECT * FROM users WHERE id = ?", [req.params.id])',
        {
            "vuln_type": "SQL Injection",
            "framework": "Express",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript"
        }
    ),
    (
        "const query = `SELECT * FROM users WHERE username = '${req.body.username}'`; db.execute(query);",
        "const query = 'SELECT * FROM users WHERE username = ?'; db.execute(query, [req.body.username]);",
        {
            "vuln_type": "SQL Injection",
            "framework": "Express",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript"
        }
    ),
    # Django
    (
        "User.objects.raw('SELECT * FROM auth_user WHERE username = %s' % username)",
        "User.objects.raw('SELECT * FROM auth_user WHERE username = %s', [username])",
        {
            "vuln_type": "SQL Injection",
            "framework": "Django",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "language": "Python"
        }
    ),
    (
        "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        {
            "vuln_type": "SQL Injection",
            "framework": "Django",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "language": "Python"
        }
    ),
    # FastAPI
    (
        "session.execute(f'SELECT * FROM users WHERE username = \\'{username}\\'')",
        "from sqlalchemy import text\nsession.execute(text('SELECT * FROM users WHERE username = :username'), {'username': username})",
        {
            "vuln_type": "SQL Injection",
            "framework": "FastAPI",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "language": "Python"
        }
    ),
    
    # ============ XSS Patterns ============
    # Express
    (
        "res.send('<html><body>Hello ' + req.query.name + '</body></html>')",
        "const escapeHtml = require('escape-html');\nres.send('<html><body>Hello ' + escapeHtml(req.query.name) + '</body></html>')",
        {
            "vuln_type": "Cross-Site Scripting",
            "framework": "Express",
            "severity": "high",
            "cwe": "CWE-79",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript"
        }
    ),
    # Vanilla JS
    (
        "document.getElementById('output').innerHTML = userInput;",
        "document.getElementById('output').textContent = userInput;",
        {
            "vuln_type": "Cross-Site Scripting",
            "framework": "Vanilla JS",
            "severity": "high",
            "cwe": "CWE-79",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript"
        }
    ),
    # React
    (
        "<div dangerouslySetInnerHTML={{__html: props.userContent}} />",
        "import DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(props.userContent)}} />",
        {
            "vuln_type": "Cross-Site Scripting",
            "framework": "React",
            "severity": "high",
            "cwe": "CWE-79",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript"
        }
    ),
    # Django
    (
        "from django.utils.safestring import mark_safe\nreturn HttpResponse(mark_safe(f'Hello {request.GET.get(\"name\")}'))",
        "from django.utils.html import escape\nreturn HttpResponse(f'Hello {escape(request.GET.get(\"name\"))}')",
        {
            "vuln_type": "Cross-Site Scripting",
            "framework": "Django",
            "severity": "high",
            "cwe": "CWE-79",
            "owasp": "A03:2021-Injection",
            "language": "Python"
        }
    ),
    # Flask
    (
        'return render_template_string(f"<h1>Hello {name}</h1>")',
        "from markupsafe import escape\nreturn render_template_string(f'<h1>Hello {escape(name)}</h1>')",
        {
            "vuln_type": "Cross-Site Scripting",
            "framework": "Flask",
            "severity": "high",
            "cwe": "CWE-79",
            "owasp": "A03:2021-Injection",
            "language": "Python"
        }
    ),
    
    # ============ Path Traversal Patterns ============
    # Express
    (
        "const fs = require('fs');\nfs.readFile(__dirname + '/public/' + req.query.file, 'utf8', (err, data) => { res.send(data); });",
        "const fs = require('fs');\nconst path = require('path');\nconst safePath = path.join(__dirname, 'public', path.basename(req.query.file));\nif (!safePath.startsWith(path.join(__dirname, 'public'))) throw new Error('Invalid path');\nfs.readFile(safePath, 'utf8', (err, data) => { res.send(data); });",
        {
            "vuln_type": "Path Traversal",
            "framework": "Express",
            "severity": "high",
            "cwe": "CWE-22",
            "owasp": "A01:2021-Broken Access Control",
            "language": "JavaScript"
        }
    ),
    # FastAPI
    (
        'with open(f"/var/data/{filename}", "r") as f:\n    return f.read()',
        "import os\nfilename = os.path.basename(filename)\nsafe_path = os.path.join('/var/data', filename)\nif not os.path.realpath(safe_path).startswith('/var/data'):\n    raise ValueError('Invalid path')\nwith open(safe_path, 'r') as f:\n    return f.read()",
        {
            "vuln_type": "Path Traversal",
            "framework": "FastAPI",
            "severity": "high",
            "cwe": "CWE-22",
            "owasp": "A01:2021-Broken Access Control",
            "language": "Python"
        }
    ),
    
    # ============ Command Injection Patterns ============
    # Node.js
    (
        "const { exec } = require('child_process');\nexec(`ping -c 4 ${req.body.host}`)",
        "const { execFile } = require('child_process');\nexecFile('ping', ['-c', '4', req.body.host])",
        {
            "vuln_type": "Command Injection",
            "framework": "Node.js",
            "severity": "critical",
            "cwe": "CWE-78",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript"
        }
    ),
    # Python
    (
        'os.system("ping -c 4 " + host)',
        "import subprocess\nsubprocess.run(['ping', '-c', '4', host], check=True)",
        {
            "vuln_type": "Command Injection",
            "framework": "Generic",
            "severity": "critical",
            "cwe": "CWE-78",
            "owasp": "A03:2021-Injection",
            "language": "Python"
        }
    ),
    
    # ============ Insecure Deserialization Patterns ============
    # Node.js
    (
        "const userData = eval(req.cookies.session);",
        "const userData = JSON.parse(req.cookies.session);",
        {
            "vuln_type": "Insecure Deserialization",
            "framework": "Express",
            "severity": "critical",
            "cwe": "CWE-502",
            "owasp": "A08:2021-Software and Data Integrity Failures",
            "language": "JavaScript"
        }
    ),
    # Python
    (
        "user_data = pickle.loads(request.get_data())",
        "import json\nuser_data = json.loads(request.get_data())",
        {
            "vuln_type": "Insecure Deserialization",
            "framework": "Flask",
            "severity": "critical",
            "cwe": "CWE-502",
            "owasp": "A08:2021-Software and Data Integrity Failures",
            "language": "Python"
        }
    ),
    (
        "import yaml\ndata = yaml.load(request.data)",
        "import yaml\ndata = yaml.safe_load(request.data)",
        {
            "vuln_type": "Insecure Deserialization",
            "framework": "Flask",
            "severity": "critical",
            "cwe": "CWE-502",
            "owasp": "A08:2021-Software and Data Integrity Failures",
            "language": "Python"
        }
    ),
    
    # ============ Broken Authentication Patterns ============
    # JWT
    (
        'const token = jwt.sign({userId: user.id}, "hardcoded-secret");',
        "const token = jwt.sign({userId: user.id}, process.env.JWT_SECRET);",
        {
            "vuln_type": "Broken Authentication",
            "framework": "Express",
            "severity": "high",
            "cwe": "CWE-798",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "language": "JavaScript"
        }
    ),
    (
        "const decoded = jwt.decode(token, {complete: true});",
        "const decoded = jwt.verify(token, process.env.JWT_SECRET);",
        {
            "vuln_type": "Broken Authentication",
            "framework": "Node.js",
            "severity": "critical",
            "cwe": "CWE-347",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "language": "JavaScript"
        }
    ),
    # Password Storage
    (
        "if (password == user.password):\n    login_user(user)",
        "import bcrypt\nif bcrypt.checkpw(password.encode(), user.password_hash):\n    login_user(user)",
        {
            "vuln_type": "Broken Authentication",
            "framework": "Generic",
            "severity": "critical",
            "cwe": "CWE-256",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "language": "Python"
        }
    ),
    
    # ============ SSRF Patterns ============
    # Express
    (
        "const response = await axios.get(req.query.url);",
        "const allowedHosts = ['api.example.com', 'trusted.com'];\nconst url = new URL(req.query.url);\nif (!allowedHosts.includes(url.hostname)) throw new Error('Invalid host');\nconst response = await axios.get(url.toString());",
        {
            "vuln_type": "Server-Side Request Forgery",
            "framework": "Express",
            "severity": "high",
            "cwe": "CWE-918",
            "owasp": "A10:2021-Server-Side Request Forgery",
            "language": "JavaScript"
        }
    ),
    # Python
    (
        "response = requests.get(url)",
        "from urllib.parse import urlparse\nallowed_hosts = ['api.example.com', 'trusted.com']\nparsed = urlparse(url)\nif parsed.hostname not in allowed_hosts:\n    raise ValueError('Invalid host')\nresponse = requests.get(url)",
        {
            "vuln_type": "Server-Side Request Forgery",
            "framework": "Generic",
            "severity": "high",
            "cwe": "CWE-918",
            "owasp": "A10:2021-Server-Side Request Forgery",
            "language": "Python"
        }
    ),
    
    # ============ Weak Cryptography Patterns ============
    # MD5 for passwords
    (
        'const hash = crypto.createHash("md5").update(password).digest("hex");',
        "const bcrypt = require('bcrypt');\nconst hash = await bcrypt.hash(password, 10);",
        {
            "vuln_type": "Weak Cryptography",
            "framework": "Node.js",
            "severity": "high",
            "cwe": "CWE-327",
            "owasp": "A02:2021-Cryptographic Failures",
            "language": "JavaScript"
        }
    ),
    (
        "password_hash = hashlib.md5(password.encode()).hexdigest()",
        "import bcrypt\npassword_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
        {
            "vuln_type": "Weak Cryptography",
            "framework": "Generic",
            "severity": "high",
            "cwe": "CWE-327",
            "owasp": "A02:2021-Cryptographic Failures",
            "language": "Python"
        }
    ),
    
    # ============ Sensitive Data Exposure Patterns ============
    (
        'console.log("User login:", username, password);',
        'console.log("User login:", username);',
        {
            "vuln_type": "Sensitive Data Exposure",
            "framework": "Generic",
            "severity": "medium",
            "cwe": "CWE-532",
            "owasp": "A02:2021-Cryptographic Failures",
            "language": "JavaScript"
        }
    ),
    (
        'return JsonResponse({"user": user, "password": user.password})',
        'user_data = {k: v for k, v in user.__dict__.items() if k != "password"}\nreturn JsonResponse({"user": user_data})',
        {
            "vuln_type": "Sensitive Data Exposure",
            "framework": "Django",
            "severity": "high",
            "cwe": "CWE-200",
            "owasp": "A02:2021-Cryptographic Failures",
            "language": "Python"
        }
    ),
    
    # ============ CORS Misconfiguration Patterns ============
    (
        'res.setHeader("Access-Control-Allow-Origin", "*");',
        'const allowedOrigins = ["https://myapp.com"];\nif (allowedOrigins.includes(req.headers.origin)) {\n  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);\n}',
        {
            "vuln_type": "CORS Misconfiguration",
            "framework": "Express",
            "severity": "medium",
            "cwe": "CWE-942",
            "owasp": "A05:2021-Security Misconfiguration",
            "language": "JavaScript"
        }
    ),
    (
        'response["Access-Control-Allow-Origin"] = request.headers.get("Origin")',
        'allowed_origins = ["https://myapp.com"]\norigin = request.headers.get("Origin")\nif origin in allowed_origins:\n    response["Access-Control-Allow-Origin"] = origin',
        {
            "vuln_type": "CORS Misconfiguration",
            "framework": "Django",
            "severity": "medium",
            "cwe": "CWE-942",
            "owasp": "A05:2021-Security Misconfiguration",
            "language": "Python"
        }
    ),
    
    # ============ NoSQL Injection Patterns ============
    (
        "User.findOne({username: req.body.username, password: req.body.password})",
        "User.findOne({\n  username: {$eq: req.body.username},\n  password: {$eq: req.body.password}\n})",
        {
            "vuln_type": "NoSQL Injection",
            "framework": "MongoDB",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript"
        }
    ),
    
    # ============ XXE Patterns ============
    (
        "const doc = libxmljs.parseXml(userXml);",
        "const doc = libxmljs.parseXml(userXml, {noent: false, dtdload: false});",
        {
            "vuln_type": "XML External Entity",
            "framework": "Node.js",
            "severity": "high",
            "cwe": "CWE-611",
            "owasp": "A05:2021-Security Misconfiguration",
            "language": "JavaScript"
        }
    ),
    
    # ============ Unrestricted File Upload Patterns ============
    (
        "file.mv(`./uploads/${file.name}`, (err) => {});",
        "const allowedTypes = ['.jpg', '.png', '.pdf'];\nconst ext = path.extname(file.name).toLowerCase();\nif (!allowedTypes.includes(ext)) throw new Error('Invalid file type');\nfile.mv(`./uploads/${file.name}`, (err) => {});",
        {
            "vuln_type": "Unrestricted File Upload",
            "framework": "Express",
            "severity": "high",
            "cwe": "CWE-434",
            "owasp": "A04:2021-Insecure Design",
            "language": "JavaScript"
        }
    ),
    
    # ============ LDAP Injection Patterns ============
    (
        "const filter = `(uid=${username})`;",
        "const sanitized = username.replace(/[^a-zA-Z0-9]/g, '');\nconst filter = `(uid=${sanitized})`;",
        {
            "vuln_type": "LDAP Injection",
            "framework": "Generic",
            "severity": "high",
            "cwe": "CWE-90",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript"
        }
    ),
    
    # ============ Mass Assignment Patterns ============
    (
        "user.update(req.body)",
        "const allowedFields = ['name', 'email'];\nconst updates = {};\nallowedFields.forEach(f => {\n  if (req.body[f]) updates[f] = req.body[f];\n});\nuser.update(updates);",
        {
            "vuln_type": "Mass Assignment",
            "framework": "Express",
            "severity": "high",
            "cwe": "CWE-915",
            "owasp": "A04:2021-Insecure Design",
            "language": "JavaScript"
        }
    ),
    
    # ============ SSTI Patterns ============
    (
        "Template(request.args.get('template')).render()",
        "from markupsafe import escape\ntemplate_str = 'Hello {{ name }}'\nTemplate(template_str).render(name=escape(request.args.get('name')))",
        {
            "vuln_type": "Server-Side Template Injection",
            "framework": "Jinja2",
            "severity": "critical",
            "cwe": "CWE-94",
            "owasp": "A03:2021-Injection",
            "language": "Python"
        }
    ),
    
    # ============ Race Condition Patterns ============
    (
        "if (user.balance >= amount) {\n  // delay...\n  user.balance -= amount;\n}",
        "await db.transaction(async (trx) => {\n  const user = await trx('users').where({id}).forUpdate().first();\n  if (user.balance >= amount) {\n    await trx('users').where({id}).decrement('balance', amount);\n  }\n});",
        {
            "vuln_type": "Race Condition",
            "framework": "Generic",
            "severity": "high",
            "cwe": "CWE-362",
            "owasp": "A04:2021-Insecure Design",
            "language": "JavaScript"
        }
    ),
]


def seed_upstash():
    """Seed Upstash Vector with vulnerable and safe code patterns."""
    
    print("🚀 Connecting to Upstash Vector...")
    print(f"   URL: {settings.UPSTASH_SEARCH_REST_URL[:50]}...")
    
    index = Index(
        url=settings.UPSTASH_SEARCH_REST_URL, 
        token=settings.UPSTASH_SEARCH_REST_TOKEN
    )
    
    print("✅ Connected to Upstash Vector")
    
    # Prepare records
    records = []
    pattern_count = {"vulnerable": 0, "safe": 0}
    
    print(f"\n📦 Processing {len(SEED_PATTERNS)} pattern pairs...")
    
    for vuln_code, safe_code, base_meta in SEED_PATTERNS:
        v_id = str(uuid.uuid4())
        s_id = str(uuid.uuid4())
        
        # Vulnerable pattern
        vuln_meta = base_meta.copy()
        vuln_meta["type"] = "vulnerable"
        vuln_meta["text"] = vuln_code
        vuln_meta["pair_id"] = v_id  # Link to safe version
        
        records.append({
            "id": v_id,
            "data": vuln_code,
            "metadata": vuln_meta
        })
        pattern_count["vulnerable"] += 1
        
        # Safe pattern
        safe_meta = base_meta.copy()
        safe_meta["type"] = "safe"
        safe_meta["text"] = safe_code
        safe_meta["fix_for"] = v_id  # Link back to vulnerable version
        safe_meta["pair_id"] = v_id
        
        records.append({
            "id": s_id,
            "data": safe_code,
            "metadata": safe_meta
        })
        pattern_count["safe"] += 1
    
    print(f"✅ Created {pattern_count['vulnerable']} vulnerable + {pattern_count['safe']} safe patterns")
    
    # Generate embeddings
    print("\n🤖 Loading embedding model (fastembed)...")
    try:
        from fastembed import TextEmbedding
        model = TextEmbedding()
        print("✅ Model loaded")
    except ImportError:
        print("❌ fastembed not installed. Run: pip install fastembed")
        return
    
    print("🔢 Generating embeddings...")
    texts = [record["metadata"]["text"] for record in records]
    embeddings = list(model.embed(texts))
    
    for i, record in enumerate(records):
        record["vector"] = embeddings[i].tolist()
    
    print(f"✅ Generated {len(embeddings)} embeddings")
    
    # Upsert to Upstash
    print(f"\n📤 Upserting {len(records)} patterns to Upstash Vector...")
    try:
        # Batch upsert (Upstash handles batching internally)
        index.upsert(vectors=records)
        print("✅ Upload complete!")
    except Exception as e:
        print(f"❌ Failed to upsert. Error: {e}")
        return
    
    # Verify
    print("\n🔍 Verifying upload...")
    try:
        # Test query
        test_query = 'db.execute("SELECT * FROM users WHERE email = " + email)'
        results = index.query(
            data=test_query,
            top_k=3,
            include_metadata=True
        )
        
        print(f"\n📊 Test query results (SQL injection pattern):")
        for i, result in enumerate(results):
            metadata = result.get("metadata", {})
            print(f"\n{i+1}. {metadata.get('vuln_type')} ({metadata.get('framework')})")
            print(f"   Type: {metadata.get('type')}")
            print(f"   Score: {result.get('score', 0):.4f}")
            print(f"   Code: {metadata.get('text', '')[:80]}...")
    except Exception as e:
        print(f"⚠️  Verification query failed: {e}")
    
    print("\n✨ Seeding complete!")
    print(f"\n📈 Summary:")
    print(f"   - Vulnerable patterns: {pattern_count['vulnerable']}")
    print(f"   - Safe patterns: {pattern_count['safe']}")
    print(f"   - Total entries: {sum(pattern_count.values())}")
    print(f"   - OWASP categories covered: SQLi, XSS, Path Traversal, Command Injection,")
    print(f"     SSRF, Insecure Deserialization, Broken Auth, Weak Crypto, and more")
    print("\n💡 Usage:")
    print("   - Code Analyzer: Query type='vulnerable' to detect known-bad patterns")
    print("   - Fix Generator: Query type='safe' with fix_for=<vuln_id> for fixes")


if __name__ == "__main__":
    seed_upstash()
