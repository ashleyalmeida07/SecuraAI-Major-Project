# AuthTrack Database Setup Guide

Complete setup guide for Upstash Vector and Neon PostgreSQL integration.

---

## Quick Start

```bash
# 1. Check setup
python scripts/check_setup.py

# 2. Initialize PostgreSQL tables
python scripts/init_db.py

# 3. Seed Upstash Vector with patterns
python scripts/seed_upstash.py

# 4. Start backend
uvicorn app.main:app --reload
```

---

## Detailed Setup

### Prerequisites

1. **Python 3.10+** with uv or pip
2. **Upstash Vector account** - https://console.upstash.com/vector
3. **Neon PostgreSQL account** - https://console.neon.tech

### Step 1: Install Dependencies

```bash
# Install required packages
pip install upstash-vector fastembed sqlalchemy psycopg2-binary
```

Or if using uv:
```bash
uv pip install upstash-vector fastembed
```

### Step 2: Configure Upstash Vector

1. **Create Vector Index**
   - Go to https://console.upstash.com/vector
   - Click "Create Index"
   - Settings:
     - **Name**: `authtrack-patterns`
     - **Dimension**: `384` (fastembed default)
     - **Metric**: `cosine`
     - **Region**: Choose closest to your location

2. **Get Credentials**
   - Click on your newly created index
   - Copy "REST URL" and "REST Token"

3. **Update .env**
   ```env
   UPSTASH_SEARCH_REST_URL=https://xxxxx-xxxxx-xxxxx.upstash.io
   UPSTASH_SEARCH_REST_TOKEN=AxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxQ
   ```

### Step 3: Configure Neon PostgreSQL

1. **Create Project**
   - Go to https://console.neon.tech
   - Click "Create Project"
   - Choose region and name

2. **Get Connection String**
   - Click "Connection Details"
   - Copy connection parameters

3. **Update .env**
   ```env
   POSTGRES_SERVER=ep-cool-darkness-123456.us-east-2.aws.neon.tech
   POSTGRES_USER=your_username
   POSTGRES_PASSWORD=your_password
   POSTGRES_DB=authtrack
   POSTGRES_PORT=5432
   DB_URL=postgresql://user:pass@host:5432/authtrack
   ```

### Step 4: Verify Setup

```bash
python scripts/check_setup.py
```

Expected output:
```
============================================================
AuthTrack Database Setup Check
============================================================

🔍 Checking Python dependencies...
✅ upstash-vector
✅ fastembed
✅ sqlalchemy
✅ psycopg2

🔍 Checking Upstash Vector...
✅ URL configured: https://xxxxx...
✅ Token configured: Axxxxx...
✅ Connection successful!
   Dimension: 384
   Metric: cosine
   Vector count: 0

🔍 Checking Neon PostgreSQL...
✅ Server: ep-cool-darkness-123456.us-east-2.aws.neon.tech
✅ Database: authtrack
✅ User: your_username
✅ Connection successful!
⚠️  Missing tables: scans, flow_runs, findings, fixes, users
   Run: python scripts/init_db.py

============================================================
Summary
============================================================
Dependencies: ✅ OK
Upstash Vector: ✅ OK
Neon PostgreSQL: ✅ OK
```

### Step 5: Initialize PostgreSQL Tables

```bash
python scripts/init_db.py
```

This creates:
- `users` - User accounts
- `scans` - Scan runs
- `flow_runs` - Individual agent flows
- `findings` - Discovered vulnerabilities
- `fixes` - Generated fixes

### Step 6: Seed Upstash Vector

```bash
python scripts/seed_upstash.py
```

This uploads ~50 vulnerable/safe code pattern pairs covering:
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection
- SSRF
- Insecure Deserialization
- Broken Authentication
- Weak Cryptography
- And more...

Expected output:
```
🚀 Connecting to Upstash Vector...
✅ Connected to Upstash Vector

📦 Processing 40 pattern pairs...
✅ Created 40 vulnerable + 40 safe patterns

🤖 Loading embedding model (fastembed)...
✅ Model loaded
🔢 Generating embeddings...
✅ Generated 80 embeddings

📤 Upserting 80 patterns to Upstash Vector...
✅ Upload complete!

🔍 Verifying upload...

📊 Test query results (SQL injection pattern):

1. SQL Injection (Express)
   Type: vulnerable
   Score: 0.9234
   Code: db.query("SELECT * FROM users WHERE id = " + req.params.id)...

✨ Seeding complete!

📈 Summary:
   - Vulnerable patterns: 40
   - Safe patterns: 40
   - Total entries: 80
```

---

## Usage in Code

### Code Analyzer (Detect Vulnerabilities)

```python
from app.utils.pattern_matcher import PatternMatcher

matcher = PatternMatcher()

# Analyze suspicious code
code = 'db.query("SELECT * FROM users WHERE id = " + userId)'

matches = matcher.find_vulnerable_patterns(
    code_snippet=code,
    top_k=3,
    min_score=0.75
)

if matches:
    # Vulnerability detected!
    vuln = matches[0]
    print(f"Found {vuln['vuln_type']} (confidence: {vuln['score']:.0%})")
```

### Fix Generator (Generate Secure Code)

```python
from app.utils.pattern_matcher import PatternMatcher

matcher = PatternMatcher()

# Get safe pattern for a vulnerability
safe_pattern = matcher.find_safe_pattern(vuln_pattern_id)

if safe_pattern:
    print(f"Fix: {safe_pattern['code']}")
    print(f"Explanation: {safe_pattern['fix_description']}")
```

### Database Operations

```python
from app.db.session import SessionLocal
from app.db.models import Scan, Finding, Fix

db = SessionLocal()

# Create scan
scan = Scan(
    target="https://example.com",
    scan_type="url",
    status="running"
)
db.add(scan)
db.commit()

# Add finding
finding = Finding(
    scan_id=scan.id,
    issue_title="SQL Injection detected",
    severity="critical",
    category="A03:2021-Injection",
    endpoint_or_file="/api/users",
    evidence=code
)
db.add(finding)
db.commit()

# Generate fix
fix = Fix(
    finding_id=finding.id,
    diff_text="- vulnerable code\n+ safe code",
    explanation="Use parameterized queries"
)
db.add(fix)
db.commit()
```

---

## Testing the Setup

### Test Upstash Vector Query

```python
from upstash_vector import Index
from app.core.config import settings

index = Index(
    url=settings.UPSTASH_SEARCH_REST_URL,
    token=settings.UPSTASH_SEARCH_REST_TOKEN
)

# Search for SQL injection patterns
results = index.query(
    data='db.execute("SELECT * FROM users WHERE id = " + id)',
    top_k=3,
    include_metadata=True,
    filter="type = 'vulnerable'"
)

for r in results:
    print(f"{r['metadata']['vuln_type']} - Score: {r['score']:.2f}")
```

### Test PostgreSQL Connection

```python
from app.db.session import SessionLocal
from app.db.models import Scan

db = SessionLocal()

# Create test scan
scan = Scan(target="test", scan_type="cli", status="completed")
db.add(scan)
db.commit()
print(f"Created scan with ID: {scan.id}")

# Query it back
found = db.query(Scan).filter(Scan.id == scan.id).first()
print(f"Found scan: {found.target}")

# Clean up
db.delete(found)
db.commit()
```

---

## Troubleshooting

### Upstash Connection Issues

**Error: "Invalid credentials"**
- Verify URL and token in `.env`
- Check Upstash console for correct values
- Ensure no extra spaces in `.env` file

**Error: "Dimension mismatch"**
- Upstash index must be created with dimension=384
- This matches fastembed's default embedding size

### PostgreSQL Connection Issues

**Error: "Connection refused"**
- Check if Neon project is active (not suspended)
- Verify connection string format
- Check firewall settings

**Error: "Table does not exist"**
- Run `python scripts/init_db.py` to create tables
- Verify migrations completed successfully

### Seeding Issues

**Error: "ModuleNotFoundError: No module named 'fastembed'"**
```bash
pip install fastembed
```

**Slow embedding generation**
- First run downloads fastembed model (~30MB)
- Subsequent runs are much faster
- Expected: ~2-3 seconds for 80 patterns

---

## Performance Metrics

### Expected Latencies
- **Upstash query**: 50-200ms
- **PostgreSQL query**: 10-50ms (Neon)
- **Embedding generation**: 100-300ms for a single snippet

### Capacity
- **Upstash free tier**: 10,000 vectors, 10,000 queries/day
- **Neon free tier**: 512 MB storage, 100 hours compute/month
- **Production**: Upgrade both for unlimited usage

---

## Next Steps

1. ✅ Complete setup
2. ✅ Seed databases
3. 🔄 Integrate with agents:
   - Static Analysis agent → PatternMatcher
   - Fix Generator agent → PatternMatcher + Fix model
4. 🔄 Build dashboard:
   - Query findings by scan_id
   - Display false positive rate
   - Show fix generation stats
5. 🔄 Add more patterns:
   - Expand `seed_upstash.py` with more examples
   - Add framework-specific patterns (Next.js, Laravel, etc.)

---

## Resources

- **Upstash Docs**: https://upstash.com/docs/vector/overall/getstarted
- **Neon Docs**: https://neon.tech/docs/introduction
- **FastEmbed**: https://github.com/qdrant/fastembed
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **CWE Database**: https://cwe.mitre.org/

---

## Support

If you encounter issues:
1. Run `python scripts/check_setup.py` for diagnostics
2. Check `.env` file for typos
3. Verify Upstash/Neon console shows active resources
4. See `VECTOR_DB_SETUP.md` for detailed architecture
