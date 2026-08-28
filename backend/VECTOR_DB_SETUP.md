# Vector Database & PostgreSQL Setup

## Overview

AuthTrack uses two database systems:
1. **Upstash Vector** - For semantic search of vulnerable/safe code patterns
2. **Neon PostgreSQL** - For relational data (scans, findings, fixes)

---

## 1. Upstash Vector Database

### Purpose
Store and query code patterns using semantic similarity:
- **Vulnerable patterns** - Known bad code from OWASP, CVEs, vulnerable apps
- **Safe patterns** - Fixed/secure versions linked to vulnerabilities

### Collections Structure
Single index with two pattern types:

#### Vulnerable Patterns
```json
{
  "id": "uuid",
  "data": "db.query('SELECT * FROM users WHERE id = ' + req.params.id)",
  "metadata": {
    "type": "vulnerable",
    "vuln_type": "SQL Injection",
    "framework": "Express",
    "severity": "critical",
    "cwe": "CWE-89",
    "owasp": "A03:2021-Injection",
    "language": "JavaScript",
    "pair_id": "uuid"
  }
}
```

#### Safe Patterns
```json
{
  "id": "uuid",
  "data": "db.query('SELECT * FROM users WHERE id = ?', [req.params.id])",
  "metadata": {
    "type": "safe",
    "vuln_type": "SQL Injection",
    "framework": "Express",
    "severity": "safe",
    "cwe": "CWE-89",
    "owasp": "A03:2021-Injection",
    "language": "JavaScript",
    "fix_for": "vuln_uuid",
    "pair_id": "vuln_uuid",
    "fix_description": "Use parameterized queries"
  }
}
```

### Coverage
- **~50 pattern pairs** across top OWASP categories:
  - SQL Injection (Express, Django, FastAPI)
  - Cross-Site Scripting (React, Vue, Django, Flask)
  - Path Traversal
  - Command Injection
  - SSRF
  - Insecure Deserialization
  - Broken Authentication (JWT, passwords)
  - Weak Cryptography
  - CORS Misconfiguration
  - NoSQL Injection
  - XXE
  - Unrestricted File Upload
  - LDAP Injection
  - Mass Assignment
  - SSTI
  - Race Conditions

### Setup Instructions

1. **Create Upstash Vector Index**
   - Go to https://console.upstash.com/vector
   - Create new index with these settings:
     - **Dimension**: 384 (fastembed default)
     - **Metric**: cosine
     - **Region**: Choose closest to you

2. **Get Credentials**
   - Copy REST URL and Token from console
   - Add to `.env`:
   ```env
   UPSTASH_SEARCH_REST_URL=https://xxxxx.upstash.io
   UPSTASH_SEARCH_REST_TOKEN=xxxxx
   ```

3. **Install Dependencies**
   ```bash
   pip install upstash-vector fastembed
   ```

4. **Seed the Database**
   ```bash
   python scripts/seed_upstash.py
   ```

### Usage in Code

#### Query Vulnerable Patterns (Code Analyzer)
```python
from upstash_vector import Index
from app.core.config import settings

index = Index(
    url=settings.UPSTASH_SEARCH_REST_URL,
    token=settings.UPSTASH_SEARCH_REST_TOKEN
)

# Find similar vulnerable patterns
results = index.query(
    data="db.execute('SELECT * FROM users WHERE email = ' + email)",
    top_k=5,
    include_metadata=True,
    filter="type = 'vulnerable'"
)

for result in results:
    metadata = result["metadata"]
    print(f"{metadata['vuln_type']} - {metadata['framework']}")
    print(f"Confidence: {result['score']:.2f}")
```

#### Query Safe Patterns (Fix Generator)
```python
# Given a vulnerable pattern ID, get the fix
results = index.query(
    data="",  # Not used when filtering by metadata
    top_k=1,
    include_metadata=True,
    filter=f"fix_for = '{vuln_id}'"
)

safe_code = results[0]["metadata"]["text"]
```

---

## 2. Neon PostgreSQL Database

### Purpose
Store structured scan data, findings, and generated fixes.

### Schema

#### `scans` table
Tracks each scan run.

```sql
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    target VARCHAR NOT NULL,           -- URL or repo path
    scan_type VARCHAR NOT NULL,        -- "url", "cli", "full"
    status VARCHAR DEFAULT 'running',  -- "running", "completed", "failed"
    started_at TIMESTAMP DEFAULT NOW(),
    finished_at TIMESTAMP
);
```

#### `flow_runs` table
Tracks individual agent flows within a scan.

```sql
CREATE TABLE flow_runs (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    flow_name VARCHAR NOT NULL,        -- "recon", "headers", "static_analysis", etc.
    status VARCHAR DEFAULT 'running',  -- "running", "completed", "failed"
    duration_ms INTEGER
);
```

#### `findings` table
Stores discovered vulnerabilities.

```sql
CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    flow_run_id INTEGER REFERENCES flow_runs(id),
    issue_title VARCHAR NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR NOT NULL,         -- "low", "medium", "high", "critical", "info"
    category VARCHAR,                  -- OWASP category (e.g., "A03:2021-Injection")
    endpoint_or_file VARCHAR NOT NULL, -- URL endpoint or file path
    evidence TEXT,                     -- Raw response, code snippet, etc.
    is_false_positive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### `fixes` table
Stores AI-generated fixes for findings.

```sql
CREATE TABLE fixes (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id),
    diff_text TEXT NOT NULL,           -- Git-style diff
    explanation TEXT,                  -- Human-readable explanation
    applied BOOLEAN DEFAULT FALSE      -- Track if fix was applied
);
```

### Relationships
```
scans (1) ─→ (many) flow_runs
scans (1) ─→ (many) findings
flow_runs (1) ─→ (many) findings
findings (1) ─→ (many) fixes
```

### Setup Instructions

1. **Create Neon Project**
   - Go to https://console.neon.tech
   - Create new project
   - Get connection string

2. **Update .env**
   ```env
   POSTGRES_SERVER=ep-xxxxx.us-east-2.aws.neon.tech
   POSTGRES_USER=your_user
   POSTGRES_PASSWORD=your_password
   POSTGRES_DB=authtrack
   POSTGRES_PORT=5432
   DB_URL=postgresql://user:pass@host:5432/authtrack
   ```

3. **Initialize Database**
   ```bash
   python scripts/init_db.py
   ```

### Usage Examples

#### Create a Scan
```python
from app.db.session import SessionLocal
from app.db.models import Scan, FlowRun, Finding

db = SessionLocal()

# Create scan
scan = Scan(
    target="https://example.com",
    scan_type="url",
    status="running"
)
db.add(scan)
db.commit()

# Create flow run
flow = FlowRun(
    scan_id=scan.id,
    flow_name="recon",
    status="running"
)
db.add(flow)
db.commit()
```

#### Add Finding
```python
finding = Finding(
    scan_id=scan.id,
    flow_run_id=flow.id,
    issue_title="SQL Injection in /api/users",
    description="Unparameterized SQL query detected",
    severity="critical",
    category="A03:2021-Injection",
    endpoint_or_file="/api/users",
    evidence='db.query("SELECT * FROM users WHERE id = " + userId)'
)
db.add(finding)
db.commit()
```

#### Generate Fix
```python
fix = Fix(
    finding_id=finding.id,
    diff_text="""
-db.query("SELECT * FROM users WHERE id = " + userId)
+db.query("SELECT * FROM users WHERE id = ?", [userId])
    """,
    explanation="Use parameterized query to prevent SQL injection"
)
db.add(fix)
db.commit()
```

#### Query Results
```python
# Get all findings for a scan
findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()

# Get high/critical findings only
critical = db.query(Finding).filter(
    Finding.scan_id == scan.id,
    Finding.severity.in_(["high", "critical"])
).all()

# Calculate false positive rate
total = db.query(Finding).filter(Finding.scan_id == scan.id).count()
false_positives = db.query(Finding).filter(
    Finding.scan_id == scan.id,
    Finding.is_false_positive == True
).count()
fp_rate = false_positives / total if total > 0 else 0
```

---

## Integration Flow

### 1. Code Analysis Pipeline
```
1. Static Analyzer extracts code snippet
2. Embed snippet using fastembed
3. Query Upstash Vector for similar vulnerable patterns
4. If match found (score > threshold):
   → Evidence for triage LLM
   → Create Finding in PostgreSQL
```

### 2. Fix Generation Pipeline
```
1. Get Finding from PostgreSQL
2. Extract vulnerable code from evidence field
3. Query Upstash Vector for safe pattern (filter: fix_for = <pattern_id>)
4. LLM adapts safe pattern to context
5. Save Fix to PostgreSQL
6. Link Fix to Finding via finding_id
```

### 3. Dashboard/Report Generation
```sql
-- Get scan summary with flow status
SELECT 
    s.id,
    s.target,
    s.status,
    COUNT(DISTINCT fr.id) as flow_count,
    COUNT(DISTINCT f.id) as finding_count,
    COUNT(DISTINCT fx.id) as fix_count
FROM scans s
LEFT JOIN flow_runs fr ON fr.scan_id = s.id
LEFT JOIN findings f ON f.scan_id = s.id
LEFT JOIN fixes fx ON fx.finding_id = f.id
WHERE s.id = ?
GROUP BY s.id;
```

---

## Performance Considerations

### Upstash Vector
- **Query latency**: ~50-200ms for similarity search
- **Batch inserts**: Use bulk upsert for seeding
- **Embedding model**: fastembed (384 dimensions, runs locally)

### Neon PostgreSQL
- **Connection pooling**: Use SQLAlchemy pool
- **Indexes**: Already on `scan_id`, `flow_run_id`, `severity`
- **Autoscaling**: Neon scales automatically

---

## Maintenance

### Adding New Patterns
1. Edit `scripts/seed_upstash.py`
2. Add (vulnerable, safe, metadata) tuple to `SEED_PATTERNS`
3. Re-run: `python scripts/seed_upstash.py`

### Updating Schema
1. Modify `app/db/models.py`
2. Re-run: `python scripts/init_db.py`
3. For production: Use Alembic migrations

### Monitoring
- Check Upstash console for query metrics
- Check Neon console for DB size and connections
- Log slow queries (>1s) for optimization
