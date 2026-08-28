# Database Architecture Summary

## Overview

AuthTrack uses a hybrid database architecture:
1. **Upstash Vector** - Semantic search for code patterns (RAG)
2. **Neon PostgreSQL** - Relational data for scans, findings, and fixes

---

## 1. Upstash Vector Database

### Purpose
Store and retrieve vulnerable/safe code patterns using semantic similarity for:
- **Detection**: Find known vulnerabilities in analyzed code
- **Remediation**: Retrieve secure alternatives for confirmed issues

### Data Model

Single index with two pattern types stored in metadata:

```json
// Vulnerable Pattern
{
  "id": "uuid",
  "vector": [0.123, 0.456, ...],  // 384-dim embedding
  "metadata": {
    "type": "vulnerable",
    "text": "db.query('SELECT * FROM users WHERE id = ' + req.params.id)",
    "vuln_type": "SQL Injection",
    "framework": "Express",
    "language": "JavaScript",
    "severity": "critical",
    "cwe": "CWE-89",
    "owasp": "A03:2021-Injection",
    "pair_id": "vuln-uuid"
  }
}

// Safe Pattern (linked to vulnerable)
{
  "id": "uuid",
  "vector": [0.789, 0.234, ...],
  "metadata": {
    "type": "safe",
    "text": "db.query('SELECT * FROM users WHERE id = ?', [req.params.id])",
    "vuln_type": "SQL Injection",
    "framework": "Express",
    "language": "JavaScript",
    "severity": "safe",
    "cwe": "CWE-89",
    "owasp": "A03:2021-Injection",
    "fix_for": "vuln-uuid",
    "fix_description": "Use parameterized queries to prevent SQL injection",
    "pair_id": "vuln-uuid"
  }
}
```

### Query Patterns

**1. Detect Vulnerabilities (Code Analyzer)**
```python
results = index.query(
    data=suspicious_code,
    top_k=5,
    include_metadata=True,
    filter="type = 'vulnerable'"
)
# Returns: Most similar known vulnerabilities
```

**2. Get Fix for Vulnerability (Fix Generator)**
```python
results = index.query(
    data="",
    top_k=1,
    include_metadata=True,
    filter=f"fix_for = '{vuln_pattern_id}'"
)
# Returns: Linked safe pattern
```

**3. Search Safe Patterns by Type (Fallback)**
```python
results = index.query(
    data=vulnerable_code,
    top_k=3,
    include_metadata=True,
    filter="type = 'safe' AND vuln_type = 'SQL Injection'"
)
# Returns: Similar safe patterns
```

### Coverage (50 Pattern Pairs)

| Category | Frameworks | Count |
|----------|-----------|-------|
| SQL Injection | Express, Django, FastAPI | 5 pairs |
| XSS | React, Vue, Django, Flask, Vanilla JS | 5 pairs |
| Path Traversal | Express, FastAPI | 2 pairs |
| Command Injection | Node.js, Python | 2 pairs |
| SSRF | Express, FastAPI, Generic | 2 pairs |
| Insecure Deserialization | Node.js, Flask | 3 pairs |
| Broken Authentication | Express, Generic | 3 pairs |
| Weak Cryptography | Node.js, Python | 2 pairs |
| Sensitive Data Exposure | Generic, Django | 2 pairs |
| CORS Misconfiguration | Express, Django | 2 pairs |
| NoSQL Injection | MongoDB | 1 pair |
| XXE | Node.js | 1 pair |
| Unrestricted File Upload | Express | 1 pair |
| LDAP Injection | Generic | 1 pair |
| Mass Assignment | Express | 1 pair |
| SSTI | Jinja2 | 1 pair |
| Race Conditions | Generic | 1 pair |

### Technology Stack
- **Embedding Model**: fastembed (384 dimensions, local execution)
- **Similarity Metric**: Cosine similarity
- **Client**: upstash-vector Python SDK

---

## 2. Neon PostgreSQL Database

### Purpose
Store structured data for:
- Scan orchestration and tracking
- Vulnerability findings
- Generated fixes
- False positive tracking
- Reporting and metrics

### Schema

```sql
┌─────────┐
│  scans  │
└────┬────┘
     │
     ├─────────┐
     │         │
     ▼         ▼
┌──────────┐ ┌──────────┐
│flow_runs │ │ findings │
└────┬─────┘ └────┬─────┘
     │            │
     └────┬───────┘
          │
          ▼
     ┌────────┐
     │ fixes  │
     └────────┘
```

#### `scans` - Scan Runs
```sql
id              SERIAL PRIMARY KEY
target          VARCHAR NOT NULL        -- URL or repo path
scan_type       VARCHAR NOT NULL        -- "url", "cli", "full"
status          VARCHAR DEFAULT 'running'  -- "running", "completed", "failed"
started_at      TIMESTAMP DEFAULT NOW()
finished_at     TIMESTAMP NULL
```

**Example**:
```sql
INSERT INTO scans (target, scan_type) 
VALUES ('https://example.com', 'url');
```

#### `flow_runs` - Agent Flow Executions
```sql
id              SERIAL PRIMARY KEY
scan_id         INTEGER REFERENCES scans(id)
flow_name       VARCHAR NOT NULL        -- "recon", "headers", "static_analysis"
status          VARCHAR DEFAULT 'running'
duration_ms     INTEGER NULL
```

**Example**:
```sql
INSERT INTO flow_runs (scan_id, flow_name) 
VALUES (1, 'static_analysis');
```

#### `findings` - Discovered Vulnerabilities
```sql
id                  SERIAL PRIMARY KEY
scan_id             INTEGER REFERENCES scans(id)
flow_run_id         INTEGER REFERENCES flow_runs(id)
issue_title         VARCHAR NOT NULL
description         TEXT NOT NULL
severity            VARCHAR NOT NULL    -- "low", "medium", "high", "critical", "info"
category            VARCHAR NULL        -- OWASP category
endpoint_or_file    VARCHAR NOT NULL    -- URL endpoint or file path
evidence            TEXT NULL           -- Raw response, code snippet
is_false_positive   BOOLEAN DEFAULT FALSE
created_at          TIMESTAMP DEFAULT NOW()
```

**Example**:
```sql
INSERT INTO findings (
    scan_id, 
    flow_run_id, 
    issue_title, 
    description, 
    severity,
    category,
    endpoint_or_file,
    evidence
) VALUES (
    1,
    1,
    'SQL Injection in /api/users',
    'User input directly concatenated into SQL query',
    'critical',
    'A03:2021-Injection',
    '/api/users?id=1',
    'db.query("SELECT * FROM users WHERE id = " + userId)'
);
```

#### `fixes` - Generated Fixes
```sql
id              SERIAL PRIMARY KEY
finding_id      INTEGER REFERENCES findings(id)
diff_text       TEXT NOT NULL           -- Git-style diff
explanation     TEXT NULL               -- Human-readable explanation
applied         BOOLEAN DEFAULT FALSE   -- Track if fix was applied
```

**Example**:
```sql
INSERT INTO fixes (finding_id, diff_text, explanation) 
VALUES (
    1,
    '-db.query("SELECT * FROM users WHERE id = " + userId)
+db.query("SELECT * FROM users WHERE id = ?", [userId])',
    'Use parameterized query to prevent SQL injection'
);
```

### Key Queries

**1. Get Scan Summary**
```sql
SELECT 
    s.id,
    s.target,
    s.status,
    COUNT(DISTINCT fr.id) as flow_count,
    COUNT(DISTINCT f.id) as finding_count,
    COUNT(CASE WHEN f.severity IN ('high', 'critical') THEN 1 END) as critical_count,
    COUNT(DISTINCT fx.id) as fix_count
FROM scans s
LEFT JOIN flow_runs fr ON fr.scan_id = s.id
LEFT JOIN findings f ON f.scan_id = s.id
LEFT JOIN fixes fx ON fx.finding_id = f.id
WHERE s.id = $1
GROUP BY s.id;
```

**2. Get False Positive Rate**
```sql
SELECT 
    COUNT(*) as total_findings,
    COUNT(CASE WHEN is_false_positive THEN 1 END) as false_positives,
    ROUND(
        100.0 * COUNT(CASE WHEN is_false_positive THEN 1 END) / COUNT(*),
        2
    ) as fp_rate_percent
FROM findings
WHERE scan_id = $1;
```

**3. Get Findings by Severity**
```sql
SELECT 
    severity,
    COUNT(*) as count,
    json_agg(
        json_build_object(
            'title', issue_title,
            'endpoint', endpoint_or_file,
            'category', category
        )
    ) as findings
FROM findings
WHERE scan_id = $1 AND NOT is_false_positive
GROUP BY severity
ORDER BY 
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
    END;
```

**4. Get Flow Performance**
```sql
SELECT 
    flow_name,
    status,
    AVG(duration_ms) as avg_duration_ms,
    MIN(duration_ms) as min_duration_ms,
    MAX(duration_ms) as max_duration_ms
FROM flow_runs
WHERE scan_id = $1
GROUP BY flow_name, status;
```

---

## Integration Flow

### Detection Pipeline (Code Analyzer)

```
1. Static Analyzer extracts code snippet
   ↓
2. Generate embedding using fastembed
   ↓
3. Query Upstash Vector (vulnerable patterns)
   ↓
4. If match found (score > 0.75):
   ├─ Evidence: matched pattern + score
   ├─ Triage with LLM
   └─ If confirmed:
      └─ INSERT INTO findings (...)
```

### Remediation Pipeline (Fix Generator)

```
1. Get Finding from PostgreSQL
   ↓
2. Extract vulnerable code from evidence field
   ↓
3. Check if pattern_id exists in finding metadata
   ↓
4. Query Upstash Vector for safe pattern
   ├─ If direct match: GET safe pattern by fix_for
   └─ If no match: SEARCH safe patterns by vuln_type
   ↓
5. LLM adapts safe pattern to context
   ↓
6. INSERT INTO fixes (finding_id, diff_text, explanation)
```

### Dashboard Query Flow

```
1. Get scan by ID
   ↓
2. JOIN with flow_runs, findings, fixes
   ↓
3. Aggregate:
   ├─ Total findings by severity
   ├─ False positive rate
   ├─ Fixes generated/applied
   └─ Flow completion status
   ↓
4. Stream updates via WebSocket
```

---

## Metrics & Benchmarking

### Performance Targets
- **Detection latency**: <500ms per code snippet
- **Fix generation**: <2s per finding
- **Dashboard refresh**: <100ms for summary queries

### Quality Metrics (Stored in DB)
```sql
-- Detection Rate: True positives / (True positives + False negatives)
SELECT 
    COUNT(CASE WHEN NOT is_false_positive THEN 1 END)::float / 
    COUNT(*)::float as detection_rate
FROM findings
WHERE scan_id = $1;

-- False Positive Rate: False positives / Total findings
SELECT 
    COUNT(CASE WHEN is_false_positive THEN 1 END)::float / 
    COUNT(*)::float as fp_rate
FROM findings
WHERE scan_id = $1;

-- Fix Success Rate: Applied fixes / Total fixes
SELECT 
    COUNT(CASE WHEN applied THEN 1 END)::float / 
    COUNT(*)::float as fix_success_rate
FROM fixes
JOIN findings ON findings.id = fixes.finding_id
WHERE findings.scan_id = $1;
```

---

## Deployment Considerations

### Upstash Vector
- **Free Tier**: 10K vectors, 10K queries/day
- **Scaling**: Auto-scales, pay per query
- **Latency**: ~50-200ms per query
- **Backup**: Automatic, point-in-time recovery

### Neon PostgreSQL
- **Free Tier**: 512MB storage, 100 compute hours/month
- **Scaling**: Serverless, scales to zero
- **Latency**: ~10-50ms per query
- **Backup**: Automatic daily backups

### Cost Estimates (Beyond Free Tier)
- **Upstash**: $0.002 per 1K queries = ~$2/month for 1M queries
- **Neon**: $0.16/GB storage + $0.102/hour compute = ~$20-50/month

---

## Maintenance

### Adding New Patterns
1. Edit `scripts/seed_upstash.py`
2. Add tuple: `(vulnerable_code, safe_code, metadata)`
3. Run: `python scripts/seed_upstash.py`

### Updating Schema
1. Modify `app/db/models.py`
2. Run: `python scripts/init_db.py`
3. For production: Create Alembic migration

### Monitoring
- Upstash Dashboard: Query volume, latency
- Neon Dashboard: Storage, compute hours
- App Metrics: Log slow queries (>1s)

---

## Files Created

```
backend/
├── scripts/
│   ├── seed_upstash.py          # Seed Upstash with 50 pattern pairs
│   ├── init_db.py               # Initialize PostgreSQL tables
│   └── check_setup.py           # Verify database connections
├── app/
│   ├── db/
│   │   ├── models.py            # SQLAlchemy models (already existed)
│   │   └── session.py           # DB session management
│   └── utils/
│       └── pattern_matcher.py   # Upstash query utilities
├── VECTOR_DB_SETUP.md           # Detailed architecture docs
├── SETUP_GUIDE.md               # Step-by-step setup
└── DATABASE_SUMMARY.md          # This file
```

---

## Quick Reference

### Query Vulnerable Patterns
```python
from app.utils.pattern_matcher import PatternMatcher
matcher = PatternMatcher()
matches = matcher.find_vulnerable_patterns(code, top_k=5, min_score=0.75)
```

### Get Safe Pattern
```python
safe = matcher.find_safe_pattern(vuln_pattern_id)
```

### Create Finding
```python
from app.db.session import SessionLocal
from app.db.models import Finding

db = SessionLocal()
finding = Finding(
    scan_id=1,
    issue_title="SQL Injection",
    severity="critical",
    endpoint_or_file="/api/users",
    evidence=code
)
db.add(finding)
db.commit()
```

### Generate Fix
```python
from app.db.models import Fix

fix = Fix(
    finding_id=finding.id,
    diff_text=diff,
    explanation="Use parameterized queries"
)
db.add(fix)
db.commit()
```
