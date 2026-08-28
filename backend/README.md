# AuthTrack Backend

AI-powered security scanning platform using LangGraph agents for vulnerability detection and automated fix generation.

## 🏗️ Architecture

### Databases
- **Upstash Vector** - Semantic search for vulnerable/safe code patterns (RAG)
- **Neon PostgreSQL** - Relational data for scans, findings, and fixes

### Agents (LangGraph)
- **Recon Agent** - Discover endpoints and assets
- **Header Audit Agent** - Check security headers
- **Static Analysis Agent** - Analyze code for vulnerabilities
- **Fix Generator Agent** - Generate secure code alternatives

## 🚀 Quick Start

### 1. Prerequisites
```bash
# Python 3.10+ with uv
uv --version

# Or use pip
python --version
```

### 2. Install Dependencies
```bash
# Using uv (recommended)
uv pip install upstash-vector fastembed sqlalchemy psycopg2-binary

# Or using pip
pip install upstash-vector fastembed sqlalchemy psycopg2-binary langchain langgraph fastapi uvicorn
```

### 3. Configure Environment
```bash
# Copy example and edit
cp .env.example .env
```

Required variables:
```env
# LLM Provider (openrouter, anthropic, openai, nvidia)
LLM_PROVIDER=openrouter
LLM_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free
OPENROUTER_API_KEY=your_key_here

# Upstash Vector
UPSTASH_SEARCH_REST_URL=https://xxxxx.upstash.io
UPSTASH_SEARCH_REST_TOKEN=your_token_here

# Neon PostgreSQL
POSTGRES_SERVER=ep-xxxxx.aws.neon.tech
POSTGRES_USER=your_user
POSTGRES_PASSWORD=your_password
POSTGRES_DB=authtrack
```

### 4. Setup Databases
```bash
# Check if everything is configured
python scripts/check_setup.py

# Initialize PostgreSQL tables
python scripts/init_db.py

# Seed Upstash with 50 vulnerable/safe code pattern pairs
python scripts/seed_upstash.py
```

### 5. Start Backend
```bash
uvicorn app.main:app --reload
```

Visit: http://localhost:8000/docs

## 📊 Database Setup

### Upstash Vector (Code Patterns)
Stores 50 pairs of vulnerable/safe code patterns:
- **Vulnerable patterns** - Known bad code from OWASP, CVEs
- **Safe patterns** - Fixed/secure versions

**Coverage:**
- SQL Injection (Express, Django, FastAPI)
- XSS (React, Vue, Django, Flask)
- Path Traversal, Command Injection
- SSRF, Insecure Deserialization
- Broken Auth, Weak Crypto
- And more...

**Query Usage:**
```python
from app.utils.pattern_matcher import PatternMatcher

matcher = PatternMatcher()

# Detect vulnerabilities
matches = matcher.find_vulnerable_patterns(
    code_snippet='db.query("SELECT * FROM users WHERE id = " + id)',
    top_k=5,
    min_score=0.75
)

# Get fixes
safe = matcher.find_safe_pattern(vuln_pattern_id)
```

### Neon PostgreSQL (Scan Data)
Stores structured scan data with 4 tables:

```
scans → flow_runs → findings → fixes
```

**Example:**
```python
from app.db.session import SessionLocal
from app.db.models import Scan, Finding, Fix

db = SessionLocal()

# Create scan
scan = Scan(target="https://example.com", scan_type="url")
db.add(scan)
db.commit()

# Add finding
finding = Finding(
    scan_id=scan.id,
    issue_title="SQL Injection",
    severity="critical",
    endpoint_or_file="/api/users",
    evidence=code
)
db.add(finding)
db.commit()

# Generate fix
fix = Fix(
    finding_id=finding.id,
    diff_text=diff_text,
    explanation="Use parameterized queries"
)
db.add(fix)
db.commit()
```

## 🔍 API Endpoints

### Authentication
```bash
POST /api/v1/auth/register
POST /api/v1/auth/login
```

### Scanning
```bash
# Start a URL scan
POST /api/v1/scan/url
Body: {"url": "https://example.com"}

# Start a CLI/code scan
POST /api/v1/scan/cli
Body: {"repo_path": "/path/to/repo"}

# Get scan status
GET /api/v1/scan/{scan_id}

# Get scan findings
GET /api/v1/scan/{scan_id}/findings

# Get generated fixes
GET /api/v1/scan/{scan_id}/fixes
```

## 🤖 Agent Workflows

### Static Analysis Flow
```
1. Extract code snippets from files
2. Generate embeddings with fastembed
3. Query Upstash for similar vulnerable patterns
4. If match found (score > 0.75):
   - Evidence: matched pattern + confidence
   - Triage with LLM
   - Create Finding in PostgreSQL
5. For confirmed findings:
   - Query Upstash for safe pattern
   - LLM adapts to context
   - Save Fix to PostgreSQL
```

### Header Audit Flow
```
1. Fetch URL headers
2. Check against security best practices
3. Flag missing/misconfigured headers
4. Generate remediation suggestions
```

### Recon Flow
```
1. Discover endpoints (sitemap, robots.txt, etc.)
2. Identify technologies
3. Map attack surface
4. Feed results to other agents
```

## 📁 Project Structure

```
backend/
├── app/
│   ├── agents/              # LangGraph agent implementations
│   │   ├── recon/          # Reconnaissance agent
│   │   ├── header_audit/   # Header security checker
│   │   └── static_analysis/ # Code vulnerability scanner
│   ├── api/                # FastAPI routes
│   │   ├── auth.py        # Authentication endpoints
│   │   └── scan.py        # Scan endpoints
│   ├── core/              # Configuration and LLM setup
│   │   ├── config.py      # Settings management
│   │   ├── llm.py         # LLM provider abstraction
│   │   └── security.py    # JWT and auth utilities
│   ├── db/                # Database models and session
│   │   ├── models.py      # SQLAlchemy models
│   │   └── session.py     # DB connection
│   ├── models/            # Pydantic schemas
│   │   └── schemas.py     # API request/response models
│   ├── utils/             # Utility functions
│   │   └── pattern_matcher.py  # Upstash query utilities
│   └── main.py            # FastAPI app entry point
├── scripts/               # Database setup scripts
│   ├── check_setup.py    # Verify configuration
│   ├── init_db.py        # Initialize PostgreSQL
│   └── seed_upstash.py   # Seed Upstash Vector
├── .env.example          # Environment variables template
├── pyproject.toml        # Python dependencies
├── DATABASE_SUMMARY.md   # Database architecture overview
├── SETUP_GUIDE.md        # Step-by-step setup instructions
└── VECTOR_DB_SETUP.md    # Detailed database documentation
```

## 🛠️ Development

### Run Tests
```bash
pytest
```

### Code Quality
```bash
# Format code
black app/

# Lint
flake8 app/

# Type check
mypy app/
```

### Database Migrations
```bash
# For schema changes, use Alembic
alembic revision --autogenerate -m "Description"
alembic upgrade head
```

## 📈 Monitoring & Metrics

### Database Metrics (Stored in PostgreSQL)
```sql
-- Detection Rate
SELECT COUNT(CASE WHEN NOT is_false_positive THEN 1 END)::float / 
       COUNT(*)::float as detection_rate
FROM findings WHERE scan_id = $1;

-- False Positive Rate
SELECT COUNT(CASE WHEN is_false_positive THEN 1 END)::float / 
       COUNT(*)::float as fp_rate
FROM findings WHERE scan_id = $1;

-- Fix Success Rate
SELECT COUNT(CASE WHEN applied THEN 1 END)::float / 
       COUNT(*)::float as fix_success_rate
FROM fixes 
JOIN findings ON findings.id = fixes.finding_id
WHERE findings.scan_id = $1;
```

### Performance Targets
- **Detection latency**: <500ms per code snippet
- **Fix generation**: <2s per finding
- **Upstash query**: 50-200ms
- **PostgreSQL query**: 10-50ms

## 🔐 Security Considerations

### API Security
- JWT authentication for all protected endpoints
- Rate limiting on scan endpoints
- Input validation with Pydantic

### Database Security
- Connection strings in environment variables
- Parameterized queries (SQLAlchemy)
- Row-level security in Neon (future)

### LLM Security
- API keys in environment variables
- Content filtering for prompt injection
- Output sanitization

## 🚧 Roadmap

### Phase 1 (Current)
- ✅ Basic agent flows (recon, headers, static)
- ✅ Upstash Vector integration
- ✅ PostgreSQL schema
- ✅ Pattern matching utilities
- 🔄 Fix generation implementation

### Phase 2
- [ ] Real-time dashboard with WebSocket
- [ ] Batch scanning for multiple URLs
- [ ] Custom pattern upload
- [ ] False positive feedback loop

### Phase 3
- [ ] GitHub integration (scan PRs)
- [ ] CI/CD pipeline integration
- [ ] Advanced code analysis (dataflow, taint)
- [ ] Machine learning for pattern ranking

## 🤝 Contributing

### Adding New Vulnerability Patterns
1. Edit `scripts/seed_upstash.py`
2. Add pattern pair to `SEED_PATTERNS`:
   ```python
   (
       "vulnerable_code_here",
       "safe_code_here",
       {
           "vuln_type": "SQL Injection",
           "framework": "Express",
           "severity": "critical",
           "cwe": "CWE-89",
           "owasp": "A03:2021-Injection",
           "language": "JavaScript"
       }
   )
   ```
3. Re-run: `python scripts/seed_upstash.py`

### Adding New Agent Flows
1. Create new directory in `app/agents/`
2. Implement:
   - `state.py` - Define state schema
   - `nodes.py` - Implement node functions
   - `graph.py` - Build LangGraph workflow
3. Register in `app/agents/__init__.py`
4. Add API endpoint in `app/api/scan.py`

## 📚 Documentation

- **[SETUP_GUIDE.md](SETUP_GUIDE.md)** - Step-by-step setup instructions
- **[VECTOR_DB_SETUP.md](VECTOR_DB_SETUP.md)** - Database architecture details
- **[DATABASE_SUMMARY.md](DATABASE_SUMMARY.md)** - Quick reference for DB operations

## 🐛 Troubleshooting

### Upstash Connection Issues
```bash
# Verify credentials
python scripts/check_setup.py

# Check Upstash console
https://console.upstash.com/vector
```

### PostgreSQL Connection Issues
```bash
# Test connection
python -c "from app.db.session import engine; engine.connect()"

# Recreate tables
python scripts/init_db.py
```

### LLM Provider Issues
```bash
# Test LLM connection
python -c "from app.core.llm import get_llm; llm = get_llm(); print(llm.invoke('test'))"
```

## 📞 Support

- **Issues**: GitHub Issues
- **Docs**: See `*.md` files in this directory
- **OWASP Resources**: https://owasp.org/www-project-top-ten/

## 📄 License

MIT License - See LICENSE file for details

---

**Built with:**
- [LangGraph](https://langchain-ai.github.io/langgraph/) - Agent orchestration
- [FastAPI](https://fastapi.tiangolo.com/) - Web framework
- [Upstash Vector](https://upstash.com/docs/vector) - Vector database
- [Neon](https://neon.tech/) - Serverless PostgreSQL
- [FastEmbed](https://github.com/qdrant/fastembed) - Local embeddings


50 vulnerable code patterns (known bad code from OWASP, CVEs)
50 safe/fixed patterns (secure alternatives)
Each pattern gets converted to a 384-dimensional embedding (vector)
Total: 100 patterns stored as semantic vectors