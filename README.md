# SecuraAI — AI-Powered Multi-Agent Security Scanner

> Architected a multi-agent SAST pipeline using **LangGraph** with 5 parallel scanners (Semgrep, Gitleaks, OSV-Scanner, CodeQL, Bearer), RAG retrieval over **Upstash Vector**, and LLM-powered triage with AI-generated code fixes via **OpenRouter**.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-SecuraAI-black?style=for-the-badge&logo=vercel)](https://securaai.vercel.app)
[![Backend](https://img.shields.io/badge/Backend-Render-46E3B7?style=for-the-badge&logo=render)](https://securaai-major-project.onrender.com/docs)
[![npm](https://img.shields.io/badge/CLI-@authtrack%2Fsecura-red?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@authtrack/secura)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

---

## What is SecuraAI?

SecuraAI is an agentic security platform that automatically scans web applications and codebases for vulnerabilities. It chains multiple AI agents together using **LangGraph** state machines to deliver results no single scanner could produce alone:

- **5 scanners run in parallel** — each specialised for a different vulnerability class
- **RAG triage** — findings are matched against a Upstash Vector database of known CVE patterns
- **LLM confirms or rules out** each finding, eliminating false positives
- **AI generates code fixes** with explanations and diff-style patches
- **Everything streams live** to a terminal CLI or a Next.js dashboard

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    SecuraAI Backend                  │
│                   (FastAPI + LangGraph)              │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │  Recon   │  │ Header   │  │ Static Analysis  │  │
│  │  Agent   │  │  Audit   │  │     Agent        │  │
│  │          │  │  Agent   │  │                  │  │
│  │Playwright│  │          │  │ Semgrep  Gitleaks│  │
│  │ Crawler  │  │ 15 header│  │ Bearer   OSV-Scan│  │
│  │ LLM Class│  │  checks  │  │ CodeQL   ← dedup │  │
│  └──────────┘  └──────────┘  │ RAG triage       │  │
│                               │ LLM confirm/fix  │  │
│                               └──────────────────┘  │
│                                                     │
│  PostgreSQL (NeonDB)    Upstash Vector (RAG)         │
└─────────────────────────────────────────────────────┘
         ↑ SSE streaming          ↑ REST API
┌────────────────┐       ┌────────────────────┐
│  Next.js UI    │       │  secura CLI (npm)  │
│  (Dashboard)   │       │  @authtrack/secura │
└────────────────┘       └────────────────────┘
```

---

## Features

### 🔍 Three Scan Flows

| Flow | What it does |
|---|---|
| **Recon & Surface Mapping** | Crawls the target with Playwright (full JS rendering), maps all endpoints, forms and APIs, classifies them with LLM, and scores risk |
| **Security Header Audit** | Checks 15 HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) against OWASP best practices |
| **Static Code Analysis** | Runs 5 scanners in parallel, deduplicates findings, RAG-matches against CVEs, LLM triages, generates AI patch diffs |

### 🤖 AI Pipeline (Static Analysis)

```
target code
    ↓
5 scanners (parallel)        Semgrep, Gitleaks, OSV-Scanner, CodeQL, Bearer
    ↓
deduplication                9 raw → 5 unique (cross-tool corroboration)
    ↓
RAG retrieval                match against Upstash Vector CVE database
    ↓
LLM triage                   confirm or rule out each finding
    ↓
fix generation               AI writes code patches with explanations
    ↓
streaming report             SSE to dashboard or CLI
```

### 📦 Zero-dependency CLI

```bash
npm i -g @authtrack/secura
secura scan .                  # scan current directory
secura scan . --show-fixes     # print AI-generated patch diffs
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python, FastAPI, LangGraph, SQLAlchemy |
| **LLM** | OpenRouter (Nemotron 550B) / NVIDIA NIM (Kimi K3) |
| **Vector DB** | Upstash Vector (RAG retrieval) |
| **Database** | PostgreSQL via NeonDB (serverless) |
| **Frontend** | Next.js 16, TypeScript, Tailwind CSS, Framer Motion |
| **Browser automation** | Playwright (Chromium, headless) |
| **CLI** | Node.js ESM, published to npm |
| **Deployment** | Render (backend), Vercel (frontend) |

---

## Getting Started

### Prerequisites
- Python 3.12+
- Node.js 18+
- An [OpenRouter](https://openrouter.ai) API key (free tier available)
- A [NeonDB](https://neon.tech) PostgreSQL database (free tier available)
- An [Upstash](https://upstash.com) Vector index (free tier available)

### 1. Clone & set up the backend

```bash
git clone https://github.com/ashleyalmeida07/SecuraAI-Major-Project.git
cd SecuraAI-Major-Project/backend

# Install dependencies
pip install -r requirements.txt

# Install Playwright browser
python -m playwright install chromium

# Copy and fill in the env file
cp .env.example .env
# Edit .env with your keys
```

### 2. Configure environment variables

```env
# backend/.env
LLM_PROVIDER="openrouter"
LLM_MODEL="nvidia/nemotron-3-ultra-550b-a55b:free"
OPENROUTER_API_KEY="sk-or-..."

POSTGRES_SERVER="your-neon-host"
POSTGRES_USER="your-user"
POSTGRES_PASSWORD="your-password"
POSTGRES_DB="neondb"

UPSTASH_VECTOR_REST_URL="https://..."
UPSTASH_VECTOR_REST_TOKEN="..."
```

### 3. Start the backend

```bash
uvicorn app.main:app --reload
# Runs at http://localhost:8000
# Swagger UI at http://localhost:8000/docs
```

### 4. Start the frontend

```bash
cd ../frontend
npm install
npm run dev
# Runs at http://localhost:3000
```

### 5. Use the CLI

```bash
npm i -g @authtrack/secura

# Scan a local directory (uses live backend by default)
secura scan /path/to/your/project

# Scan with AI fix diffs printed
secura scan . --show-fixes

# Point at your own backend
SECURA_API=http://localhost:8000/api/v1 secura scan .
```

---

## Live Demo

- **Frontend**: [securaai.vercel.app](https://securaai.vercel.app)
- **Backend API**: [securaai-major-project.onrender.com/docs](https://securaai-major-project.onrender.com/docs)
- **npm CLI**: [`@authtrack/secura`](https://www.npmjs.com/package/@authtrack/secura)

> ⚠️ The backend runs on Render's free tier — it may take ~30s to wake up after inactivity.

---

## Project Structure

```
SecuraAI-Major-Project/
├── backend/
│   ├── app/
│   │   ├── agents/
│   │   │   ├── recon/          # Playwright crawler + LLM classifier
│   │   │   ├── header_audit/   # 15-check HTTP header auditor
│   │   │   └── static_analysis/# 5-scanner SAST + RAG + fix gen
│   │   ├── api/                # FastAPI routes + SSE streaming
│   │   ├── core/               # LLM factory, config, DB session
│   │   └── models/             # SQLAlchemy models + Pydantic schemas
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── app/                # Next.js App Router pages
│       ├── components/         # UI components + scan runner
│       └── lib/                # API client, scan flows
├── cli/
│   └── src/                    # Node.js ESM CLI (@authtrack/secura)
└── render.yaml                 # Render deployment config
```


---

## License

MIT © 2026 SecuraAI
